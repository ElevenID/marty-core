//! Bounded, run-owned browser wallet storage. A stale session never falls back
//! to the legacy interactive wallet, and a session cookie is never reported.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use serde::Serialize;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "marty_test_wallet_session";
const SESSION_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_SESSIONS: usize = 128;

#[derive(Clone, Debug, Serialize)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub instance_id: Uuid,
    pub run_id: String,
    pub expires_after_seconds: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error(
        "A run ID of 1 to 160 ASCII letters, digits, dots, underscores or hyphens is required"
    )]
    InvalidRunId,
    #[error("This run already owns a wallet session")]
    DuplicateRun,
    #[error("The wallet session limit has been reached")]
    Capacity,
    #[error("The wallet session is absent, closed or expired; create a new isolated session")]
    Missing,
    #[error("The wallet session cookie is malformed or ambiguous")]
    InvalidCookie,
    #[error("Wallet session storage is unavailable")]
    Unavailable,
}

struct Session<T> {
    info: SessionInfo,
    created: Instant,
    wallet: Arc<RwLock<T>>,
    open: Arc<RwLock<bool>>,
}

/// A protocol operation retains this lease across issuer, signer and verifier
/// awaits. The data handle cannot be extracted and used after the lease ends.
pub struct SessionLease<T> {
    pub info: SessionInfo,
    wallet: Arc<RwLock<T>>,
    _operation: OwnedRwLockReadGuard<bool>,
}

impl<T> std::ops::Deref for SessionLease<T> {
    type Target = RwLock<T>;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

fn retain_live<T>(session: &Session<T>, now: Instant) -> bool {
    if now.duration_since(session.created) < SESSION_TTL {
        return true;
    }
    // Expiry must not evict storage still owned by an in-flight operation.
    if let Ok(mut open) = session.open.clone().try_write_owned() {
        *open = false;
        false
    } else {
        true
    }
}

pub struct WalletSessions<T> {
    instance_id: Uuid,
    sessions: Mutex<HashMap<Uuid, Session<T>>>,
}

impl<T: Default> Default for WalletSessions<T> {
    fn default() -> Self {
        Self {
            instance_id: Uuid::new_v4(),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Default> WalletSessions<T> {
    pub fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    pub fn create(&self, run_id: &str) -> Result<(SessionInfo, String), SessionError> {
        self.create_at(run_id, Instant::now())
    }

    fn create_at(&self, run_id: &str, now: Instant) -> Result<(SessionInfo, String), SessionError> {
        if run_id.is_empty()
            || run_id.len() > 160
            || !run_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(SessionError::InvalidRunId);
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        sessions.retain(|_, session| retain_live(session, now));
        if sessions
            .values()
            .any(|session| session.info.run_id == run_id)
        {
            return Err(SessionError::DuplicateRun);
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::Capacity);
        }
        let info = SessionInfo {
            session_id: Uuid::new_v4(),
            instance_id: self.instance_id,
            run_id: run_id.to_string(),
            expires_after_seconds: SESSION_TTL.as_secs(),
        };
        // The CSPRNG-generated cookie is a separate capability from public IDs.
        let token = Uuid::new_v4();
        sessions.insert(
            token,
            Session {
                info: info.clone(),
                created: now,
                wallet: Arc::new(RwLock::new(T::default())),
                open: Arc::new(RwLock::new(true)),
            },
        );
        Ok((info, token.to_string()))
    }

    pub async fn get(&self, token: Uuid) -> Result<SessionLease<T>, SessionError> {
        self.get_at(token, Instant::now()).await
    }

    async fn get_at(&self, token: Uuid, now: Instant) -> Result<SessionLease<T>, SessionError> {
        let (info, wallet, open) = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| SessionError::Unavailable)?;
            sessions.retain(|_, session| retain_live(session, now));
            let session = sessions.get(&token).ok_or(SessionError::Missing)?;
            if now.duration_since(session.created) >= SESSION_TTL {
                return Err(SessionError::Missing);
            }
            (
                session.info.clone(),
                Arc::clone(&session.wallet),
                Arc::clone(&session.open),
            )
        };
        let operation = open.read_owned().await;
        if !*operation {
            return Err(SessionError::Missing);
        }
        Ok(SessionLease {
            info,
            wallet,
            _operation: operation,
        })
    }

    pub async fn close(&self, token: Uuid) -> Result<(), SessionError> {
        let open = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| SessionError::Unavailable)?;
            Arc::clone(&sessions.get(&token).ok_or(SessionError::Missing)?.open)
        };
        // The fair async lock queues later operations behind close. They see
        // false after active operations drain, and cannot use detached storage
        // after cleanup has acknowledged success.
        let mut open = open.write_owned().await;
        if !*open {
            return Err(SessionError::Missing);
        }
        *open = false;
        self.sessions
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .remove(&token)
            .ok_or(SessionError::Missing)?;
        Ok(())
    }
}

/// Missing cookies select the pre-existing interactive wallet. A supplied
/// invalid/expired cookie is an error, so it cannot redirect a reset to it.
pub fn session_cookie(headers: &HeaderMap) -> Result<Option<Uuid>, SessionError> {
    let mut token = None;
    for header in headers.get_all(axum::http::header::COOKIE) {
        let header = header.to_str().map_err(|_| SessionError::InvalidCookie)?;
        for cookie in header.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                if cookie.trim() == SESSION_COOKIE {
                    return Err(SessionError::InvalidCookie);
                }
                continue;
            };
            if name != SESSION_COOKIE {
                continue;
            }
            let parsed = Uuid::parse_str(value).map_err(|_| SessionError::InvalidCookie)?;
            if token.is_some() || parsed.to_string() != value {
                return Err(SessionError::InvalidCookie);
            }
            token = Some(parsed);
        }
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn separate_runs_cannot_reset_read_or_close_each_others_credentials() {
        let sessions = WalletSessions::<Vec<String>>::default();
        let (info_a, token_a) = sessions.create("run-a").unwrap();
        let (info_b, token_b) = sessions.create("run-b").unwrap();
        let token_a = Uuid::parse_str(&token_a).unwrap();
        let token_b = Uuid::parse_str(&token_b).unwrap();
        let a = sessions.get(token_a).await.unwrap();
        let b = sessions.get(token_b).await.unwrap();
        a.write().await.push("credential-a".into());
        b.write().await.push("credential-b".into());
        a.write().await.clear();
        drop(a);
        sessions.close(token_a).await.unwrap();
        assert!(matches!(
            sessions.get(token_a).await,
            Err(SessionError::Missing)
        ));
        assert_eq!(&*b.read().await, &["credential-b"]);
        assert_eq!(sessions.get(token_b).await.unwrap().info.run_id, "run-b");
        assert_ne!(info_a.session_id, info_b.session_id);
        assert!(matches!(
            sessions.get(info_b.session_id).await,
            Err(SessionError::Missing)
        ));
        assert!(!serde_json::to_string(&info_b)
            .unwrap()
            .contains(&token_b.to_string()));
    }

    #[tokio::test]
    async fn stale_capabilities_expire_and_never_resolve_to_another_wallet() {
        let sessions = WalletSessions::<Vec<String>>::default();
        let now = Instant::now();
        let (_, token) = sessions.create_at("expired-run", now).unwrap();
        let token = Uuid::parse_str(&token).unwrap();
        assert!(matches!(
            sessions.get_at(token, now + SESSION_TTL).await,
            Err(SessionError::Missing)
        ));
        assert!(sessions.create_at("expired-run", now + SESSION_TTL).is_ok());
        assert!(matches!(
            sessions.get_at(token, now + SESSION_TTL).await,
            Err(SessionError::Missing)
        ));
    }

    #[tokio::test]
    async fn capacity_and_duplicate_runs_fail_without_evicting_a_live_run() {
        let sessions = WalletSessions::<Vec<String>>::default();
        let (_, first) = sessions.create("run-0").unwrap();
        assert!(matches!(
            sessions.create("run-0"),
            Err(SessionError::DuplicateRun)
        ));
        for i in 1..MAX_SESSIONS {
            sessions.create(&format!("run-{i}")).unwrap();
        }
        assert!(matches!(
            sessions.create("overflow"),
            Err(SessionError::Capacity)
        ));
        assert!(sessions.get(Uuid::parse_str(&first).unwrap()).await.is_ok());
        for invalid in ["", "space id", "slash/id", "line\nfeed", "unicode-é"] {
            assert!(matches!(
                sessions.create(invalid),
                Err(SessionError::InvalidRunId)
            ));
        }
    }

    #[test]
    fn malformed_or_duplicate_cookies_never_select_the_interactive_wallet() {
        use axum::http::{header::COOKIE, HeaderValue};
        let mut headers = HeaderMap::new();
        assert_eq!(session_cookie(&headers).unwrap(), None);
        for value in ["bad".to_string(), Uuid::new_v4().to_string().to_uppercase()] {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&format!("{SESSION_COOKIE}={value}")).unwrap(),
            );
            assert_eq!(session_cookie(&headers), Err(SessionError::InvalidCookie));
        }
        let token = Uuid::new_v4();
        let value = HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}")).unwrap();
        headers.insert(COOKIE, value.clone());
        assert_eq!(session_cookie(&headers).unwrap(), Some(token));
        headers.append(COOKIE, value);
        assert_eq!(session_cookie(&headers), Err(SessionError::InvalidCookie));
    }

    #[tokio::test]
    async fn close_drains_delayed_operations_and_rejects_queued_operations_before_acknowledging() {
        use std::{future::Future, task::Poll};
        let sessions = WalletSessions::<Vec<String>>::default();
        let (_, token) = sessions.create("delayed-issuer").unwrap();
        let token = Uuid::parse_str(&token).unwrap();
        let operation = sessions.get(token).await.unwrap();
        let mut close = Box::pin(sessions.close(token));
        std::future::poll_fn(|cx| {
            assert!(
                close.as_mut().poll(cx).is_pending(),
                "close must wait for the protocol operation"
            );
            Poll::Ready(())
        })
        .await;
        let mut later = Box::pin(sessions.get(token));
        std::future::poll_fn(|cx| {
            assert!(
                later.as_mut().poll(cx).is_pending(),
                "later operations must queue behind close"
            );
            Poll::Ready(())
        })
        .await;
        operation
            .write()
            .await
            .push("issuer-response-completed".into());
        drop(operation);
        tokio::time::timeout(Duration::from_secs(1), close)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(later.await, Err(SessionError::Missing)));
        assert!(matches!(
            sessions.get(token).await,
            Err(SessionError::Missing)
        ));
    }
}
