//! Operational proof through the same authenticated IPC and JOSE paths as the wallet.
use base64::Engine as _;
use marty_oid4vci::jose::{
    validate_public_signing_jwk_json, verify_detached_signature_with_public_jwk,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::signer_ipc::{request_signature, SignerAuthenticationKey, MAX_KEY_ID_BYTES};

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum HolderSigningProbeError {
    #[error("Holder signing preflight public configuration is invalid")]
    Configuration,
    #[error("Holder signing preflight could not obtain an authenticated signature")]
    Signing,
    #[error(
        "Holder signing preflight signature does not verify against the configured public key"
    )]
    Verification,
}

// At most one routine health signature per minute, leaving a finite-use KMS
// leaf available for actual wallet operations. Issuance always checks afresh.
const READINESS_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct HolderSigningReadiness {
    observation: Mutex<Option<ReadinessObservation>>,
}

struct ReadinessObservation {
    attempted_at: Instant,
    result: Result<(), HolderSigningProbeError>,
}

impl HolderSigningReadiness {
    /// Coalesce routine checks. `fresh` is selected only by the wallet's
    /// pre-issuance path, never by a public readiness query parameter.
    pub async fn check<F, P>(
        self: &Arc<Self>,
        fresh: bool,
        probe: F,
    ) -> Result<(), HolderSigningProbeError>
    where
        F: FnOnce() -> P + Send + 'static,
        P: Future<Output = Result<(), HolderSigningProbeError>> + Send + 'static,
    {
        let readiness = self.clone();
        // A short-lived HTTP waiter must not cancel a slow, already dispatched
        // KMS probe. Its bounded IPC deadline still applies. All routine callers
        // coalesce under the same observation lock and use the completed proof.
        tokio::spawn(async move { readiness.check_inner(fresh, probe).await })
            .await
            .unwrap_or(Err(HolderSigningProbeError::Signing))
    }

    async fn check_inner<F, P>(&self, fresh: bool, probe: F) -> Result<(), HolderSigningProbeError>
    where
        F: FnOnce() -> P,
        P: Future<Output = Result<(), HolderSigningProbeError>>,
    {
        let mut observation = self.observation.lock().await;
        if !fresh {
            if let Some(previous) = observation.as_ref() {
                if previous.attempted_at.elapsed() < READINESS_CACHE_TTL {
                    return previous.result;
                }
            }
        }
        // Retain a failed attempt even if an HTTP client cancels this future.
        // Otherwise aborted health polls could repeatedly spend token uses.
        *observation = Some(ReadinessObservation {
            attempted_at: Instant::now(),
            result: Err(HolderSigningProbeError::Signing),
        });
        let result = probe().await;
        observation.as_mut().expect("attempt recorded").result = result;
        result
    }

    pub async fn invalidate(&self) {
        *self.observation.lock().await = Some(ReadinessObservation {
            attempted_at: Instant::now(),
            result: Err(HolderSigningProbeError::Signing),
        });
    }
}

/// Public, independently verifiable observations only; never a credential or demo pass.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderSigningProbeReceipt {
    pub schema_version: u8,
    pub scope: &'static str,
    pub production_demo_ready: bool,
    pub holder_key_id: String,
    pub public_jwk: Value,
    pub algorithm: &'static str,
    pub challenge: String,
    pub signature_base64url: String,
    pub verified: bool,
}

/// Sign a fresh, domain-separated non-JWT challenge and verify the actual result.
/// KMS credentials belong to the existing signer agent and are not arguments here.
pub async fn probe_holder_signing(
    endpoint: &str,
    authentication_key: &SignerAuthenticationKey,
    holder_key_id: &str,
    public_jwk_json: &str,
) -> Result<HolderSigningProbeReceipt, HolderSigningProbeError> {
    validate_public_signing_jwk_json(public_jwk_json, "ES256")
        .map_err(|_| HolderSigningProbeError::Configuration)?;
    let public_jwk: Value = serde_json::from_str(public_jwk_json)
        .map_err(|_| HolderSigningProbeError::Configuration)?;
    if holder_key_id.is_empty()
        || holder_key_id.len() > MAX_KEY_ID_BYTES
        || public_jwk["kty"] != "EC"
        || public_jwk["crv"] != "P-256"
    {
        return Err(HolderSigningProbeError::Configuration);
    }
    let challenge = format!(
        "marty-test-wallet/holder-signing-preflight/v1:{}",
        Uuid::new_v4()
    );
    let signature = request_signature(
        endpoint,
        authentication_key,
        "ES256",
        holder_key_id,
        challenge.as_bytes(),
    )
    .await
    .map_err(|_| HolderSigningProbeError::Signing)?;
    let verified = verify_detached_signature_with_public_jwk(
        challenge.as_bytes(),
        &signature,
        public_jwk_json,
        "ES256",
    )
    .map_err(|_| HolderSigningProbeError::Verification)?;
    if !verified {
        return Err(HolderSigningProbeError::Verification);
    }
    Ok(HolderSigningProbeReceipt {
        schema_version: 1,
        scope: "HOLDER_SIGNING_PREFLIGHT_ONLY",
        production_demo_ready: false,
        holder_key_id: holder_key_id.into(),
        // Retain only actual public key coordinates, not arbitrary caller metadata.
        public_jwk: serde_json::json!({"kty":"EC","crv":"P-256",
            "x":public_jwk["x"],"y":public_jwk["y"]}),
        algorithm: "ES256",
        challenge,
        signature_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        verified,
    })
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn concurrent_health_polls_share_one_probe_and_expiry_is_bounded() {
        let readiness = Arc::new(HolderSigningReadiness::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let readiness = readiness.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                readiness
                    .check(false, move || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(())
                    })
                    .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        readiness
            .observation
            .lock()
            .await
            .as_mut()
            .unwrap()
            .attempted_at = Instant::now() - READINESS_CACHE_TTL;
        let probe_calls = calls.clone();
        assert!(readiness
            .check(false, move || async move {
                probe_calls.fetch_add(1, Ordering::SeqCst);
                Err(HolderSigningProbeError::Signing)
            })
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fresh_issuance_probe_bypasses_cached_success_and_can_recover() {
        let readiness = Arc::new(HolderSigningReadiness::default());
        readiness.check(false, || async { Ok(()) }).await.unwrap();
        assert!(readiness
            .check(true, || async { Err(HolderSigningProbeError::Signing) })
            .await
            .is_err());
        assert!(readiness
            .check(false, || async { panic!("failed probe must be cached") })
            .await
            .is_err());
        readiness.check(true, || async { Ok(()) }).await.unwrap();
        readiness
            .check(false, || async {
                panic!("fresh recovery must update health")
            })
            .await
            .unwrap();
        readiness.invalidate().await;
        assert!(readiness
            .check(false, || async {
                panic!("signing failure must invalidate health")
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cancelled_http_waiter_does_not_cancel_or_repeat_the_owned_probe() {
        let readiness = Arc::new(HolderSigningReadiness::default());
        let started = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let worker = {
            let readiness = readiness.clone();
            let started = started.clone();
            let finish = finish.clone();
            tokio::spawn(async move {
                readiness
                    .check(false, move || async move {
                        started.notify_one();
                        finish.notified().await;
                        Ok(())
                    })
                    .await
            })
        };
        started.notified().await;
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        finish.notify_one();
        readiness
            .check(false, || async {
                panic!("existing probe must finish without another token use")
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failed_probe_task_retains_fail_closed_backoff() {
        let readiness = Arc::new(HolderSigningReadiness::default());
        assert!(readiness
            .check(false, || async { panic!("controlled probe failure") })
            .await
            .is_err());
        assert!(readiness
            .check(false, || async {
                panic!("failed probe must not retry immediately")
            })
            .await
            .is_err());
    }
}
