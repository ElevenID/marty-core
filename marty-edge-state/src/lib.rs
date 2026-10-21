//! Bounded, network-free state transitions for a future headless verifier.
//!
//! Authentication, verification, durable storage, trusted time, and audit are
//! deliberately host responsibilities. See the crate README before use.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const FORMAT_VERSION: u8 = 1;
const MAX_REPLAY_KEYS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum number of simultaneously live replay keys.
    pub max_replay_keys: usize,
    /// Maximum accepted lifetime of any replay key, in seconds.
    pub max_replay_ttl_seconds: u64,
}

impl Limits {
    fn validate(self) -> Result<(), StateError> {
        if self.max_replay_keys == 0
            || self.max_replay_keys > MAX_REPLAY_KEYS
            || self.max_replay_ttl_seconds == 0
        {
            return Err(StateError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("replay limits are zero or exceed the supported bound")]
    InvalidLimits,
    #[error("offline state snapshot is invalid or has an unsupported format")]
    InvalidSnapshot,
    #[error("trusted time moved backwards")]
    ClockRollback,
    #[error("authenticated trust revision did not advance")]
    TrustRevisionRollback,
    #[error("an authenticated trust revision must be provisioned first")]
    Unprovisioned,
    #[error("replay key was already accepted within its window")]
    Replay,
    #[error("replay window is full")]
    ReplayCapacity,
    #[error("replay time-to-live is invalid or exceeds the configured limit")]
    InvalidReplayTtl,
    #[error("offline state generation is exhausted")]
    GenerationExhausted,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format_version: u8,
    generation: u64,
    trust_revision: u64,
    last_observed_seconds: u64,
    // Hex-encoded fixed-length digests only; no credential or session payloads.
    replay_expiry: BTreeMap<String, u64>,
}

/// State that must be persisted atomically before reporting an accepted request.
#[derive(Debug)]
pub struct OfflineState {
    snapshot: Snapshot,
    limits: Limits,
}

impl OfflineState {
    pub fn new(limits: Limits) -> Result<Self, StateError> {
        limits.validate()?;
        Ok(Self {
            snapshot: Snapshot {
                format_version: FORMAT_VERSION,
                generation: 0,
                trust_revision: 0,
                last_observed_seconds: 0,
                replay_expiry: BTreeMap::new(),
            },
            limits,
        })
    }

    /// Restore only from host-authenticated storage, using independently held
    /// monotonic floors to reject a replaced old snapshot. The generation
    /// floor is essential: time and trust revision may stay constant across
    /// multiple accepted verifications.
    pub fn restore(
        json: &str,
        limits: Limits,
        minimum_generation: u64,
        minimum_trust_revision: u64,
        minimum_observed_seconds: u64,
    ) -> Result<Self, StateError> {
        limits.validate()?;
        // Reject oversized input before allocating the deserialized map.
        if json.len() > limits.max_replay_keys * 96 + 256 {
            return Err(StateError::InvalidSnapshot);
        }
        let snapshot: Snapshot =
            serde_json::from_str(json).map_err(|_| StateError::InvalidSnapshot)?;
        if snapshot.format_version != FORMAT_VERSION
            || snapshot.generation < minimum_generation
            || snapshot.trust_revision < minimum_trust_revision
            || snapshot.last_observed_seconds < minimum_observed_seconds
            || (snapshot.trust_revision > 0 && snapshot.generation == 0)
            || (snapshot.trust_revision == 0 && !snapshot.replay_expiry.is_empty())
            || snapshot.replay_expiry.len() > limits.max_replay_keys
            || snapshot.replay_expiry.iter().any(|(key, expiry)| {
                key.len() != 64
                    || !key
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    || *expiry <= snapshot.last_observed_seconds
                    || *expiry - snapshot.last_observed_seconds > limits.max_replay_ttl_seconds
            })
        {
            return Err(StateError::InvalidSnapshot);
        }
        Ok(Self { snapshot, limits })
    }

    pub fn snapshot_json(&self) -> Result<String, StateError> {
        serde_json::to_string(&self.snapshot).map_err(|_| StateError::InvalidSnapshot)
    }

    pub fn trust_revision(&self) -> u64 {
        self.snapshot.trust_revision
    }

    /// Advance an independently protected floor to this value before reporting
    /// acceptance. If the floor advances but the snapshot does not, restoration
    /// must fail closed; it must not silently reset replay history.
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    pub fn replay_len(&self) -> usize {
        self.snapshot.replay_expiry.len()
    }

    /// Call only after validating the new trust package's authenticity,
    /// provenance, and policy compatibility. Equal revisions are rejected.
    pub fn accept_authenticated_trust_revision(
        &mut self,
        revision: u64,
        now_seconds: u64,
    ) -> Result<(), StateError> {
        self.check_time(now_seconds)?;
        if revision <= self.snapshot.trust_revision {
            return Err(StateError::TrustRevisionRollback);
        }
        let next_generation = self
            .snapshot
            .generation
            .checked_add(1)
            .ok_or(StateError::GenerationExhausted)?;
        self.snapshot
            .replay_expiry
            .retain(|_, expiry| *expiry > now_seconds);
        self.snapshot.trust_revision = revision;
        self.snapshot.last_observed_seconds = now_seconds;
        self.snapshot.generation = next_generation;
        Ok(())
    }

    /// Record a context-bound digest after successful verification. The host
    /// must persist this state before acknowledging acceptance to the caller.
    pub fn record_replay_key(
        &mut self,
        digest: [u8; 32],
        now_seconds: u64,
        ttl_seconds: u64,
    ) -> Result<(), StateError> {
        self.check_time(now_seconds)?;
        if self.snapshot.trust_revision == 0 {
            return Err(StateError::Unprovisioned);
        }
        if ttl_seconds == 0 || ttl_seconds > self.limits.max_replay_ttl_seconds {
            return Err(StateError::InvalidReplayTtl);
        }
        let expiry = now_seconds
            .checked_add(ttl_seconds)
            .ok_or(StateError::InvalidReplayTtl)?;
        let key = hex::encode(digest);
        if self
            .snapshot
            .replay_expiry
            .get(&key)
            .is_some_and(|existing| *existing > now_seconds)
        {
            return Err(StateError::Replay);
        }
        // The transition is atomic on errors: count live entries without
        // pruning until all rejection checks have passed.
        let live_count = self
            .snapshot
            .replay_expiry
            .values()
            .filter(|existing| **existing > now_seconds)
            .count();
        if live_count >= self.limits.max_replay_keys {
            return Err(StateError::ReplayCapacity);
        }
        let next_generation = self
            .snapshot
            .generation
            .checked_add(1)
            .ok_or(StateError::GenerationExhausted)?;
        self.snapshot
            .replay_expiry
            .retain(|_, existing| *existing > now_seconds);
        self.snapshot.replay_expiry.insert(key, expiry);
        self.snapshot.last_observed_seconds = now_seconds;
        self.snapshot.generation = next_generation;
        Ok(())
    }

    fn check_time(&self, now_seconds: u64) -> Result<(), StateError> {
        if now_seconds < self.snapshot.last_observed_seconds {
            Err(StateError::ClockRollback)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_replay_keys: 2,
            max_replay_ttl_seconds: 60,
        }
    }

    #[test]
    fn replay_capacity_and_expiry_fail_closed() {
        let mut state = OfflineState::new(limits()).unwrap();
        state.accept_authenticated_trust_revision(1, 100).unwrap();
        state.record_replay_key([1; 32], 100, 20).unwrap();
        state.record_replay_key([2; 32], 100, 20).unwrap();
        let before = state.snapshot_json().unwrap();
        assert_eq!(
            state.record_replay_key([1; 32], 101, 20),
            Err(StateError::Replay)
        );
        assert_eq!(
            state.record_replay_key([3; 32], 101, 20),
            Err(StateError::ReplayCapacity)
        );
        assert_eq!(state.snapshot_json().unwrap(), before);
        state.record_replay_key([3; 32], 120, 20).unwrap();
        assert_eq!(state.replay_len(), 1);
    }

    #[test]
    fn revision_and_time_cannot_roll_back() {
        let mut state = OfflineState::new(limits()).unwrap();
        state.accept_authenticated_trust_revision(7, 100).unwrap();
        assert_eq!(
            state.accept_authenticated_trust_revision(7, 101),
            Err(StateError::TrustRevisionRollback)
        );
        assert_eq!(
            state.accept_authenticated_trust_revision(6, 101),
            Err(StateError::TrustRevisionRollback)
        );
        assert_eq!(
            state.record_replay_key([1; 32], 99, 5),
            Err(StateError::ClockRollback)
        );
        assert_eq!(state.trust_revision(), 7);
    }

    #[test]
    fn snapshot_round_trip_and_independent_floors() {
        let mut state = OfflineState::new(limits()).unwrap();
        state.accept_authenticated_trust_revision(4, 100).unwrap();
        state.record_replay_key([9; 32], 101, 30).unwrap();
        let json = state.snapshot_json().unwrap();
        let mut restored = OfflineState::restore(&json, limits(), 2, 4, 101).unwrap();
        assert_eq!(
            restored.record_replay_key([9; 32], 102, 30),
            Err(StateError::Replay)
        );
        assert!(matches!(
            OfflineState::restore(&json, limits(), 2, 5, 101),
            Err(StateError::InvalidSnapshot)
        ));
        assert!(matches!(
            OfflineState::restore(&json, limits(), 2, 4, 102),
            Err(StateError::InvalidSnapshot)
        ));
    }

    #[test]
    fn trust_update_prunes_expired_replay_keys_before_persistence() {
        let mut state = OfflineState::new(limits()).unwrap();
        state.accept_authenticated_trust_revision(1, 100).unwrap();
        state.record_replay_key([1; 32], 100, 5).unwrap();
        state.accept_authenticated_trust_revision(2, 106).unwrap();
        assert_eq!(state.replay_len(), 0);
        let json = state.snapshot_json().unwrap();
        OfflineState::restore(&json, limits(), 3, 2, 106).unwrap();
    }

    #[test]
    fn earlier_same_second_snapshot_cannot_discard_accepted_replay_key() {
        let mut state = OfflineState::new(limits()).unwrap();
        state.accept_authenticated_trust_revision(1, 100).unwrap();
        state.record_replay_key([1; 32], 100, 30).unwrap();
        let earlier = state.snapshot_json().unwrap();
        state.record_replay_key([2; 32], 100, 30).unwrap();
        assert_eq!(state.generation(), 3);
        assert!(matches!(
            OfflineState::restore(&earlier, limits(), state.generation(), 1, 100),
            Err(StateError::InvalidSnapshot)
        ));
        let current = state.snapshot_json().unwrap();
        let mut restored = OfflineState::restore(&current, limits(), 3, 1, 100).unwrap();
        assert_eq!(
            restored.record_replay_key([2; 32], 100, 30),
            Err(StateError::Replay)
        );
    }

    #[test]
    fn malformed_snapshot_and_bad_limits_rejected() {
        assert!(matches!(
            OfflineState::new(Limits {
                max_replay_keys: 0,
                max_replay_ttl_seconds: 1
            }),
            Err(StateError::InvalidLimits)
        ));
        let mut state = OfflineState::new(limits()).unwrap();
        assert_eq!(
            state.record_replay_key([1; 32], 100, 10),
            Err(StateError::Unprovisioned)
        );
        state.accept_authenticated_trust_revision(1, 100).unwrap();
        assert_eq!(
            state.record_replay_key([1; 32], 100, 61),
            Err(StateError::InvalidReplayTtl)
        );
        let json = state
            .snapshot_json()
            .unwrap()
            .replace("\"format_version\":1", "\"format_version\":2");
        assert!(matches!(
            OfflineState::restore(&json, limits(), 0, 0, 0),
            Err(StateError::InvalidSnapshot)
        ));
        assert!(matches!(
            OfflineState::restore(&"x".repeat(449), limits(), 0, 0, 0),
            Err(StateError::InvalidSnapshot)
        ));
    }
}
