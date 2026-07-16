//! Freshness constraint validation.

use crate::policy::types::FreshnessRequirements;
use std::time::{Duration, SystemTime};

/// Checks credential and presentation freshness constraints.
pub struct FreshnessChecker {
    requirements: FreshnessRequirements,
}

impl FreshnessChecker {
    pub fn new(requirements: &FreshnessRequirements) -> Self {
        Self {
            requirements: requirements.clone(),
        }
    }

    /// Validate credential issuance time against max age constraint.
    pub fn check_credential_age(&self, issued_at: SystemTime) -> FreshnessCheckResult {
        if let Some(max_age_seconds) = self.requirements.max_credential_age_seconds {
            let age = SystemTime::now()
                .duration_since(issued_at)
                .unwrap_or(Duration::from_secs(0));

            if age.as_secs() > max_age_seconds {
                return FreshnessCheckResult::Stale(format!(
                    "Credential is {} seconds old, maximum allowed is {}",
                    age.as_secs(),
                    max_age_seconds
                ));
            }
        }

        FreshnessCheckResult::Fresh
    }

    /// Validate presentation/proof time against max proof age.
    pub fn check_proof_age(&self, proof_timestamp: SystemTime) -> FreshnessCheckResult {
        let age = SystemTime::now()
            .duration_since(proof_timestamp)
            .unwrap_or(Duration::from_secs(0));

        if age.as_secs() > self.requirements.max_proof_age_seconds {
            return FreshnessCheckResult::Stale(format!(
                "Proof is {} seconds old, maximum allowed is {}",
                age.as_secs(),
                self.requirements.max_proof_age_seconds
            ));
        }

        FreshnessCheckResult::Fresh
    }

    /// Check if live revocation check is required.
    pub fn requires_live_revocation_check(&self) -> bool {
        self.requirements.require_live_revocation_check
    }
}

/// Result of freshness checking.
#[derive(Debug, Clone, PartialEq)]
pub enum FreshnessCheckResult {
    Fresh,
    Stale(String),
}

impl FreshnessCheckResult {
    pub fn is_fresh(&self) -> bool {
        matches!(self, FreshnessCheckResult::Fresh)
    }

    pub fn violation_message(&self) -> Option<&str> {
        match self {
            FreshnessCheckResult::Fresh => None,
            FreshnessCheckResult::Stale(msg) => Some(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_requirements() -> FreshnessRequirements {
        FreshnessRequirements {
            max_credential_age_seconds: Some(3600), // 1 hour
            max_proof_age_seconds: 300,             // 5 minutes
            require_live_revocation_check: true,
        }
    }

    // ====================================================================
    // FreshnessCheckResult
    // ====================================================================

    #[test]
    fn test_fresh_result_is_fresh() {
        let result = FreshnessCheckResult::Fresh;
        assert!(result.is_fresh());
        assert_eq!(result.violation_message(), None);
    }

    #[test]
    fn test_stale_result_is_not_fresh() {
        let result = FreshnessCheckResult::Stale("too old".to_string());
        assert!(!result.is_fresh());
        assert_eq!(result.violation_message(), Some("too old"));
    }

    #[test]
    fn test_freshness_result_equality() {
        assert_eq!(FreshnessCheckResult::Fresh, FreshnessCheckResult::Fresh);
        assert_ne!(
            FreshnessCheckResult::Fresh,
            FreshnessCheckResult::Stale("x".to_string())
        );
    }

    // ====================================================================
    // check_credential_age
    // ====================================================================

    #[test]
    fn test_credential_age_fresh() {
        let checker = FreshnessChecker::new(&default_requirements());
        let issued_now = SystemTime::now();
        let result = checker.check_credential_age(issued_now);
        assert!(result.is_fresh());
    }

    #[test]
    fn test_credential_age_stale() {
        let checker = FreshnessChecker::new(&default_requirements());
        // Issued 2 hours ago — exceeds 1-hour max
        let issued_2h_ago = SystemTime::now() - Duration::from_secs(7200);
        let result = checker.check_credential_age(issued_2h_ago);
        assert!(!result.is_fresh());
        let msg = result.violation_message().unwrap();
        assert!(msg.contains("maximum allowed is 3600"));
    }

    #[test]
    fn test_credential_age_no_max_always_fresh() {
        let requirements = FreshnessRequirements {
            max_credential_age_seconds: None,
            max_proof_age_seconds: 300,
            require_live_revocation_check: false,
        };
        let checker = FreshnessChecker::new(&requirements);
        // Even very old credentials pass when no max is set
        let old = SystemTime::now() - Duration::from_secs(86400 * 365);
        assert!(checker.check_credential_age(old).is_fresh());
    }

    #[test]
    fn test_credential_age_exactly_at_boundary() {
        let requirements = FreshnessRequirements {
            max_credential_age_seconds: Some(10),
            max_proof_age_seconds: 300,
            require_live_revocation_check: false,
        };
        let checker = FreshnessChecker::new(&requirements);
        // Issued exactly at the boundary — should still be fresh (age == max)
        let issued = SystemTime::now() - Duration::from_secs(10);
        assert!(checker.check_credential_age(issued).is_fresh());
    }

    #[test]
    fn test_credential_age_future_timestamp() {
        let checker = FreshnessChecker::new(&default_requirements());
        // Future timestamp — duration_since returns Err, defaults to 0 → fresh
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert!(checker.check_credential_age(future).is_fresh());
    }

    // ====================================================================
    // check_proof_age
    // ====================================================================

    #[test]
    fn test_proof_age_fresh() {
        let checker = FreshnessChecker::new(&default_requirements());
        let now = SystemTime::now();
        assert!(checker.check_proof_age(now).is_fresh());
    }

    #[test]
    fn test_proof_age_stale() {
        let checker = FreshnessChecker::new(&default_requirements());
        // 10 minutes ago — exceeds 5-minute max
        let old = SystemTime::now() - Duration::from_secs(600);
        let result = checker.check_proof_age(old);
        assert!(!result.is_fresh());
        let msg = result.violation_message().unwrap();
        assert!(msg.contains("maximum allowed is 300"));
    }

    #[test]
    fn test_proof_age_future_timestamp() {
        let checker = FreshnessChecker::new(&default_requirements());
        let future = SystemTime::now() + Duration::from_secs(60);
        assert!(checker.check_proof_age(future).is_fresh());
    }

    // ====================================================================
    // requires_live_revocation_check
    // ====================================================================

    #[test]
    fn test_requires_live_revocation_check_true() {
        let checker = FreshnessChecker::new(&default_requirements());
        assert!(checker.requires_live_revocation_check());
    }

    #[test]
    fn test_requires_live_revocation_check_false() {
        let requirements = FreshnessRequirements {
            max_credential_age_seconds: None,
            max_proof_age_seconds: 300,
            require_live_revocation_check: false,
        };
        let checker = FreshnessChecker::new(&requirements);
        assert!(!checker.requires_live_revocation_check());
    }
}
