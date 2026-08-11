//! Freshness constraint validation.

use crate::policy::types::FreshnessRequirements;

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
    pub fn check_credential_age(
        &self,
        issued_at_epoch_seconds: u64,
        evaluation_time_epoch_seconds: u64,
    ) -> FreshnessCheckResult {
        let Some(age_seconds) = evaluation_time_epoch_seconds.checked_sub(issued_at_epoch_seconds)
        else {
            return FreshnessCheckResult::InvalidFuture(
                "Credential issuance time is after evaluation time".to_string(),
            );
        };
        if let Some(max_age_seconds) = self.requirements.max_credential_age_seconds {
            if age_seconds > max_age_seconds {
                return FreshnessCheckResult::Stale(format!(
                    "Credential is {} seconds old, maximum allowed is {}",
                    age_seconds, max_age_seconds
                ));
            }
        }

        FreshnessCheckResult::Fresh
    }

    /// Validate presentation/proof time against max proof age.
    pub fn check_proof_age(
        &self,
        proof_epoch_seconds: u64,
        evaluation_time_epoch_seconds: u64,
    ) -> FreshnessCheckResult {
        let Some(age_seconds) = evaluation_time_epoch_seconds.checked_sub(proof_epoch_seconds)
        else {
            return FreshnessCheckResult::InvalidFuture(
                "Proof time is after evaluation time".to_string(),
            );
        };
        if age_seconds > self.requirements.max_proof_age_seconds {
            return FreshnessCheckResult::Stale(format!(
                "Proof is {} seconds old, maximum allowed is {}",
                age_seconds, self.requirements.max_proof_age_seconds
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
    InvalidFuture(String),
}

impl FreshnessCheckResult {
    pub fn is_fresh(&self) -> bool {
        matches!(self, FreshnessCheckResult::Fresh)
    }

    pub fn violation_message(&self) -> Option<&str> {
        match self {
            FreshnessCheckResult::Fresh => None,
            FreshnessCheckResult::Stale(msg) | FreshnessCheckResult::InvalidFuture(msg) => {
                Some(msg)
            }
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
        let result = checker.check_credential_age(1_000, 1_000);
        assert!(result.is_fresh());
    }

    #[test]
    fn test_credential_age_stale() {
        let checker = FreshnessChecker::new(&default_requirements());
        // Issued 2 hours ago — exceeds 1-hour max
        let result = checker.check_credential_age(1_000, 8_200);
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
        assert!(checker.check_credential_age(1, 31_536_001).is_fresh());
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
        assert!(checker.check_credential_age(90, 100).is_fresh());
    }

    #[test]
    fn test_credential_age_future_timestamp() {
        let checker = FreshnessChecker::new(&default_requirements());
        // Future timestamp — duration_since returns Err, defaults to 0 → fresh
        assert!(matches!(
            checker.check_credential_age(101, 100),
            FreshnessCheckResult::InvalidFuture(_)
        ));
    }

    // ====================================================================
    // check_proof_age
    // ====================================================================

    #[test]
    fn test_proof_age_fresh() {
        let checker = FreshnessChecker::new(&default_requirements());
        assert!(checker.check_proof_age(1_000, 1_000).is_fresh());
    }

    #[test]
    fn test_proof_age_stale() {
        let checker = FreshnessChecker::new(&default_requirements());
        // 10 minutes ago — exceeds 5-minute max
        let result = checker.check_proof_age(400, 1_000);
        assert!(!result.is_fresh());
        let msg = result.violation_message().unwrap();
        assert!(msg.contains("maximum allowed is 300"));
    }

    #[test]
    fn test_proof_age_future_timestamp() {
        let checker = FreshnessChecker::new(&default_requirements());
        assert!(matches!(
            checker.check_proof_age(1_001, 1_000),
            FreshnessCheckResult::InvalidFuture(_)
        ));
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
