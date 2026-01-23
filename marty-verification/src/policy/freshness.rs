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
