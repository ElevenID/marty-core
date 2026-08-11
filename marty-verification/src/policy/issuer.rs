//! Compatibility API for issuer constraint checking.

use super::{
    compat::{neutral_input, neutral_policy},
    PolicyErrorCode, PolicyEvaluator,
};

/// Checks issuer constraints (allowlist and trust profile).
pub struct IssuerConstraintChecker {
    trust_profile_id: Option<String>,
    allowed_issuers: Vec<String>,
}

impl IssuerConstraintChecker {
    pub fn new(trust_profile_id: Option<&String>, allowed_issuers: &[String]) -> Self {
        Self {
            trust_profile_id: trust_profile_id.cloned(),
            allowed_issuers: allowed_issuers.to_vec(),
        }
    }

    /// Check if an issuer is trusted according to policy constraints.
    ///
    /// # Arguments
    /// * `issuer_id` - DID, certificate DN, or other issuer identifier
    /// * `trust_profile_verified` - Whether issuer was verified against trust profile
    pub fn check_issuer(&self, issuer_id: &str, trust_profile_verified: bool) -> IssuerCheckResult {
        let mut policy = neutral_policy();
        policy.trust_profile_id.clone_from(&self.trust_profile_id);
        policy.allowed_issuers.clone_from(&self.allowed_issuers);
        let mut input = neutral_input();
        input.issuer_id = issuer_id.to_string();
        input.trust_profile_verified = trust_profile_verified;

        let result = PolicyEvaluator::new(policy).evaluate(&input);
        if let Some(error) = result
            .errors
            .iter()
            .find(|error| error.code == PolicyErrorCode::IssuerNotAllowed)
        {
            return IssuerCheckResult::NotAllowed(error.message.clone());
        }
        if let Some(error) = result
            .errors
            .iter()
            .find(|error| error.code == PolicyErrorCode::IssuerNotTrusted)
        {
            return IssuerCheckResult::NotTrusted(error.message.clone());
        }
        if result.is_satisfied {
            IssuerCheckResult::Trusted
        } else {
            IssuerCheckResult::NotTrusted(
                "Issuer constraints could not be evaluated by the canonical policy kernel"
                    .to_string(),
            )
        }
    }

    /// Check if policy has issuer constraints.
    pub fn has_constraints(&self) -> bool {
        self.trust_profile_id.is_some() || !self.allowed_issuers.is_empty()
    }
}

/// Result of issuer constraint checking.
#[derive(Debug, Clone, PartialEq)]
pub enum IssuerCheckResult {
    Trusted,
    NotAllowed(String),
    NotTrusted(String),
}

impl IssuerCheckResult {
    pub fn is_trusted(&self) -> bool {
        matches!(self, IssuerCheckResult::Trusted)
    }

    pub fn violation_message(&self) -> Option<&str> {
        match self {
            IssuerCheckResult::Trusted => None,
            IssuerCheckResult::NotAllowed(msg) => Some(msg),
            IssuerCheckResult::NotTrusted(msg) => Some(msg),
        }
    }
}
