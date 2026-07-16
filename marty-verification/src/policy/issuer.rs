//! Issuer constraint checking.

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
        // If explicit allowlist exists, issuer must be in it
        if !self.allowed_issuers.is_empty() {
            if !self.allowed_issuers.contains(&issuer_id.to_string()) {
                return IssuerCheckResult::NotAllowed(format!(
                    "Issuer '{}' not in allowed issuers list",
                    issuer_id
                ));
            }
        }

        // If trust profile is specified, issuer must be verified against it
        if self.trust_profile_id.is_some() && !trust_profile_verified {
            return IssuerCheckResult::NotTrusted(format!(
                "Issuer '{}' not verified against trust profile",
                issuer_id
            ));
        }

        IssuerCheckResult::Trusted
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
