//! Credential ranking for multi-credential scenarios.

use crate::policy::types::{CredentialRankingStrategy, PresentationPolicy};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::SystemTime;

/// Ranks credentials when multiple match a policy.
pub struct CredentialRanker {
    strategy: CredentialRankingStrategy,
    weights: HashMap<String, f64>,
}

impl CredentialRanker {
    pub fn new(policy: &PresentationPolicy) -> Self {
        Self {
            strategy: policy.credential_ranking_strategy,
            weights: policy.credential_ranking_weights.clone(),
        }
    }

    /// Rank a list of credentials according to the configured strategy.
    /// 
    /// Returns credentials sorted from most to least preferred.
    pub fn rank(&self, credentials: &mut [RankableCredential]) {
        match self.strategy {
            CredentialRankingStrategy::FreshestFirst => {
                credentials.sort_by(|a, b| {
                    b.issued_at
                        .cmp(&a.issued_at)
                        .then_with(|| a.issuer_id.cmp(&b.issuer_id))
                });
            }
            CredentialRankingStrategy::HighestTrustFirst => {
                credentials.sort_by(|a, b| {
                    b.trust_level
                        .partial_cmp(&a.trust_level)
                        .unwrap_or(Ordering::Equal)
                        .then_with(|| b.issued_at.cmp(&a.issued_at))
                });
            }
            CredentialRankingStrategy::MinimumClaimsFirst => {
                credentials.sort_by(|a, b| {
                    a.claim_count
                        .cmp(&b.claim_count)
                        .then_with(|| b.issued_at.cmp(&a.issued_at))
                });
            }
            CredentialRankingStrategy::Custom => {
                // Apply weighted scoring
                let freshness_weight = self.weights.get("freshness").copied().unwrap_or(1.0);
                let trust_weight = self.weights.get("trust_level").copied().unwrap_or(1.0);
                let claim_weight = self.weights.get("claim_count").copied().unwrap_or(-0.1);

                credentials.sort_by(|a, b| {
                    let score_a = self.compute_custom_score(a, freshness_weight, trust_weight, claim_weight);
                    let score_b = self.compute_custom_score(b, freshness_weight, trust_weight, claim_weight);
                    
                    score_b
                        .partial_cmp(&score_a)
                        .unwrap_or(Ordering::Equal)
                });
            }
        }
    }

    fn compute_custom_score(
        &self,
        cred: &RankableCredential,
        freshness_weight: f64,
        trust_weight: f64,
        claim_weight: f64,
    ) -> f64 {
        // Freshness score: normalize age to 0-1 (newer is higher)
        let age_seconds = SystemTime::now()
            .duration_since(cred.issued_at)
            .unwrap_or_default()
            .as_secs() as f64;
        let max_age = 31536000.0; // 1 year in seconds
        let freshness_score = (max_age - age_seconds.min(max_age)) / max_age;

        // Trust score: already 0-1 normalized
        let trust_score = cred.trust_level;

        // Claim count score: fewer claims is better (inverted)
        let claim_score = cred.claim_count as f64;

        freshness_weight * freshness_score
            + trust_weight * trust_score
            + claim_weight * claim_score
    }
}

/// Metadata about a credential for ranking purposes.
#[derive(Debug, Clone)]
pub struct RankableCredential {
    pub credential_id: String,
    pub issuer_id: String,
    pub issued_at: SystemTime,
    pub trust_level: f64,     // 0.0 - 1.0, higher is more trusted
    pub claim_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_policy(strategy: CredentialRankingStrategy) -> PresentationPolicy {
        PresentationPolicy {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            purpose: "Test".to_string(),
            accepted_credential_types: vec![],
            required_claims: vec![],
            holder_binding: crate::policy::types::HolderBindingMethod::None,
            trust_profile_id: None,
            allowed_issuers: vec![],
            freshness_requirements: Default::default(),
            prefer_predicates: true,
            single_presentation: false,
            derived_attribute_preferences: HashMap::new(),
            credential_ranking_strategy: strategy,
            credential_ranking_weights: HashMap::new(),
            metadata: HashMap::new(),
            version: 1,
        }
    }

    #[test]
    fn test_freshest_first_ranking() {
        let policy = create_test_policy(CredentialRankingStrategy::FreshestFirst);
        let ranker = CredentialRanker::new(&policy);

        let mut creds = vec![
            RankableCredential {
                credential_id: "old".to_string(),
                issuer_id: "issuer1".to_string(),
                issued_at: SystemTime::UNIX_EPOCH,
                trust_level: 0.9,
                claim_count: 5,
            },
            RankableCredential {
                credential_id: "new".to_string(),
                issuer_id: "issuer1".to_string(),
                issued_at: SystemTime::now(),
                trust_level: 0.8,
                claim_count: 10,
            },
        ];

        ranker.rank(&mut creds);

        assert_eq!(creds[0].credential_id, "new");
        assert_eq!(creds[1].credential_id, "old");
    }
}
