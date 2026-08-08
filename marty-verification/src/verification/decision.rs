//! Canonical required-check decision reduction.
//!
//! Format adapters produce explicit check outcomes. This module is the sole
//! framework-neutral authority that turns those outcomes into a final decision;
//! adapters and service layers must not implement competing boolean reducers.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Stable identifier recorded in canonical verification result provenance.
pub const REQUIRED_CHECK_REDUCER_ID: &str = "mip.required-check-reducer";

/// Semantic version of the reducer algorithm implemented by this module.
pub const REQUIRED_CHECK_REDUCER_VERSION: &str = "1.0.0";

/// Whether verification processing reached a complete decision input set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationProcessingStatus {
    Completed,
    Unsupported,
    Unavailable,
    Error,
}

/// Policy-aware final verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationDecision {
    Pass,
    Fail,
    Indeterminate,
}

/// Stable explanation for the reducer's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationDecisionCode {
    AllRequiredChecksPassed,
    RequiredCheckFailed,
    RequiredCheckUnresolved,
    ProcessingNotCompleted,
}

/// Stable verification evidence category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationCheckCategory {
    Structure,
    CredentialProof,
    PresentationProof,
    DocumentIntegrity,
    IssuerTrust,
    Validity,
    Status,
    HolderBinding,
    TransactionBinding,
    ClaimConstraints,
    Biometric,
    Policy,
}

/// Explicit outcome of one verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationCheckOutcome {
    Passed,
    Failed,
    NotPerformed,
    Unsupported,
    Error,
    NotApplicable,
}

impl VerificationCheckOutcome {
    fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::NotPerformed | Self::Unsupported | Self::Error | Self::NotApplicable
        )
    }

    fn requires_evidence(self) -> bool {
        matches!(self, Self::Passed | Self::Failed)
    }
}

/// Outcome derived for all required checks in one category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationCategoryOutcome {
    Passed,
    Failed,
    Indeterminate,
    NotApplicable,
}

/// Privacy-minimized input for one verification check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheckResult {
    pub check_id: String,
    pub category: VerificationCheckCategory,
    pub required: bool,
    pub outcome: VerificationCheckOutcome,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_message: Option<String>,
    pub component_id: String,
    pub evaluated_at: String,
    pub evidence_refs: Vec<String>,
}

/// Reducer-derived summary for one verification check category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCategorySummary {
    pub category: VerificationCheckCategory,
    pub outcome: VerificationCategoryOutcome,
    pub required_check_count: u32,
    pub passed_required_count: u32,
    pub failed_required_count: u32,
    pub unresolved_required_count: u32,
}

/// Decision fields and summaries derived from a canonical check set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ReducedVerificationDecision {
    pub(crate) processing_status: VerificationProcessingStatus,
    pub(crate) decision: VerificationDecision,
    pub(crate) decision_code: VerificationDecisionCode,
    /// Legacy compatibility projection, derived only from `decision`.
    pub(crate) valid: bool,
    pub(crate) category_summaries: Vec<VerificationCategorySummary>,
}

impl ReducedVerificationDecision {
    pub fn processing_status(&self) -> VerificationProcessingStatus {
        self.processing_status
    }

    pub fn decision(&self) -> VerificationDecision {
        self.decision
    }

    pub fn decision_code(&self) -> VerificationDecisionCode {
        self.decision_code
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn category_summaries(&self) -> &[VerificationCategorySummary] {
        &self.category_summaries
    }
}

/// Invalid reducer input that cannot safely produce a decision.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerificationReductionError {
    #[error("the canonical check set must contain at least one required check")]
    MissingRequiredCheck,
    #[error("duplicate verification check ID: {check_id}")]
    DuplicateCheckId { check_id: String },
    #[error("check {check_id} with outcome {outcome:?} requires an evidence reference")]
    MissingEvidence {
        check_id: String,
        outcome: VerificationCheckOutcome,
    },
    #[error("check {check_id} contains duplicate evidence reference: {evidence_ref}")]
    DuplicateEvidenceReference {
        check_id: String,
        evidence_ref: String,
    },
    #[error("category {category:?} contains more checks than the result model supports")]
    CategoryCountOverflow { category: VerificationCheckCategory },
}

#[derive(Debug, Default)]
struct CategoryCounts {
    required: u32,
    passed: u32,
    failed: u32,
    unresolved: u32,
}

/// Reduce explicit check outcomes using the canonical required-check algorithm.
///
/// This function is deterministic and has no I/O, clock, policy, or ambient
/// tenant dependencies. Required failures dominate unresolved outcomes only
/// after processing completed. Optional checks are recorded in summaries but
/// never alter the final decision.
pub fn reduce_required_checks(
    processing_status: VerificationProcessingStatus,
    checks: &[VerificationCheckResult],
) -> Result<ReducedVerificationDecision, VerificationReductionError> {
    let mut check_ids = BTreeSet::new();
    let mut category_counts = BTreeMap::<VerificationCheckCategory, CategoryCounts>::new();
    let mut required_check_count = 0_u32;

    for check in checks {
        if !check_ids.insert(check.check_id.as_str()) {
            return Err(VerificationReductionError::DuplicateCheckId {
                check_id: check.check_id.clone(),
            });
        }

        if check.outcome.requires_evidence() && check.evidence_refs.is_empty() {
            return Err(VerificationReductionError::MissingEvidence {
                check_id: check.check_id.clone(),
                outcome: check.outcome,
            });
        }

        let mut evidence_refs = BTreeSet::new();
        for evidence_ref in &check.evidence_refs {
            if !evidence_refs.insert(evidence_ref.as_str()) {
                return Err(VerificationReductionError::DuplicateEvidenceReference {
                    check_id: check.check_id.clone(),
                    evidence_ref: evidence_ref.clone(),
                });
            }
        }

        let counts = category_counts.entry(check.category).or_default();
        if check.required {
            required_check_count = required_check_count.checked_add(1).ok_or(
                VerificationReductionError::CategoryCountOverflow {
                    category: check.category,
                },
            )?;
            counts.required = counts.required.checked_add(1).ok_or(
                VerificationReductionError::CategoryCountOverflow {
                    category: check.category,
                },
            )?;
            match check.outcome {
                VerificationCheckOutcome::Passed => {
                    counts.passed = counts.passed.checked_add(1).ok_or(
                        VerificationReductionError::CategoryCountOverflow {
                            category: check.category,
                        },
                    )?;
                }
                VerificationCheckOutcome::Failed => {
                    counts.failed = counts.failed.checked_add(1).ok_or(
                        VerificationReductionError::CategoryCountOverflow {
                            category: check.category,
                        },
                    )?;
                }
                VerificationCheckOutcome::NotPerformed
                | VerificationCheckOutcome::Unsupported
                | VerificationCheckOutcome::Error
                | VerificationCheckOutcome::NotApplicable => {
                    counts.unresolved = counts.unresolved.checked_add(1).ok_or(
                        VerificationReductionError::CategoryCountOverflow {
                            category: check.category,
                        },
                    )?;
                }
            }
        }
    }

    if required_check_count == 0 {
        return Err(VerificationReductionError::MissingRequiredCheck);
    }

    let category_summaries = category_counts
        .into_iter()
        .map(|(category, counts)| VerificationCategorySummary {
            category,
            outcome: if counts.required == 0 {
                VerificationCategoryOutcome::NotApplicable
            } else if counts.failed > 0 {
                VerificationCategoryOutcome::Failed
            } else if counts.unresolved > 0 {
                VerificationCategoryOutcome::Indeterminate
            } else {
                VerificationCategoryOutcome::Passed
            },
            required_check_count: counts.required,
            passed_required_count: counts.passed,
            failed_required_count: counts.failed,
            unresolved_required_count: counts.unresolved,
        })
        .collect();

    let (decision, decision_code) = if processing_status != VerificationProcessingStatus::Completed
    {
        (
            VerificationDecision::Indeterminate,
            VerificationDecisionCode::ProcessingNotCompleted,
        )
    } else if checks
        .iter()
        .any(|check| check.required && check.outcome == VerificationCheckOutcome::Failed)
    {
        (
            VerificationDecision::Fail,
            VerificationDecisionCode::RequiredCheckFailed,
        )
    } else if checks
        .iter()
        .any(|check| check.required && check.outcome.is_unresolved())
    {
        (
            VerificationDecision::Indeterminate,
            VerificationDecisionCode::RequiredCheckUnresolved,
        )
    } else {
        (
            VerificationDecision::Pass,
            VerificationDecisionCode::AllRequiredChecksPassed,
        )
    };

    Ok(ReducedVerificationDecision {
        processing_status,
        decision,
        decision_code,
        valid: decision == VerificationDecision::Pass,
        category_summaries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(
        check_id: &str,
        category: VerificationCheckCategory,
        required: bool,
        outcome: VerificationCheckOutcome,
    ) -> VerificationCheckResult {
        VerificationCheckResult {
            check_id: check_id.to_owned(),
            category,
            required,
            outcome,
            code: "CHECK_EVALUATED".to_owned(),
            safe_message: None,
            component_id: "test-adapter".to_owned(),
            evaluated_at: "2026-08-08T00:00:00Z".to_owned(),
            evidence_refs: if outcome.requires_evidence() {
                vec![format!("urn:marty:evidence:{check_id}")]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn passes_only_when_all_required_checks_pass() {
        let checks = [
            check(
                "credential.proof",
                VerificationCheckCategory::CredentialProof,
                true,
                VerificationCheckOutcome::Passed,
            ),
            check(
                "credential.status",
                VerificationCheckCategory::Status,
                true,
                VerificationCheckOutcome::Passed,
            ),
            check(
                "credential.biometric",
                VerificationCheckCategory::Biometric,
                false,
                VerificationCheckOutcome::Error,
            ),
        ];

        let reduced = reduce_required_checks(VerificationProcessingStatus::Completed, &checks)
            .expect("valid canonical checks");

        assert_eq!(reduced.decision, VerificationDecision::Pass);
        assert_eq!(
            reduced.decision_code,
            VerificationDecisionCode::AllRequiredChecksPassed
        );
        assert!(reduced.valid);
    }

    #[test]
    fn exhaustive_two_check_decision_table_matches_the_contract() {
        let statuses = [
            VerificationProcessingStatus::Completed,
            VerificationProcessingStatus::Unsupported,
            VerificationProcessingStatus::Unavailable,
            VerificationProcessingStatus::Error,
        ];
        let outcomes = [
            VerificationCheckOutcome::Passed,
            VerificationCheckOutcome::Failed,
            VerificationCheckOutcome::NotPerformed,
            VerificationCheckOutcome::Unsupported,
            VerificationCheckOutcome::Error,
            VerificationCheckOutcome::NotApplicable,
        ];

        for status in statuses {
            for left in outcomes {
                for right in outcomes {
                    let checks = [
                        check(
                            "credential.proof",
                            VerificationCheckCategory::CredentialProof,
                            true,
                            left,
                        ),
                        check(
                            "credential.status",
                            VerificationCheckCategory::Status,
                            true,
                            right,
                        ),
                    ];
                    let reduced = reduce_required_checks(status, &checks)
                        .expect("truth-table inputs are canonical");

                    let expected = if status != VerificationProcessingStatus::Completed {
                        (
                            VerificationDecision::Indeterminate,
                            VerificationDecisionCode::ProcessingNotCompleted,
                        )
                    } else if [left, right].contains(&VerificationCheckOutcome::Failed) {
                        (
                            VerificationDecision::Fail,
                            VerificationDecisionCode::RequiredCheckFailed,
                        )
                    } else if left.is_unresolved() || right.is_unresolved() {
                        (
                            VerificationDecision::Indeterminate,
                            VerificationDecisionCode::RequiredCheckUnresolved,
                        )
                    } else {
                        (
                            VerificationDecision::Pass,
                            VerificationDecisionCode::AllRequiredChecksPassed,
                        )
                    };

                    assert_eq!((reduced.decision, reduced.decision_code), expected);
                    assert_eq!(reduced.valid, expected.0 == VerificationDecision::Pass);
                }
            }
        }
    }

    #[test]
    fn required_failure_dominates_unresolved_check() {
        let checks = [
            check(
                "credential.proof",
                VerificationCheckCategory::CredentialProof,
                true,
                VerificationCheckOutcome::Failed,
            ),
            check(
                "credential.status",
                VerificationCheckCategory::Status,
                true,
                VerificationCheckOutcome::Unsupported,
            ),
        ];

        let reduced = reduce_required_checks(VerificationProcessingStatus::Completed, &checks)
            .expect("valid canonical checks");

        assert_eq!(reduced.decision, VerificationDecision::Fail);
        assert_eq!(
            reduced.decision_code,
            VerificationDecisionCode::RequiredCheckFailed
        );
        assert!(!reduced.valid);
    }

    #[test]
    fn every_unresolved_outcome_is_indeterminate() {
        for outcome in [
            VerificationCheckOutcome::NotPerformed,
            VerificationCheckOutcome::Unsupported,
            VerificationCheckOutcome::Error,
            VerificationCheckOutcome::NotApplicable,
        ] {
            let checks = [check(
                "credential.status",
                VerificationCheckCategory::Status,
                true,
                outcome,
            )];

            let reduced = reduce_required_checks(VerificationProcessingStatus::Completed, &checks)
                .expect("valid canonical checks");

            assert_eq!(reduced.decision, VerificationDecision::Indeterminate);
            assert_eq!(
                reduced.decision_code,
                VerificationDecisionCode::RequiredCheckUnresolved
            );
            assert!(!reduced.valid);
        }
    }

    #[test]
    fn incomplete_processing_overrides_partial_check_results() {
        let checks = [check(
            "credential.proof",
            VerificationCheckCategory::CredentialProof,
            true,
            VerificationCheckOutcome::Failed,
        )];

        for status in [
            VerificationProcessingStatus::Unsupported,
            VerificationProcessingStatus::Unavailable,
            VerificationProcessingStatus::Error,
        ] {
            let reduced = reduce_required_checks(status, &checks).expect("valid canonical checks");
            assert_eq!(reduced.decision, VerificationDecision::Indeterminate);
            assert_eq!(
                reduced.decision_code,
                VerificationDecisionCode::ProcessingNotCompleted
            );
            assert!(!reduced.valid);
        }
    }

    #[test]
    fn rejects_empty_and_optional_only_check_sets() {
        assert_eq!(
            reduce_required_checks(VerificationProcessingStatus::Completed, &[]),
            Err(VerificationReductionError::MissingRequiredCheck)
        );

        let optional = [check(
            "credential.biometric",
            VerificationCheckCategory::Biometric,
            false,
            VerificationCheckOutcome::Passed,
        )];
        assert_eq!(
            reduce_required_checks(VerificationProcessingStatus::Completed, &optional),
            Err(VerificationReductionError::MissingRequiredCheck)
        );
    }

    #[test]
    fn rejects_duplicate_check_ids() {
        let duplicate = check(
            "credential.proof",
            VerificationCheckCategory::CredentialProof,
            true,
            VerificationCheckOutcome::Passed,
        );

        assert_eq!(
            reduce_required_checks(
                VerificationProcessingStatus::Completed,
                &[duplicate.clone(), duplicate]
            ),
            Err(VerificationReductionError::DuplicateCheckId {
                check_id: "credential.proof".to_owned()
            })
        );
    }

    #[test]
    fn rejects_terminal_outcomes_without_unique_evidence() {
        let mut missing = check(
            "credential.proof",
            VerificationCheckCategory::CredentialProof,
            true,
            VerificationCheckOutcome::Passed,
        );
        missing.evidence_refs.clear();
        assert!(matches!(
            reduce_required_checks(VerificationProcessingStatus::Completed, &[missing]),
            Err(VerificationReductionError::MissingEvidence { .. })
        ));

        let mut duplicate = check(
            "credential.status",
            VerificationCheckCategory::Status,
            true,
            VerificationCheckOutcome::Failed,
        );
        duplicate
            .evidence_refs
            .push(duplicate.evidence_refs[0].clone());
        assert!(matches!(
            reduce_required_checks(VerificationProcessingStatus::Completed, &[duplicate]),
            Err(VerificationReductionError::DuplicateEvidenceReference { .. })
        ));
    }

    #[test]
    fn derives_deterministic_category_summaries() {
        let checks = [
            check(
                "credential.status.revocation",
                VerificationCheckCategory::Status,
                true,
                VerificationCheckOutcome::Passed,
            ),
            check(
                "credential.status.suspension",
                VerificationCheckCategory::Status,
                true,
                VerificationCheckOutcome::Error,
            ),
            check(
                "credential.biometric",
                VerificationCheckCategory::Biometric,
                false,
                VerificationCheckOutcome::Failed,
            ),
        ];

        let reduced = reduce_required_checks(VerificationProcessingStatus::Completed, &checks)
            .expect("valid canonical checks");

        assert_eq!(
            reduced.category_summaries,
            vec![
                VerificationCategorySummary {
                    category: VerificationCheckCategory::Status,
                    outcome: VerificationCategoryOutcome::Indeterminate,
                    required_check_count: 2,
                    passed_required_count: 1,
                    failed_required_count: 0,
                    unresolved_required_count: 1,
                },
                VerificationCategorySummary {
                    category: VerificationCheckCategory::Biometric,
                    outcome: VerificationCategoryOutcome::NotApplicable,
                    required_check_count: 0,
                    passed_required_count: 0,
                    failed_required_count: 0,
                    unresolved_required_count: 0,
                },
            ]
        );
    }

    #[test]
    fn serializes_protocol_vocabulary() {
        assert_eq!(REQUIRED_CHECK_REDUCER_ID, "mip.required-check-reducer");
        assert_eq!(REQUIRED_CHECK_REDUCER_VERSION, "1.0.0");

        let checks = [check(
            "credential.proof",
            VerificationCheckCategory::CredentialProof,
            true,
            VerificationCheckOutcome::Passed,
        )];
        let reduced = reduce_required_checks(VerificationProcessingStatus::Completed, &checks)
            .expect("canonical checks");

        let value = serde_json::to_value(reduced).expect("serializable reducer output");
        assert_eq!(value["processing_status"], "COMPLETED");
        assert_eq!(value["decision"], "PASS");
        assert_eq!(value["decision_code"], "ALL_REQUIRED_CHECKS_PASSED");
    }
}
