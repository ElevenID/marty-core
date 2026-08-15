//! Canonical eMRTD data-group integrity comparison and risk reporting.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{VerificationError, VerificationResult};

#[derive(Debug, Clone, Deserialize)]
pub struct IntegrityRequest {
    pub algorithm: String,
    pub expected_hashes: BTreeMap<u8, String>,
    pub computed_hashes: Vec<ComputedHash>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComputedHash {
    pub data_group: u8,
    pub hash: String,
    pub algorithm: String,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(default)]
    pub error_message: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntegrityEntry {
    pub data_group: u8,
    pub data_group_name: String,
    pub description: String,
    pub result: String,
    pub severity: String,
    pub is_mandatory: bool,
    pub is_biometric: bool,
    pub expected_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub algorithm: String,
    pub message: String,
    pub is_valid: bool,
    pub is_critical_error: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IntegrityReport {
    pub total_data_groups: usize,
    pub successful_verifications: usize,
    pub failed_verifications: usize,
    pub critical_errors: usize,
    pub warnings: usize,
    pub algorithm: String,
    pub comparison_entries: Vec<IntegrityEntry>,
    pub overall_status: String,
    pub success_rate_percent: f64,
    pub mandatory_data_groups: usize,
    pub is_passport_valid: bool,
    pub mismatch_analysis: MismatchAnalysis,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MismatchAnalysis {
    pub summary: String,
    pub total_mismatches: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detailed_mismatches: Vec<MismatchDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_implications: Option<SecurityImplications>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MismatchDetail {
    pub data_group: String,
    pub description: String,
    pub mismatch_type: String,
    pub severity: String,
    pub is_mandatory: bool,
    pub is_biometric: bool,
    pub expected_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub hash_size_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity_analysis: Option<SimilarityAnalysis>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SimilarityAnalysis {
    pub matching_bytes: usize,
    pub total_bytes: usize,
    pub similarity_percent: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityImplications {
    pub risk_level: String,
    pub risk_description: String,
    pub affected_mandatory_dgs: usize,
    pub affected_biometric_dgs: usize,
    pub total_affected_dgs: usize,
    pub recommendations: Vec<String>,
}

pub fn compare(request: &IntegrityRequest) -> VerificationResult<IntegrityReport> {
    let algorithm = normalize_algorithm(&request.algorithm)?;
    let mut computed = HashMap::new();
    for item in &request.computed_hashes {
        if computed.insert(item.data_group, item).is_some() {
            return Err(VerificationError::internal(format!(
                "duplicate computed hash for DG{}",
                item.data_group
            )));
        }
    }

    let mut entries = Vec::new();
    let mut successful = 0;
    let mut failed = 0;
    let mut critical = 0;
    let mut warnings = 0;

    for (&dg, expected_hex) in &request.expected_hashes {
        let Some(info) = data_group_info(dg) else {
            continue;
        };
        let expected = decode_hash(expected_hex, "expected", dg)?;
        let entry = match computed.get(&dg) {
            None => make_entry(
                info,
                "missing_computed",
                if info.mandatory {
                    "critical"
                } else {
                    "warning"
                },
                Some(&expected),
                None,
                algorithm,
                format!("Computed hash missing for {}", info.description),
            ),
            Some(value) if !value.success => make_entry(
                info,
                "missing_computed",
                if info.mandatory {
                    "critical"
                } else {
                    "warning"
                },
                Some(&expected),
                None,
                algorithm,
                value
                    .error_message
                    .clone()
                    .unwrap_or_else(|| format!("Computed hash missing for {}", info.description)),
            ),
            Some(value) => {
                let computed_algorithm = normalize_algorithm(&value.algorithm)?;
                let actual = decode_hash(&value.hash, "computed", dg)?;
                if computed_algorithm != algorithm {
                    make_entry(
                        info,
                        "algorithm_error",
                        "error",
                        Some(&expected),
                        Some(&actual),
                        algorithm,
                        format!(
                            "Algorithm mismatch: expected {}, got {}",
                            algorithm, computed_algorithm
                        ),
                    )
                } else if expected.len() != actual.len() {
                    make_entry(
                        info,
                        "mismatch",
                        "critical",
                        Some(&expected),
                        Some(&actual),
                        algorithm,
                        format!(
                            "Hash size mismatch: expected {} bytes, got {} bytes",
                            expected.len(),
                            actual.len()
                        ),
                    )
                } else if expected == actual {
                    make_entry(
                        info,
                        "match",
                        "info",
                        Some(&expected),
                        Some(&actual),
                        algorithm,
                        format!("Hash verification successful for {}", info.description),
                    )
                } else {
                    make_entry(
                        info,
                        "mismatch",
                        if info.mandatory {
                            "critical"
                        } else {
                            "warning"
                        },
                        Some(&expected),
                        Some(&actual),
                        algorithm,
                        format!("Hash mismatch detected for {}", info.description),
                    )
                }
            }
        };
        if entry.is_valid {
            successful += 1;
        } else {
            failed += 1;
            if entry.is_critical_error {
                critical += 1;
            } else {
                warnings += 1;
            }
        }
        entries.push(entry);
    }

    for item in &request.computed_hashes {
        if request.expected_hashes.contains_key(&item.data_group) {
            continue;
        }
        let Some(info) = data_group_info(item.data_group) else {
            continue;
        };
        let actual = decode_hash(&item.hash, "computed", item.data_group)?;
        entries.push(make_entry(
            info,
            "missing_expected",
            "info",
            None,
            Some(&actual),
            algorithm,
            format!("No expected hash in SOD for {}", info.description),
        ));
    }

    entries.sort_by_key(|entry| entry.data_group);
    let total = entries.len();
    let success_rate = if total == 0 {
        0.0
    } else {
        successful as f64 / total as f64 * 100.0
    };
    let mandatory = entries.iter().filter(|entry| entry.is_mandatory).count();
    let overall_status = if critical > 0 {
        "FAILED - Critical errors detected"
    } else if failed > successful {
        "FAILED - More failures than successes"
    } else if warnings > 0 {
        "PASSED - With warnings"
    } else {
        "PASSED - All verifications successful"
    };
    let is_valid = critical == 0 && successful >= mandatory && success_rate >= 80.0;
    let mismatch_analysis = analyze_mismatches(&entries)?;

    Ok(IntegrityReport {
        total_data_groups: total,
        successful_verifications: successful,
        failed_verifications: failed,
        critical_errors: critical,
        warnings,
        algorithm: algorithm.to_string(),
        comparison_entries: entries,
        overall_status: overall_status.to_string(),
        success_rate_percent: round2(success_rate),
        mandatory_data_groups: mandatory,
        is_passport_valid: is_valid,
        mismatch_analysis,
    })
}

pub fn compare_json(request_json: &str) -> VerificationResult<String> {
    let request: IntegrityRequest = serde_json::from_str(request_json).map_err(|error| {
        VerificationError::internal(format!("invalid integrity request: {error}"))
    })?;
    serde_json::to_string(&compare(&request)?).map_err(|error| {
        VerificationError::internal(format!("serialize integrity report: {error}"))
    })
}

fn analyze_mismatches(entries: &[IntegrityEntry]) -> VerificationResult<MismatchAnalysis> {
    let mismatches: Vec<_> = entries
        .iter()
        .filter(|entry| entry.result == "mismatch")
        .collect();
    if mismatches.is_empty() {
        return Ok(MismatchAnalysis {
            summary: "No hash mismatches detected".to_string(),
            total_mismatches: 0,
            analysis: Some("All data group hashes match their expected values".to_string()),
            detailed_mismatches: Vec::new(),
            security_implications: None,
        });
    }

    let mut details = Vec::new();
    for entry in &mismatches {
        let expected = decode_optional(entry.expected_hash.as_deref())?;
        let computed = decode_optional(entry.computed_hash.as_deref())?;
        let (kind, similarity) = mismatch_similarity(&expected, &computed);
        details.push(MismatchDetail {
            data_group: entry.data_group_name.clone(),
            description: entry.description.clone(),
            mismatch_type: kind,
            severity: entry.severity.clone(),
            is_mandatory: entry.is_mandatory,
            is_biometric: entry.is_biometric,
            expected_hash: entry.expected_hash.clone(),
            computed_hash: entry.computed_hash.clone(),
            hash_size_bytes: expected.as_ref().map_or(0, Vec::len),
            similarity_analysis: similarity,
        });
    }

    let mandatory = mismatches.iter().filter(|entry| entry.is_mandatory).count();
    let biometric = mismatches.iter().filter(|entry| entry.is_biometric).count();
    let critical = mismatches
        .iter()
        .filter(|entry| entry.is_critical_error)
        .count();
    let (risk, description, mut recommendations) = if critical > 0 || mandatory > 0 {
        (
            "HIGH",
            "Critical security risk - mandatory data groups compromised",
            vec![
                "REJECT passport - critical security failure detected",
                "Verify passport authenticity through alternative means",
                "Report potential document tampering to authorities",
                "Do not rely on digital verification for this document",
            ],
        )
    } else if biometric > 0 || mismatches.len() > 3 {
        (
            "MEDIUM",
            if biometric > 0 {
                "Moderate security risk - biometric data integrity compromised"
            } else {
                "Moderate security risk - multiple data groups affected"
            },
            vec![
                "Exercise caution - moderate security concerns detected",
                "Perform additional manual verification steps",
                "Consider secondary authentication methods",
                "Review biometric data integrity if affected",
            ],
        )
    } else {
        (
            "LOW",
            "Low security risk - limited impact to optional data groups",
            vec![
                "Proceed with caution - minor integrity issues detected",
                "Document findings for audit trail",
                "Consider re-scanning if possible",
            ],
        )
    };
    let mut recommendations: Vec<String> = recommendations.drain(..).map(str::to_string).collect();
    if mandatory > 0 {
        recommendations.push(format!(
            "Pay special attention to mandatory data groups: {}",
            mismatches
                .iter()
                .filter(|entry| entry.is_mandatory)
                .map(|entry| entry.data_group_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if biometric > 0 {
        recommendations.push(format!(
            "Verify biometric data independently: {}",
            mismatches
                .iter()
                .filter(|entry| entry.is_biometric)
                .map(|entry| entry.data_group_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(MismatchAnalysis {
        summary: format!("{} hash mismatches detected", mismatches.len()),
        total_mismatches: mismatches.len(),
        analysis: None,
        detailed_mismatches: details,
        security_implications: Some(SecurityImplications {
            risk_level: risk.to_string(),
            risk_description: description.to_string(),
            affected_mandatory_dgs: mandatory,
            affected_biometric_dgs: biometric,
            total_affected_dgs: mismatches.len(),
            recommendations,
        }),
    })
}

fn mismatch_similarity(
    expected: &Option<Vec<u8>>,
    computed: &Option<Vec<u8>>,
) -> (String, Option<SimilarityAnalysis>) {
    let (Some(expected), Some(computed)) = (expected, computed) else {
        return ("unknown".to_string(), None);
    };
    if expected.len() != computed.len() {
        return ("size_mismatch".to_string(), None);
    }
    if expected.is_empty() {
        return ("unknown".to_string(), None);
    }
    let matching = expected
        .iter()
        .zip(computed)
        .filter(|(left, right)| left == right)
        .count();
    let percent = matching as f64 / expected.len() as f64 * 100.0;
    let kind = if percent < 10.0 {
        "completely_different"
    } else if percent < 50.0 {
        "partially_different"
    } else {
        "minor_difference"
    };
    let similarity = (kind != "completely_different").then_some(SimilarityAnalysis {
        matching_bytes: matching,
        total_bytes: expected.len(),
        similarity_percent: round2(percent),
    });
    (kind.to_string(), similarity)
}

fn decode_optional(value: Option<&str>) -> VerificationResult<Option<Vec<u8>>> {
    value
        .map(|value| decode_hash(value, "report", 0))
        .transpose()
}

fn decode_hash(value: &str, kind: &str, dg: u8) -> VerificationResult<Vec<u8>> {
    hex::decode(value).map_err(|error| {
        VerificationError::internal(format!("invalid {kind} hash for DG{dg}: {error}"))
    })
}

fn normalize_algorithm(value: &str) -> VerificationResult<&'static str> {
    match value.to_ascii_lowercase().replace('-', "").as_str() {
        "sha1" => Ok("sha1"),
        "sha256" => Ok("sha256"),
        "sha384" => Ok("sha384"),
        "sha512" => Ok("sha512"),
        _ => Err(VerificationError::internal(format!(
            "unsupported hash algorithm: {value}"
        ))),
    }
}

fn make_entry(
    info: DataGroupInfo,
    result: &str,
    severity: &str,
    expected: Option<&[u8]>,
    computed: Option<&[u8]>,
    algorithm: &str,
    message: String,
) -> IntegrityEntry {
    IntegrityEntry {
        data_group: info.number,
        data_group_name: info.name.to_string(),
        description: info.description.to_string(),
        result: result.to_string(),
        severity: severity.to_string(),
        is_mandatory: info.mandatory,
        is_biometric: info.biometric,
        expected_hash: expected.map(hex_upper),
        computed_hash: computed.map(hex_upper),
        algorithm: algorithm.to_string(),
        message,
        is_valid: result == "match",
        is_critical_error: severity == "critical" || (result == "mismatch" && info.mandatory),
    }
}

fn hex_upper(value: &[u8]) -> String {
    hex::encode_upper(value)
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Copy)]
struct DataGroupInfo {
    number: u8,
    name: &'static str,
    description: &'static str,
    mandatory: bool,
    biometric: bool,
}

fn data_group_info(number: u8) -> Option<DataGroupInfo> {
    const NAMES: [&str; 15] = [
        "DG1_MRZ",
        "DG2_FACE",
        "DG3_FINGERPRINT",
        "DG4_IRIS",
        "DG5_PORTRAIT",
        "DG6_RESERVED",
        "DG7_SIGNATURE",
        "DG8_DATA_FEATURES",
        "DG9_STRUCTURE_FEATURES",
        "DG10_SUBSTANCE_FEATURES",
        "DG11_ADDITIONAL_PERSONAL",
        "DG12_ADDITIONAL_DOCUMENT",
        "DG13_OPTIONAL_DETAILS",
        "DG14_SECURITY_INFOS",
        "DG15_ACTIVE_AUTH",
    ];
    const DESCRIPTIONS: [&str; 15] = [
        "Machine Readable Zone (MRZ) data",
        "Encoded face biometric data",
        "Encoded fingerprint biometric data",
        "Encoded iris biometric data",
        "Displayed portrait image",
        "Reserved for future use",
        "Displayed signature or mark",
        "Data features",
        "Structure features",
        "Substance features",
        "Additional personal details",
        "Additional document details",
        "Optional details",
        "Security infos",
        "Active authentication public key info",
    ];
    let index = number.checked_sub(1)? as usize;
    Some(DataGroupInfo {
        number,
        name: NAMES.get(index)?,
        description: DESCRIPTIONS.get(index)?,
        mandatory: matches!(number, 1 | 2),
        biometric: matches!(number, 2..=4),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_mismatch_fails_closed() {
        let report = compare(&IntegrityRequest {
            algorithm: "sha256".to_string(),
            expected_hashes: BTreeMap::from([(1, "00".repeat(32))]),
            computed_hashes: vec![ComputedHash {
                data_group: 1,
                hash: "ff".repeat(32),
                algorithm: "sha256".to_string(),
                success: true,
                error_message: None,
            }],
        })
        .unwrap();
        assert!(!report.is_passport_valid);
        assert_eq!(report.critical_errors, 1);
        assert_eq!(
            report
                .mismatch_analysis
                .security_implications
                .unwrap()
                .risk_level,
            "HIGH"
        );
    }

    #[test]
    fn duplicate_computed_hashes_are_rejected() {
        let hash = ComputedHash {
            data_group: 1,
            hash: "00".repeat(32),
            algorithm: "sha256".to_string(),
            success: true,
            error_message: None,
        };
        assert!(compare(&IntegrityRequest {
            algorithm: "sha256".to_string(),
            expected_hashes: BTreeMap::new(),
            computed_hashes: vec![hash.clone(), hash],
        })
        .is_err());
    }
}
