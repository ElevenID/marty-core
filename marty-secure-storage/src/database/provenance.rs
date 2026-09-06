//! Shared decoding and package-state consistency for stored trust records.

use super::{load_open_badge_package_provenance, parse_stored_timestamp, required_stored_value};
use crate::{StorageError, TrustPackageProvenance};
use rusqlite::{Connection, Row};
use std::collections::hash_map::{Entry, HashMap};

#[derive(Clone, Copy)]
pub(super) enum RecordKind {
    Anchor,
    Method,
}

impl RecordKind {
    fn label(self) -> &'static str {
        match self {
            Self::Anchor => "trust anchor",
            Self::Method => "method",
        }
    }
}

pub(super) struct StoredProvenance {
    domain: Option<String>,
    sequence: Option<i64>,
    version: Option<String>,
    created: Option<String>,
    expires: Option<String>,
    signer: Option<String>,
    digest: Option<String>,
    imported: Option<String>,
}

impl StoredProvenance {
    pub(super) fn read(row: &Row<'_>) -> Result<Self, StorageError> {
        Ok(Self {
            domain: row.get("trust_domain")?,
            sequence: row.get("package_sequence")?,
            version: row.get("package_version")?,
            created: row.get("package_created_at")?,
            expires: row.get("package_expires_at")?,
            signer: row.get("package_signer_key_id")?,
            digest: row.get("package_digest")?,
            imported: row.get("package_imported_at")?,
        })
    }

    pub(super) fn is_governed(&self) -> bool {
        self.domain.is_some()
    }

    pub(super) fn decode(
        self,
        kind: RecordKind,
        id: &str,
    ) -> Result<Option<TrustPackageProvenance>, StorageError> {
        let label = kind.label();
        let Some(domain) = self.domain else {
            if self.sequence.is_some()
                || self.version.is_some()
                || self.created.is_some()
                || self.expires.is_some()
                || self.signer.is_some()
                || self.digest.is_some()
                || self.imported.is_some()
            {
                return Err(StorageError::InvalidTrustPackage(format!(
                    "{label} {id} has partial package provenance"
                )));
            }
            return Ok(None);
        };
        let sequence = self.sequence.ok_or_else(|| {
            StorageError::InvalidTrustPackage(format!("{label} {id} is missing package sequence"))
        })?;
        let sequence = u64::try_from(sequence).map_err(|_| {
            StorageError::InvalidTrustPackage(format!("{label} {id} has invalid package sequence"))
        })?;

        // Keep each record kind's established error precedence for malformed rows.
        let method_times = if matches!(kind, RecordKind::Method) {
            Some((
                parse_stored_timestamp(self.created.as_deref(), id, "package creation time")?,
                parse_stored_timestamp(self.imported.as_deref(), id, "package import time")?,
            ))
        } else {
            None
        };
        let version = required_stored_value(self.version, id, "package version")?;
        let created_at = match method_times {
            Some((created, _)) => created,
            None => parse_stored_timestamp(self.created.as_deref(), id, "package creation time")?,
        };
        let expires_at =
            parse_stored_timestamp(self.expires.as_deref(), id, "package expiry time")?;
        let signer_key_id = required_stored_value(self.signer, id, "package signer key id")?;
        let package_digest = required_stored_value(self.digest, id, "package digest")?;
        let imported_at = match method_times {
            Some((_, imported)) => imported,
            None => parse_stored_timestamp(self.imported.as_deref(), id, "package import time")?,
        };
        Ok(Some(TrustPackageProvenance {
            trust_domain: domain,
            sequence,
            package_version: version,
            created_at,
            expires_at,
            signer_key_id,
            package_digest,
            imported_at,
        }))
    }
}

pub(super) fn check_package_states<'a>(
    conn: &Connection,
    records: impl IntoIterator<Item = (&'a str, Option<&'a TrustPackageProvenance>)>,
    kind: RecordKind,
) -> Result<(), StorageError> {
    let mut states = HashMap::new();
    let label = kind.label();
    for (id, provenance) in records {
        let Some(provenance) = provenance else {
            continue;
        };
        let stored = match states.entry(&provenance.trust_domain) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                load_open_badge_package_provenance(conn, &provenance.trust_domain)?.ok_or_else(
                    || {
                        StorageError::InvalidTrustPackage(format!(
                            "{label} {id} references missing package state for domain {}",
                            provenance.trust_domain
                        ))
                    },
                )?,
            ),
        };
        if stored != provenance {
            return Err(StorageError::InvalidTrustPackage(format!(
                "{label} {id} provenance conflicts with package state for domain {}",
                provenance.trust_domain
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> StoredProvenance {
        StoredProvenance {
            domain: Some("example".into()),
            sequence: Some(7),
            version: Some("v7".into()),
            created: Some("2026-09-01T00:00:00Z".into()),
            expires: Some("2026-10-01T00:00:00Z".into()),
            signer: Some("key-1".into()),
            digest: Some("digest".into()),
            imported: Some("2026-09-02T00:00:00Z".into()),
        }
    }

    #[test]
    fn record_kinds_decode_the_same_complete_provenance() {
        let anchor = valid().decode(RecordKind::Anchor, "record").unwrap();
        let method = valid().decode(RecordKind::Method, "record").unwrap();
        assert_eq!(anchor, method);
        assert_eq!(anchor.unwrap().sequence, 7);
    }

    #[test]
    fn every_orphaned_field_is_rejected_for_both_record_kinds() {
        for kind in [RecordKind::Anchor, RecordKind::Method] {
            for column in 0..7 {
                let mut raw = StoredProvenance {
                    domain: None,
                    sequence: None,
                    version: None,
                    created: None,
                    expires: None,
                    signer: None,
                    digest: None,
                    imported: None,
                };
                match column {
                    0 => raw.sequence = Some(7),
                    1 => raw.version = Some("v7".into()),
                    2 => raw.created = Some("date".into()),
                    3 => raw.expires = Some("date".into()),
                    4 => raw.signer = Some("key".into()),
                    5 => raw.digest = Some("digest".into()),
                    _ => raw.imported = Some("date".into()),
                }
                let error = raw.decode(kind, "record").unwrap_err().to_string();
                assert!(error.contains(&format!(
                    "{} record has partial package provenance",
                    kind.label()
                )));
            }
            let mut raw = valid();
            raw.sequence = Some(-1);
            assert!(raw
                .decode(kind, "record")
                .unwrap_err()
                .to_string()
                .contains("invalid package sequence"));
        }
    }

    #[test]
    fn decoding_preserves_domain_error_precedence() {
        let mut anchor = valid();
        anchor.version = None;
        anchor.created = None;
        assert!(anchor
            .decode(RecordKind::Anchor, "record")
            .unwrap_err()
            .to_string()
            .contains("package version"));
        let mut method = valid();
        method.version = None;
        method.created = None;
        assert!(method
            .decode(RecordKind::Method, "record")
            .unwrap_err()
            .to_string()
            .contains("package creation time"));
    }

    #[test]
    fn legacy_and_missing_package_state_remain_distinct() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::schema::SCHEMA).unwrap();
        let provenance = valid()
            .decode(RecordKind::Anchor, "record")
            .unwrap()
            .unwrap();
        for kind in [RecordKind::Anchor, RecordKind::Method] {
            check_package_states(&conn, [("legacy", None)], kind).unwrap();
            let error =
                check_package_states(&conn, [("record", Some(&provenance))], kind).unwrap_err();
            assert!(error
                .to_string()
                .contains("references missing package state"));
        }
    }
}
