//! Secure database operations

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::error::StorageError;
use crate::keychain::KeychainManager;
use crate::models::*;
use crate::schema::{SCHEMA, SCHEMA_VERSION};

const MAX_PACKAGE_FUTURE_SKEW_SECONDS: i64 = 300;

/// Offline queue status
#[derive(Debug, Serialize)]
pub struct OfflineQueueStatus {
    pub pending_events: usize,
    pub oldest_event: Option<String>,
    pub data_size_bytes: usize,
    pub last_sync_attempt: Option<String>,
    pub last_successful_sync: Option<String>,
}

/// Verification history entry for API
#[derive(Debug, Serialize)]
pub struct VerificationHistoryEntry {
    pub id: String,
    pub credential_type: String,
    pub status: String,
    pub verified_at: String,
    pub jurisdiction: Option<String>,
    pub synced: bool,
}

/// Secure storage manager
pub struct SecureStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SecureStorage {
    /// Create new secure storage at the given path
    pub fn new(data_dir: &Path) -> Result<Self, StorageError> {
        // Ensure data directory exists
        std::fs::create_dir_all(data_dir)?;

        let db_path = data_dir.join("marty_verifier.db");

        // Get or create encryption key from keychain
        let keychain = KeychainManager::new();
        let db_key = keychain.get_or_create_db_key()?;

        // Open encrypted database
        let conn = Connection::open(&db_path)?;

        // Set encryption key (SQLCipher) - use raw key format
        let key_hex = hex::encode(&db_key);
        conn.pragma_update(None, "key", format!("x'{}'", key_hex))?;

        // Set secure pragmas - must come AFTER key
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            "#,
        )?;

        // Initialize schema
        conn.execute_batch(SCHEMA)?;

        let current_version = get_schema_version(&conn)?;
        migrate_schema(&conn, current_version)?;

        // Store schema version
        let stored_version = current_version.max(SCHEMA_VERSION);
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('schema_version', ?)",
            [stored_version.to_string()],
        )?;

        tracing::info!(?db_path, "Secure storage initialized");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Store a verification event
    pub async fn store_verification_event<S: Serialize>(
        &self,
        id: &str,
        credential_type: &str,
        status: &S,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let status_str = serde_json::to_string(status)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO verification_events 
                (id, credential_type, status, verified_at, offline_verified)
            VALUES (?, ?, ?, ?, ?)
            "#,
            rusqlite::params![id, credential_type, status_str, now, false],
        )?;

        Ok(())
    }

    /// Get verification history
    pub async fn get_verification_history(
        &self,
        limit: usize,
    ) -> Result<Vec<VerificationHistoryEntry>, StorageError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, credential_type, status, verified_at, issuer_jurisdiction, synced
            FROM verification_events
            ORDER BY verified_at DESC
            LIMIT ?
            "#,
        )?;

        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map([sql_limit], |row| {
            Ok(VerificationHistoryEntry {
                id: row.get(0)?,
                credential_type: row.get(1)?,
                status: row.get(2)?,
                verified_at: row.get(3)?,
                jurisdiction: row.get(4)?,
                synced: row.get(5)?,
            })
        })?;

        let mut history = Vec::new();
        for row in rows {
            history.push(row?);
        }

        Ok(history)
    }

    /// Clear verification history older than N days
    pub async fn clear_verification_history(
        &self,
        older_than_days: u32,
    ) -> Result<usize, StorageError> {
        let conn = self.conn.lock().await;

        let deleted = if older_than_days == 0 {
            conn.execute("DELETE FROM verification_events", [])?
        } else {
            conn.execute(
                r#"
                DELETE FROM verification_events 
                WHERE verified_at < datetime('now', ? || ' days')
                "#,
                [format!("-{}", older_than_days)],
            )?
        };

        Ok(deleted)
    }

    /// Get offline queue status
    pub async fn get_queue_status(&self) -> Result<OfflineQueueStatus, StorageError> {
        let conn = self.conn.lock().await;

        let pending_events: usize =
            conn.query_row("SELECT COUNT(*) FROM offline_queue", [], |row| {
                let value = row.get::<_, i64>(0)?;
                usize::try_from(value)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
            })?;

        let oldest_event: Option<String> = conn
            .query_row("SELECT MIN(created_at) FROM offline_queue", [], |row| {
                row.get(0)
            })
            .ok();

        // Estimate data size
        let data_size_bytes: usize = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM offline_queue",
            [],
            |row| {
                let value = row.get::<_, i64>(0)?;
                usize::try_from(value)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
            },
        )?;

        // Get last sync times from sync_state
        let (last_sync_attempt, last_successful_sync): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT last_error, last_iaca_sync FROM sync_state WHERE id = 'current'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or((None, None));

        Ok(OfflineQueueStatus {
            pending_events,
            oldest_event,
            data_size_bytes,
            last_sync_attempt,
            last_successful_sync,
        })
    }

    /// Store a trust anchor certificate
    pub async fn store_trust_anchor(&self, anchor: &TrustAnchor) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let governed = conn
            .query_row(
                "SELECT trust_domain FROM trust_anchors WHERE id = ?",
                [&anchor.id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .is_some();
        if governed {
            return Err(StorageError::TrustPackageConflict(format!(
                "legacy write cannot replace governed trust anchor {}",
                anchor.id
            )));
        }

        let changed = conn.execute(
            r#"
            INSERT INTO trust_anchors
                (id, anchor_type, jurisdiction, subject, issuer, serial_number,
                 not_before, not_after, certificate_der, certificate_hash, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                anchor_type = excluded.anchor_type,
                jurisdiction = excluded.jurisdiction,
                subject = excluded.subject,
                issuer = excluded.issuer,
                serial_number = excluded.serial_number,
                not_before = excluded.not_before,
                not_after = excluded.not_after,
                certificate_der = excluded.certificate_der,
                certificate_hash = excluded.certificate_hash,
                source = excluded.source,
                synced_at = excluded.synced_at
            WHERE trust_anchors.trust_domain IS NULL
            "#,
            rusqlite::params![
                anchor.id,
                anchor.anchor_type.to_string(),
                anchor.jurisdiction,
                anchor.subject,
                anchor.issuer,
                anchor.serial_number,
                anchor.not_before.map(|dt| dt.to_rfc3339()),
                anchor.not_after.map(|dt| dt.to_rfc3339()),
                anchor.certificate_der,
                anchor.certificate_hash,
                anchor.source.to_string(),
                anchor.synced_at.to_rfc3339(),
            ],
        )?;

        if changed == 0 {
            return Err(StorageError::TrustPackageConflict(format!(
                "legacy write cannot replace governed trust anchor {}",
                anchor.id
            )));
        }

        Ok(())
    }

    /// Store a trusted Open Badge verification method
    pub async fn store_open_badge_key(
        &self,
        method: &OpenBadgeVerificationMethod,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let document_json = serde_json::to_string(&method.document)?;
        let governed = conn
            .query_row(
                "SELECT trust_domain FROM open_badge_keys WHERE id = ?",
                [&method.id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .is_some();
        if governed {
            return Err(StorageError::TrustPackageConflict(format!(
                "legacy write cannot replace governed method {}",
                method.id
            )));
        }

        let changed = conn.execute(
            r#"
            INSERT INTO open_badge_keys
                (id, document_json, controller, issuer, kid, not_before, not_after, status, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                document_json = excluded.document_json,
                controller = excluded.controller,
                issuer = excluded.issuer,
                kid = excluded.kid,
                not_before = excluded.not_before,
                not_after = excluded.not_after,
                status = excluded.status,
                source = excluded.source,
                synced_at = excluded.synced_at
            WHERE open_badge_keys.trust_domain IS NULL
            "#,
            rusqlite::params![
                method.id,
                document_json,
                method.controller,
                method.issuer,
                method.kid,
                method.not_before.map(|dt| dt.to_rfc3339()),
                method.not_after.map(|dt| dt.to_rfc3339()),
                method.status,
                method.source.to_string(),
                method.synced_at.to_rfc3339(),
            ],
        )?;

        if changed == 0 {
            return Err(StorageError::TrustPackageConflict(format!(
                "legacy write cannot replace governed method {}",
                method.id
            )));
        }

        Ok(())
    }

    /// Atomically replace one trust domain's complete anchor and Open Badge
    /// trust set with a newer authenticated package.
    ///
    /// Comparison, same-domain replacement, package-state advancement, sync
    /// metadata, and the minimized audit outcome happen in one immediate
    /// SQLite transaction. Any validation or storage failure leaves every
    /// previously active record and metadata row untouched.
    pub async fn apply_trust_package(
        &self,
        provenance: &TrustPackageProvenance,
        anchors: &[TrustAnchor],
        methods: &[OpenBadgeVerificationMethod],
    ) -> Result<TrustPackageApplyResult, StorageError> {
        let sequence = validate_trust_package(provenance, anchors, methods)?;
        let documents = methods
            .iter()
            .map(|method| serde_json::to_string(&method.document))
            .collect::<Result<Vec<_>, _>>()?;
        let audit_details = serde_json::to_string(&serde_json::json!({
            "trust_domain": provenance.trust_domain,
            "sequence": provenance.sequence,
            "package_version": provenance.package_version,
            "package_expires_at": provenance.expires_at.to_rfc3339(),
            "signer_key_id": provenance.signer_key_id,
            "package_digest": provenance.package_digest,
            "trust_anchor_count": anchors.len(),
            "open_badge_method_count": methods.len(),
            "outcome": "applied"
        }))?;

        let mut conn = self.conn.lock().await;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current = tx
            .query_row(
                r#"
                SELECT sequence, package_version, package_created_at,
                       package_expires_at, signer_key_id, package_digest, imported_at
                FROM trust_packages
                WHERE trust_domain = ?
                "#,
                [&provenance.trust_domain],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;

        if let Some((
            current_sequence,
            current_version,
            current_created_at,
            current_expires_at,
            current_signer,
            current_digest,
            _current_imported_at,
        )) = current
        {
            let current_sequence = u64::try_from(current_sequence).map_err(|_| {
                StorageError::InvalidTrustPackage(
                    "stored package sequence is negative or out of range".to_string(),
                )
            })?;

            if provenance.sequence < current_sequence {
                return Err(StorageError::TrustPackageRollback {
                    domain: provenance.trust_domain.clone(),
                    current_sequence,
                    attempted_sequence: provenance.sequence,
                });
            }
            if provenance.sequence == current_sequence {
                if provenance.package_digest == current_digest {
                    return Err(StorageError::TrustPackageReplay {
                        domain: provenance.trust_domain.clone(),
                        sequence: provenance.sequence,
                    });
                }
                return Err(StorageError::TrustPackageConflict(format!(
                    "domain {} sequence {} has a different digest",
                    provenance.trust_domain, provenance.sequence
                )));
            }
            if provenance.signer_key_id != current_signer {
                return Err(StorageError::TrustPackageSignerChange(
                    provenance.trust_domain.clone(),
                ));
            }
            if provenance.package_version == current_version {
                return Err(StorageError::TrustPackageConflict(format!(
                    "domain {} version {} has a different sequence or digest",
                    provenance.trust_domain, provenance.package_version
                )));
            }
            if provenance.package_digest == current_digest {
                return Err(StorageError::TrustPackageConflict(format!(
                    "domain {} reused digest {} at a newer sequence",
                    provenance.trust_domain, provenance.package_digest
                )));
            }

            let current_created_at = chrono::DateTime::parse_from_rfc3339(&current_created_at)
                .map_err(|_| {
                    StorageError::InvalidTrustPackage(
                        "stored package creation time is malformed".to_string(),
                    )
                })?
                .with_timezone(&Utc);
            let current_expires_at = current_expires_at.ok_or_else(|| {
                StorageError::InvalidTrustPackage(
                    "stored package expiry time is missing".to_string(),
                )
            })?;
            chrono::DateTime::parse_from_rfc3339(&current_expires_at).map_err(|_| {
                StorageError::InvalidTrustPackage(
                    "stored package expiry time is malformed".to_string(),
                )
            })?;
            if provenance.created_at <= current_created_at {
                return Err(StorageError::TrustPackageConflict(format!(
                    "domain {} package creation time did not advance",
                    provenance.trust_domain
                )));
            }
        }

        tx.execute(
            "DELETE FROM trust_anchors WHERE trust_domain = ?",
            [&provenance.trust_domain],
        )?;
        tx.execute(
            "DELETE FROM open_badge_keys WHERE trust_domain = ?",
            [&provenance.trust_domain],
        )?;

        for anchor in anchors {
            let conflicting_domain = tx
                .query_row(
                    "SELECT trust_domain FROM trust_anchors WHERE id = ?",
                    [&anchor.id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?;
            if conflicting_domain.is_some() {
                return Err(StorageError::TrustPackageConflict(format!(
                    "trust anchor {} is already owned by another or legacy trust source",
                    anchor.id
                )));
            }
        }

        for method in methods {
            let conflicting_domain = tx
                .query_row(
                    "SELECT trust_domain FROM open_badge_keys WHERE id = ?",
                    [&method.id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?;
            if conflicting_domain.is_some() {
                return Err(StorageError::TrustPackageConflict(format!(
                    "method {} is already owned by another or legacy trust source",
                    method.id
                )));
            }
        }

        for anchor in anchors {
            tx.execute(
                r#"
                INSERT INTO trust_anchors
                    (id, anchor_type, jurisdiction, subject, issuer,
                     serial_number, not_before, not_after, certificate_der,
                     certificate_hash, source, synced_at, trust_domain,
                     package_sequence, package_version, package_created_at,
                     package_expires_at, package_signer_key_id, package_digest,
                     package_imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                rusqlite::params![
                    anchor.id,
                    anchor.anchor_type.to_string(),
                    anchor.jurisdiction,
                    anchor.subject,
                    anchor.issuer,
                    anchor.serial_number,
                    anchor.not_before.map(|dt| dt.to_rfc3339()),
                    anchor.not_after.map(|dt| dt.to_rfc3339()),
                    anchor.certificate_der,
                    anchor.certificate_hash,
                    anchor.source.to_string(),
                    provenance.created_at.to_rfc3339(),
                    provenance.trust_domain,
                    sequence,
                    provenance.package_version,
                    provenance.created_at.to_rfc3339(),
                    provenance.expires_at.to_rfc3339(),
                    provenance.signer_key_id,
                    provenance.package_digest,
                    provenance.imported_at.to_rfc3339(),
                ],
            )?;
        }

        for (method, document_json) in methods.iter().zip(documents) {
            tx.execute(
                r#"
                INSERT INTO open_badge_keys
                    (id, document_json, controller, issuer, kid, not_before,
                     not_after, status, source, synced_at, trust_domain,
                     package_sequence, package_version, package_created_at,
                     package_expires_at, package_signer_key_id, package_digest,
                     package_imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                rusqlite::params![
                    method.id,
                    document_json,
                    method.controller,
                    method.issuer,
                    method.kid,
                    method.not_before.map(|dt| dt.to_rfc3339()),
                    method.not_after.map(|dt| dt.to_rfc3339()),
                    method.status,
                    method.source.to_string(),
                    provenance.created_at.to_rfc3339(),
                    provenance.trust_domain,
                    sequence,
                    provenance.package_version,
                    provenance.created_at.to_rfc3339(),
                    provenance.expires_at.to_rfc3339(),
                    provenance.signer_key_id,
                    provenance.package_digest,
                    provenance.imported_at.to_rfc3339(),
                ],
            )?;
        }

        tx.execute(
            r#"
            INSERT INTO trust_packages
                (trust_domain, sequence, package_version, package_created_at,
                 package_expires_at, signer_key_id, package_digest, imported_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(trust_domain) DO UPDATE SET
                sequence = excluded.sequence,
                package_version = excluded.package_version,
                package_created_at = excluded.package_created_at,
                package_expires_at = excluded.package_expires_at,
                signer_key_id = excluded.signer_key_id,
                package_digest = excluded.package_digest,
                imported_at = excluded.imported_at,
                updated_at = excluded.updated_at
            "#,
            rusqlite::params![
                provenance.trust_domain,
                sequence,
                provenance.package_version,
                provenance.created_at.to_rfc3339(),
                provenance.expires_at.to_rfc3339(),
                provenance.signer_key_id,
                provenance.package_digest,
                provenance.imported_at.to_rfc3339(),
                provenance.imported_at.to_rfc3339(),
            ],
        )?;

        tx.execute(
            r#"
            INSERT INTO sync_state
                (id, last_iaca_sync, last_csca_sync, iaca_version,
                 csca_version, sync_in_progress, last_error, updated_at)
            VALUES ('current', ?, ?, ?, ?, 0, NULL, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_iaca_sync = excluded.last_iaca_sync,
                last_csca_sync = excluded.last_csca_sync,
                iaca_version = excluded.iaca_version,
                csca_version = excluded.csca_version,
                sync_in_progress = 0,
                last_error = NULL,
                updated_at = excluded.updated_at
            "#,
            rusqlite::params![
                provenance.created_at.to_rfc3339(),
                provenance.created_at.to_rfc3339(),
                provenance.package_version,
                provenance.package_version,
                provenance.imported_at.to_rfc3339(),
            ],
        )?;

        tx.execute(
            r#"
            INSERT INTO audit_log
                (id, event_type, actor, target, details, ip_address, created_at)
            VALUES (?, 'trust_package_applied', NULL, ?, ?, NULL, ?)
            "#,
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                provenance.trust_domain,
                audit_details,
                provenance.imported_at.to_rfc3339(),
            ],
        )?;

        tx.commit()?;
        Ok(TrustPackageApplyResult {
            trust_anchors: anchors.len(),
            open_badge_methods: methods.len(),
        })
    }

    /// Get trust anchors by type and jurisdiction
    pub async fn get_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
        jurisdiction: Option<&str>,
    ) -> Result<Vec<TrustAnchor>, StorageError> {
        Ok(self
            .get_trust_anchor_records(anchor_type, jurisdiction)
            .await?
            .into_iter()
            .map(|record| record.anchor)
            .collect())
    }

    /// Get trust anchors together with authenticated package provenance.
    /// Partial, malformed, stale, or package-state-conflicting provenance
    /// fails closed instead of being treated as a legacy anchor.
    pub async fn get_trust_anchor_records(
        &self,
        anchor_type: TrustAnchorType,
        jurisdiction: Option<&str>,
    ) -> Result<Vec<TrustAnchorRecord>, StorageError> {
        let conn = self.conn.lock().await;

        let sql = if jurisdiction.is_some() {
            r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at,
                   trust_domain, package_sequence, package_version,
                   package_created_at, package_expires_at,
                   package_signer_key_id, package_digest, package_imported_at
            FROM trust_anchors
            WHERE anchor_type = ? AND jurisdiction = ?
            "#
        } else {
            r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at,
                   trust_domain, package_sequence, package_version,
                   package_created_at, package_expires_at,
                   package_signer_key_id, package_digest, package_imported_at
            FROM trust_anchors
            WHERE anchor_type = ?
            "#
        };

        let mut stmt = conn.prepare(sql)?;
        let mut rows = if let Some(jurisdiction) = jurisdiction {
            stmt.query(rusqlite::params![anchor_type.to_string(), jurisdiction])?
        } else {
            stmt.query(rusqlite::params![anchor_type.to_string()])?
        };

        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(map_trust_anchor_record(row)?);
        }
        drop(rows);
        drop(stmt);

        let mut package_states = HashMap::new();
        for record in &records {
            let Some(provenance) = &record.provenance else {
                continue;
            };
            let stored = if let Some(stored) = package_states.get(&provenance.trust_domain) {
                stored
            } else {
                let stored = load_open_badge_package_provenance(&conn, &provenance.trust_domain)?
                    .ok_or_else(|| {
                    StorageError::InvalidTrustPackage(format!(
                        "trust anchor {} references missing package state for domain {}",
                        record.anchor.id, provenance.trust_domain
                    ))
                })?;
                package_states.insert(provenance.trust_domain.clone(), stored);
                package_states
                    .get(&provenance.trust_domain)
                    .ok_or_else(|| {
                        StorageError::InvalidTrustPackage(format!(
                            "trust anchor {} could not load package state for domain {}",
                            record.anchor.id, provenance.trust_domain
                        ))
                    })?
            };
            if stored != provenance {
                return Err(StorageError::InvalidTrustPackage(format!(
                    "trust anchor {} provenance conflicts with package state for domain {}",
                    record.anchor.id, provenance.trust_domain
                )));
            }
        }
        Ok(records)
    }

    /// Get all trusted Open Badge verification methods
    pub async fn get_open_badge_keys(
        &self,
    ) -> Result<Vec<OpenBadgeVerificationMethod>, StorageError> {
        Ok(self
            .get_open_badge_trust_records()
            .await?
            .into_iter()
            .map(|record| record.method)
            .collect())
    }

    /// Get Open Badge methods together with authenticated package provenance.
    ///
    /// Legacy/manual rows are returned with `provenance: None`. Partially
    /// populated or malformed provenance fails closed instead of being
    /// silently downgraded to a legacy record.
    pub async fn get_open_badge_trust_records(
        &self,
    ) -> Result<Vec<OpenBadgeTrustRecord>, StorageError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_json, controller, issuer, kid, not_before,
                   not_after, status, source, synced_at, trust_domain,
                   package_sequence, package_version, package_created_at,
                   package_expires_at, package_signer_key_id, package_digest,
                   package_imported_at
            FROM open_badge_keys
            "#,
        )?;
        let mut rows = stmt.query([])?;
        let mut records = Vec::new();

        while let Some(row) = rows.next()? {
            let method = map_open_badge_key_strict(row)?;
            let trust_domain = row.get::<_, Option<String>>(10)?;
            let sequence = row.get::<_, Option<i64>>(11)?;
            let package_version = row.get::<_, Option<String>>(12)?;
            let package_created_at = row.get::<_, Option<String>>(13)?;
            let package_expires_at = row.get::<_, Option<String>>(14)?;
            let signer_key_id = row.get::<_, Option<String>>(15)?;
            let package_digest = row.get::<_, Option<String>>(16)?;
            let package_imported_at = row.get::<_, Option<String>>(17)?;

            let provenance = match trust_domain {
                None => {
                    if sequence.is_some()
                        || package_version.is_some()
                        || package_created_at.is_some()
                        || package_expires_at.is_some()
                        || signer_key_id.is_some()
                        || package_digest.is_some()
                        || package_imported_at.is_some()
                    {
                        return Err(StorageError::InvalidTrustPackage(format!(
                            "method {} has partial package provenance",
                            method.id
                        )));
                    }
                    None
                }
                Some(trust_domain) => {
                    if !method.document.is_object() {
                        return Err(StorageError::InvalidTrustPackage(format!(
                            "governed method {} has malformed document JSON",
                            method.id
                        )));
                    }
                    let sequence = sequence.ok_or_else(|| {
                        StorageError::InvalidTrustPackage(format!(
                            "method {} is missing package sequence",
                            method.id
                        ))
                    })?;
                    let sequence = u64::try_from(sequence).map_err(|_| {
                        StorageError::InvalidTrustPackage(format!(
                            "method {} has invalid package sequence",
                            method.id
                        ))
                    })?;
                    let created_at = parse_stored_timestamp(
                        package_created_at.as_deref(),
                        &method.id,
                        "package creation time",
                    )?;
                    let imported_at = parse_stored_timestamp(
                        package_imported_at.as_deref(),
                        &method.id,
                        "package import time",
                    )?;

                    let provenance = OpenBadgeTrustPackageProvenance {
                        trust_domain,
                        sequence,
                        package_version: required_stored_value(
                            package_version,
                            &method.id,
                            "package version",
                        )?,
                        created_at,
                        expires_at: parse_stored_timestamp(
                            package_expires_at.as_deref(),
                            &method.id,
                            "package expiry time",
                        )?,
                        signer_key_id: required_stored_value(
                            signer_key_id,
                            &method.id,
                            "package signer key id",
                        )?,
                        package_digest: required_stored_value(
                            package_digest,
                            &method.id,
                            "package digest",
                        )?,
                        imported_at,
                    };
                    if method.synced_at != provenance.created_at {
                        return Err(StorageError::InvalidTrustPackage(format!(
                            "governed method {} freshness does not match signed package time",
                            method.id
                        )));
                    }
                    validate_open_badge_package(&provenance, std::slice::from_ref(&method))?;
                    Some(provenance)
                }
            };

            records.push(OpenBadgeTrustRecord { method, provenance });
        }

        drop(rows);
        drop(stmt);

        let mut package_states = HashMap::new();
        for record in &records {
            let Some(provenance) = &record.provenance else {
                continue;
            };
            let stored = if let Some(stored) = package_states.get(&provenance.trust_domain) {
                stored
            } else {
                let stored = load_open_badge_package_provenance(&conn, &provenance.trust_domain)?
                    .ok_or_else(|| {
                    StorageError::InvalidTrustPackage(format!(
                        "method {} references missing package state for domain {}",
                        record.method.id, provenance.trust_domain
                    ))
                })?;
                package_states.insert(provenance.trust_domain.clone(), stored);
                package_states
                    .get(&provenance.trust_domain)
                    .ok_or_else(|| {
                        StorageError::InvalidTrustPackage(format!(
                            "method {} could not load package state for domain {}",
                            record.method.id, provenance.trust_domain
                        ))
                    })?
            };
            if stored != provenance {
                return Err(StorageError::InvalidTrustPackage(format!(
                    "method {} provenance conflicts with package state for domain {}",
                    record.method.id, provenance.trust_domain
                )));
            }
        }

        Ok(records)
    }

    /// Count trusted Open Badge verification methods
    pub async fn count_open_badge_keys(&self) -> Result<usize, StorageError> {
        Ok(self.get_open_badge_trust_records().await?.len())
    }

    /// Get latest Open Badge trust list sync timestamp
    pub async fn get_latest_open_badge_sync(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, StorageError> {
        Ok(self
            .get_open_badge_trust_records()
            .await?
            .into_iter()
            .map(|record| record.method.synced_at)
            .max())
    }

    /// Count trust anchors by type
    pub async fn count_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
    ) -> Result<usize, StorageError> {
        Ok(self
            .get_trust_anchor_records(anchor_type, None)
            .await?
            .len())
    }

    /// Get license state
    pub async fn get_license_state(&self) -> Result<Option<LicenseState>, StorageError> {
        let conn = self.conn.lock().await;

        let result = conn.query_row(
            r#"
            SELECT license_jwt, validated_at, hardware_fingerprint, 
                   verifications_today, verifications_date, verifications_total, grace_period_started
            FROM license_state WHERE id = 'current'
            "#,
            [],
            |row| {
                Ok(LicenseState {
                    license_jwt: row.get(0)?,
                    validated_at: row.get::<_, Option<String>>(1)?.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    hardware_fingerprint: row.get(2)?,
                    verifications_today: row.get(3)?,
                    verifications_date: row.get(4)?,
                    verifications_total: row.get(5)?,
                    grace_period_started: row.get::<_, Option<String>>(6)?.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                })
            },
        );

        match result {
            Ok(state) => Ok(Some(state)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update license state
    pub async fn update_license_state(&self, state: &LicenseState) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO license_state 
                (id, license_jwt, validated_at, hardware_fingerprint, 
                 verifications_today, verifications_date, verifications_total, grace_period_started, updated_at)
            VALUES ('current', ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                state.license_jwt,
                state.validated_at.map(|dt| dt.to_rfc3339()),
                state.hardware_fingerprint,
                state.verifications_today,
                state.verifications_date,
                state.verifications_total,
                state.grace_period_started.map(|dt| dt.to_rfc3339()),
                now,
            ],
        )?;

        Ok(())
    }

    /// Get sync state
    pub async fn get_sync_state(&self) -> Result<Option<SyncState>, StorageError> {
        let conn = self.conn.lock().await;

        let result = conn.query_row(
            r#"
            SELECT last_iaca_sync, last_csca_sync, last_crl_sync,
                   iaca_version, csca_version, sync_in_progress, last_error
            FROM sync_state WHERE id = 'current'
            "#,
            [],
            |row| {
                Ok(SyncState {
                    last_iaca_sync: row.get::<_, Option<String>>(0)?.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    last_csca_sync: row.get::<_, Option<String>>(1)?.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    last_crl_sync: row.get::<_, Option<String>>(2)?.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    iaca_version: row.get(3)?,
                    csca_version: row.get(4)?,
                    sync_in_progress: row.get::<_, i32>(5)? != 0,
                    last_error: row.get(6)?,
                })
            },
        );

        match result {
            Ok(state) => Ok(Some(state)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update sync state
    pub async fn update_sync_state(&self, state: &SyncState) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO sync_state 
                (id, last_iaca_sync, last_csca_sync, last_crl_sync,
                 iaca_version, csca_version, sync_in_progress, last_error, updated_at)
            VALUES ('current', ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                state.last_iaca_sync.map(|dt| dt.to_rfc3339()),
                state.last_csca_sync.map(|dt| dt.to_rfc3339()),
                state.last_crl_sync.map(|dt| dt.to_rfc3339()),
                state.iaca_version,
                state.csca_version,
                state.sync_in_progress as i32,
                state.last_error,
                now,
            ],
        )?;

        Ok(())
    }

    /// Queue an event for offline reporting
    pub async fn queue_event(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<String, StorageError> {
        let conn = self.conn.lock().await;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let payload_str = serde_json::to_string(payload)?;

        conn.execute(
            r#"
            INSERT INTO offline_queue (id, event_type, payload, created_at)
            VALUES (?, ?, ?, ?)
            "#,
            rusqlite::params![id, event_type, payload_str, now],
        )?;

        Ok(id)
    }

    /// Get pending events from offline queue
    pub async fn get_pending_events(
        &self,
        limit: usize,
    ) -> Result<Vec<OfflineQueueEntry>, StorageError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, event_type, payload, created_at, retry_count, last_retry_at, error
            FROM offline_queue
            ORDER BY created_at ASC
            LIMIT ?
            "#,
        )?;

        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map([sql_limit], |row| {
            let payload_str: String = row.get(2)?;
            Ok(OfflineQueueEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                payload: serde_json::from_str(&payload_str).unwrap_or(serde_json::Value::Null),
                created_at: row
                    .get::<_, String>(3)
                    .ok()
                    .and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    })
                    .unwrap_or_else(Utc::now),
                retry_count: row.get(4)?,
                last_retry_at: row.get::<_, Option<String>>(5)?.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }),
                error: row.get(6)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }

        Ok(entries)
    }

    /// Remove event from offline queue (after successful sync)
    pub async fn remove_queued_event(&self, id: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM offline_queue WHERE id = ?", [id])?;
        Ok(())
    }

    /// Add audit log entry
    pub async fn add_audit_log(
        &self,
        event_type: &str,
        actor: Option<&str>,
        target: Option<&str>,
        details: Option<&serde_json::Value>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let id = uuid::Uuid::new_v4().to_string();
        let details_str = details.map(serde_json::to_string).transpose()?;

        conn.execute(
            r#"
            INSERT INTO audit_log (id, event_type, actor, target, details)
            VALUES (?, ?, ?, ?, ?)
            "#,
            rusqlite::params![id, event_type, actor, target, details_str],
        )?;

        Ok(())
    }
}

fn map_trust_anchor_record(row: &rusqlite::Row<'_>) -> Result<TrustAnchorRecord, StorageError> {
    let id: String = row.get(0)?;
    let anchor_type = match row.get::<_, String>(1)?.as_str() {
        "iaca" => TrustAnchorType::Iaca,
        "csca" => TrustAnchorType::Csca,
        "dsc" => TrustAnchorType::Dsc,
        other => {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {id} has unknown type {other}"
            )));
        }
    };
    let source = match row.get::<_, String>(10)?.as_str() {
        "aamva_dts" => TrustAnchorSource::AamvaDts,
        "icao_pkd" => TrustAnchorSource::IcaoPkd,
        "usb_import" => TrustAnchorSource::UsbImport,
        "manual" => TrustAnchorSource::Manual,
        other => {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {id} has unknown source {other}"
            )));
        }
    };
    let anchor = TrustAnchor {
        id: id.clone(),
        anchor_type,
        jurisdiction: row.get(2)?,
        subject: row.get(3)?,
        issuer: row.get(4)?,
        serial_number: row.get(5)?,
        not_before: parse_optional_stored_timestamp(
            row.get::<_, Option<String>>(6)?.as_deref(),
            &id,
            "not_before",
        )?,
        not_after: parse_optional_stored_timestamp(
            row.get::<_, Option<String>>(7)?.as_deref(),
            &id,
            "not_after",
        )?,
        certificate_der: row.get(8)?,
        certificate_hash: row.get(9)?,
        source,
        synced_at: parse_stored_timestamp(
            row.get::<_, Option<String>>(11)?.as_deref(),
            &id,
            "synced_at",
        )?,
    };

    let trust_domain = row.get::<_, Option<String>>(12)?;
    let sequence = row.get::<_, Option<i64>>(13)?;
    let package_version = row.get::<_, Option<String>>(14)?;
    let package_created_at = row.get::<_, Option<String>>(15)?;
    let package_expires_at = row.get::<_, Option<String>>(16)?;
    let signer_key_id = row.get::<_, Option<String>>(17)?;
    let package_digest = row.get::<_, Option<String>>(18)?;
    let package_imported_at = row.get::<_, Option<String>>(19)?;
    let provenance = match trust_domain {
        None => {
            if sequence.is_some()
                || package_version.is_some()
                || package_created_at.is_some()
                || package_expires_at.is_some()
                || signer_key_id.is_some()
                || package_digest.is_some()
                || package_imported_at.is_some()
            {
                return Err(StorageError::InvalidTrustPackage(format!(
                    "trust anchor {id} has partial package provenance"
                )));
            }
            None
        }
        Some(trust_domain) => {
            let sequence = sequence.ok_or_else(|| {
                StorageError::InvalidTrustPackage(format!(
                    "trust anchor {id} is missing package sequence"
                ))
            })?;
            let sequence = u64::try_from(sequence).map_err(|_| {
                StorageError::InvalidTrustPackage(format!(
                    "trust anchor {id} has invalid package sequence"
                ))
            })?;
            let provenance = TrustPackageProvenance {
                trust_domain,
                sequence,
                package_version: required_stored_value(package_version, &id, "package version")?,
                created_at: parse_stored_timestamp(
                    package_created_at.as_deref(),
                    &id,
                    "package creation time",
                )?,
                expires_at: parse_stored_timestamp(
                    package_expires_at.as_deref(),
                    &id,
                    "package expiry time",
                )?,
                signer_key_id: required_stored_value(signer_key_id, &id, "package signer key id")?,
                package_digest: required_stored_value(package_digest, &id, "package digest")?,
                imported_at: parse_stored_timestamp(
                    package_imported_at.as_deref(),
                    &id,
                    "package import time",
                )?,
            };
            validate_trust_package(&provenance, std::slice::from_ref(&anchor), &[])?;
            Some(provenance)
        }
    };
    Ok(TrustAnchorRecord { anchor, provenance })
}

fn map_open_badge_key_strict(
    row: &rusqlite::Row<'_>,
) -> Result<OpenBadgeVerificationMethod, StorageError> {
    let id: String = row.get(0)?;
    let document_json: String = row.get(1)?;
    let document = serde_json::from_str(&document_json).map_err(|_| {
        StorageError::InvalidTrustPackage(format!(
            "Open Badge method {id} has malformed document JSON"
        ))
    })?;
    let source = match row.get::<_, String>(8)?.as_str() {
        "sync" => OpenBadgeKeySource::Sync,
        "usb_import" => OpenBadgeKeySource::UsbImport,
        "manual" => OpenBadgeKeySource::Manual,
        other => {
            return Err(StorageError::InvalidTrustPackage(format!(
                "Open Badge method {id} has unknown source {other}"
            )));
        }
    };
    Ok(OpenBadgeVerificationMethod {
        id: id.clone(),
        document,
        controller: row.get(2)?,
        issuer: row.get(3)?,
        kid: row.get(4)?,
        not_before: parse_optional_stored_timestamp(
            row.get::<_, Option<String>>(5)?.as_deref(),
            &id,
            "not_before",
        )?,
        not_after: parse_optional_stored_timestamp(
            row.get::<_, Option<String>>(6)?.as_deref(),
            &id,
            "not_after",
        )?,
        status: row.get(7)?,
        source,
        synced_at: parse_stored_timestamp(
            row.get::<_, Option<String>>(9)?.as_deref(),
            &id,
            "synced_at",
        )?,
    })
}

fn validate_trust_package(
    provenance: &TrustPackageProvenance,
    anchors: &[TrustAnchor],
    methods: &[OpenBadgeVerificationMethod],
) -> Result<i64, StorageError> {
    let sequence = validate_open_badge_package(provenance, methods)?;
    let mut ids = HashSet::new();
    for anchor in anchors {
        if anchor.id.is_empty() || anchor.id.len() > 512 || !ids.insert(anchor.id.as_str()) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor id {} is empty, oversized, or duplicated",
                anchor.id
            )));
        }
        if anchor.jurisdiction.is_empty()
            || anchor.jurisdiction.len() > 512
            || anchor.jurisdiction.chars().any(char::is_control)
        {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} has invalid jurisdiction metadata",
                anchor.id
            )));
        }
        if anchor.source == TrustAnchorSource::Manual {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} uses manual source in an authenticated package",
                anchor.id
            )));
        }
        if anchor.synced_at != provenance.created_at {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} freshness does not match signed package time",
                anchor.id
            )));
        }
        if anchor.certificate_der.is_empty() {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} has empty certificate DER",
                anchor.id
            )));
        }
        let digest = blake3::hash(&anchor.certificate_der).to_hex().to_string();
        if anchor.certificate_hash != digest || anchor.id != digest {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} does not match its certificate digest",
                anchor.id
            )));
        }
        if matches!(
            (anchor.not_before, anchor.not_after),
            (Some(not_before), Some(not_after)) if not_before >= not_after
        ) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "trust anchor {} has a non-positive validity interval",
                anchor.id
            )));
        }
    }
    Ok(sequence)
}

fn validate_open_badge_package(
    provenance: &TrustPackageProvenance,
    methods: &[OpenBadgeVerificationMethod],
) -> Result<i64, StorageError> {
    if provenance.trust_domain.is_empty()
        || provenance.trust_domain.len() > 128
        || !provenance
            .trust_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        return Err(StorageError::InvalidTrustPackage(
            "trust domain must be 1-128 ASCII identifier characters".to_string(),
        ));
    }
    if provenance.sequence == 0 {
        return Err(StorageError::InvalidTrustPackage(
            "package sequence must be greater than zero".to_string(),
        ));
    }
    let sequence = i64::try_from(provenance.sequence).map_err(|_| {
        StorageError::InvalidTrustPackage("package sequence exceeds SQLite range".to_string())
    })?;
    if provenance.package_version.is_empty()
        || provenance.package_version.len() > 128
        || provenance.package_version.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidTrustPackage(
            "package version must be a bounded printable value".to_string(),
        ));
    }
    if provenance.signer_key_id.is_empty()
        || provenance.signer_key_id.len() > 512
        || provenance.signer_key_id.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidTrustPackage(
            "signer key id must be a bounded printable value".to_string(),
        ));
    }
    if provenance.package_digest.len() != 64
        || !provenance
            .package_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StorageError::InvalidTrustPackage(
            "package digest must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    let now = Utc::now();
    let allowed_skew = chrono::Duration::seconds(MAX_PACKAGE_FUTURE_SKEW_SECONDS);
    if provenance.created_at > provenance.imported_at + allowed_skew {
        return Err(StorageError::InvalidTrustPackage(
            "package creation time exceeds the allowed import clock skew".to_string(),
        ));
    }
    if provenance.created_at > now + allowed_skew {
        return Err(StorageError::InvalidTrustPackage(
            "package creation time exceeds the allowed local clock skew".to_string(),
        ));
    }
    if provenance.imported_at > now + allowed_skew {
        return Err(StorageError::InvalidTrustPackage(
            "package import time exceeds the allowed local clock skew".to_string(),
        ));
    }
    if provenance.created_at >= provenance.expires_at {
        return Err(StorageError::InvalidTrustPackage(
            "package expiry time must be after its creation time".to_string(),
        ));
    }
    if provenance.imported_at > provenance.expires_at {
        return Err(StorageError::InvalidTrustPackage(
            "package cannot be imported after its signed expiry time".to_string(),
        ));
    }
    if Utc::now() > provenance.expires_at {
        return Err(StorageError::InvalidTrustPackage(
            "package signed expiry time has passed".to_string(),
        ));
    }

    let mut ids = HashSet::new();
    for method in methods {
        if method.id.is_empty() || method.id.len() > 2048 || !ids.insert(method.id.as_str()) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method id {} is empty, oversized, or duplicated",
                method.id
            )));
        }
        if method.source == OpenBadgeKeySource::Manual {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} uses manual source in an authenticated package",
                method.id
            )));
        }
        if matches!(
            (method.not_before, method.not_after),
            (Some(not_before), Some(not_after)) if not_before >= not_after
        ) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} has a non-positive validity interval",
                method.id
            )));
        }
        let Some(document) = method.document.as_object() else {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} document must be an object",
                method.id
            )));
        };
        if document.get("id").and_then(Value::as_str) != Some(method.id.as_str()) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} document id does not match its record id",
                method.id
            )));
        }
        let Some(controller) = method.controller.as_deref() else {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} is missing controller metadata",
                method.id
            )));
        };
        if document.get("controller").and_then(Value::as_str) != Some(controller) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} document controller does not match its record controller",
                method.id
            )));
        }
        if contains_private_key_material(&method.document) {
            return Err(StorageError::InvalidTrustPackage(format!(
                "method {} contains private or symmetric key material",
                method.id
            )));
        }
    }

    Ok(sequence)
}

fn contains_private_key_material(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            if key.starts_with("privateKey") || key.starts_with("secretKey") {
                return true;
            }
            if key == "publicKeyJwk" {
                return nested.as_object().is_none_or(|jwk| {
                    matches!(jwk.get("kty").and_then(Value::as_str), Some("oct") | None)
                        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                            .iter()
                            .any(|private| jwk.contains_key(*private))
                });
            }
            contains_private_key_material(nested)
        }),
        Value::Array(items) => items.iter().any(contains_private_key_material),
        _ => false,
    }
}

fn required_stored_value(
    value: Option<String>,
    record_id: &str,
    field: &str,
) -> Result<String, StorageError> {
    value.filter(|value| !value.is_empty()).ok_or_else(|| {
        StorageError::InvalidTrustPackage(format!("record {record_id} is missing {field}"))
    })
}

fn parse_stored_timestamp(
    value: Option<&str>,
    record_id: &str,
    field: &str,
) -> Result<chrono::DateTime<Utc>, StorageError> {
    let value = value.ok_or_else(|| {
        StorageError::InvalidTrustPackage(format!("record {record_id} is missing {field}"))
    })?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            StorageError::InvalidTrustPackage(format!("record {record_id} has malformed {field}"))
        })
}

fn parse_optional_stored_timestamp(
    value: Option<&str>,
    record_id: &str,
    field: &str,
) -> Result<Option<chrono::DateTime<Utc>>, StorageError> {
    value
        .map(|value| parse_stored_timestamp(Some(value), record_id, field))
        .transpose()
}

fn load_open_badge_package_provenance(
    conn: &Connection,
    trust_domain: &str,
) -> Result<Option<OpenBadgeTrustPackageProvenance>, StorageError> {
    let stored = conn
        .query_row(
            r#"
            SELECT sequence, package_version, package_created_at,
                   package_expires_at, signer_key_id, package_digest, imported_at
            FROM trust_packages
            WHERE trust_domain = ?
            "#,
            [trust_domain],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;

    let Some((sequence, version, created_at, expires_at, signer_key_id, digest, imported_at)) =
        stored
    else {
        return Ok(None);
    };
    let sequence = u64::try_from(sequence).map_err(|_| {
        StorageError::InvalidTrustPackage(format!(
            "domain {trust_domain} has invalid stored sequence"
        ))
    })?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            StorageError::InvalidTrustPackage(format!(
                "domain {trust_domain} has malformed creation time"
            ))
        })?;
    let expires_at = expires_at.ok_or_else(|| {
        StorageError::InvalidTrustPackage(format!(
            "domain {trust_domain} is missing signed expiry time"
        ))
    })?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            StorageError::InvalidTrustPackage(format!(
                "domain {trust_domain} has malformed expiry time"
            ))
        })?;
    let imported_at = chrono::DateTime::parse_from_rfc3339(&imported_at)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            StorageError::InvalidTrustPackage(format!(
                "domain {trust_domain} has malformed import time"
            ))
        })?;

    let provenance = TrustPackageProvenance {
        trust_domain: trust_domain.to_string(),
        sequence,
        package_version: version,
        created_at,
        expires_at,
        signer_key_id,
        package_digest: digest,
        imported_at,
    };
    validate_open_badge_package(&provenance, &[])?;
    Ok(Some(provenance))
}

fn get_schema_version(conn: &Connection) -> Result<i32, StorageError> {
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(version.and_then(|v| v.parse::<i32>().ok()).unwrap_or(0))
}

fn migrate_schema(conn: &Connection, current_version: i32) -> Result<(), StorageError> {
    if current_version < 2 && !column_exists(conn, "license_state", "verifications_total")? {
        conn.execute(
            "ALTER TABLE license_state ADD COLUMN verifications_total INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    // The core and application storage adapters share this database but have
    // independent schema-version histories. Check physical columns rather
    // than trusting a numerically larger version written by the other crate.
    if !column_exists(conn, "open_badge_keys", "trust_domain")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN trust_domain TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_sequence")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_sequence INTEGER",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_version")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_version TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_created_at")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_created_at TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_expires_at")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_expires_at TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_signer_key_id")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_signer_key_id TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_digest")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_digest TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "open_badge_keys", "package_imported_at")? {
        conn.execute(
            "ALTER TABLE open_badge_keys ADD COLUMN package_imported_at TEXT",
            [],
        )?;
    }
    for (column, definition) in [
        ("trust_domain", "TEXT"),
        ("package_sequence", "INTEGER"),
        ("package_version", "TEXT"),
        ("package_created_at", "TEXT"),
        ("package_expires_at", "TEXT"),
        ("package_signer_key_id", "TEXT"),
        ("package_digest", "TEXT"),
        ("package_imported_at", "TEXT"),
    ] {
        if !column_exists(conn, "trust_anchors", column)? {
            conn.execute(
                &format!("ALTER TABLE trust_anchors ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_open_badge_keys_trust_domain
            ON open_badge_keys(trust_domain);
        CREATE INDEX IF NOT EXISTS idx_trust_anchors_trust_domain
            ON trust_anchors(trust_domain);
        CREATE TABLE IF NOT EXISTS trust_packages (
            trust_domain TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL,
            package_version TEXT NOT NULL,
            package_created_at TEXT NOT NULL,
            package_expires_at TEXT,
            signer_key_id TEXT NOT NULL,
            package_digest TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TRIGGER IF NOT EXISTS prevent_legacy_open_badge_overwrite
        BEFORE INSERT ON open_badge_keys
        WHEN NEW.trust_domain IS NULL
         AND EXISTS (
             SELECT 1 FROM open_badge_keys
             WHERE id = NEW.id AND trust_domain IS NOT NULL
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy write cannot replace governed Open Badge method');
        END;
        CREATE TRIGGER IF NOT EXISTS prevent_open_badge_provenance_removal
        BEFORE UPDATE ON open_badge_keys
        WHEN OLD.trust_domain IS NOT NULL
         AND (
             NEW.trust_domain IS NULL
             OR NEW.package_sequence IS NULL
             OR NEW.package_version IS NULL
             OR NEW.package_created_at IS NULL
             OR NEW.package_expires_at IS NULL
             OR NEW.package_signer_key_id IS NULL
             OR NEW.package_digest IS NULL
             OR NEW.package_imported_at IS NULL
         )
        BEGIN
            SELECT RAISE(ABORT, 'governed Open Badge provenance cannot be removed');
        END;
        CREATE TRIGGER IF NOT EXISTS prevent_legacy_anchor_overwrite
        BEFORE INSERT ON trust_anchors
        WHEN NEW.trust_domain IS NULL
         AND EXISTS (
             SELECT 1 FROM trust_anchors
             WHERE id = NEW.id AND trust_domain IS NOT NULL
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy write cannot replace governed trust anchor');
        END;
        CREATE TRIGGER IF NOT EXISTS prevent_anchor_provenance_removal
        BEFORE UPDATE ON trust_anchors
        WHEN OLD.trust_domain IS NOT NULL
         AND (
             NEW.trust_domain IS NULL
             OR NEW.package_sequence IS NULL
             OR NEW.package_version IS NULL
             OR NEW.package_created_at IS NULL
             OR NEW.package_expires_at IS NULL
             OR NEW.package_signer_key_id IS NULL
             OR NEW.package_digest IS NULL
             OR NEW.package_imported_at IS NULL
         )
        BEGIN
            SELECT RAISE(ABORT, 'governed trust-anchor provenance cannot be removed');
        END;
        "#,
    )?;
    if !column_exists(conn, "trust_packages", "package_expires_at")? {
        // Pre-release package state did not persist a signed expiry. Leave the
        // migrated value null so governed reads fail closed instead of
        // synthesizing security metadata that was never authenticated.
        conn.execute(
            "ALTER TABLE trust_packages ADD COLUMN package_expires_at TEXT",
            [],
        )?;
    }
    if table_exists(conn, "open_badge_trust_packages")? {
        conn.execute_batch(
            r#"
            INSERT OR IGNORE INTO trust_packages
                (trust_domain, sequence, package_version, package_created_at,
                 package_expires_at, signer_key_id, package_digest, imported_at,
                 created_at, updated_at)
            SELECT trust_domain, sequence, package_version, package_created_at,
                   NULL, signer_key_id, package_digest, imported_at, created_at, updated_at
            FROM open_badge_trust_packages;
            DROP TABLE open_badge_trust_packages;
            "#,
        )?;
    }

    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, StorageError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, StorageError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
        [table],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

#[cfg(test)]
impl SecureStorage {
    /// Create in-memory storage for tests (no keychain, no encryption).
    fn new_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        migrate_schema(&conn, SCHEMA_VERSION)?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('schema_version', ?)",
            [SCHEMA_VERSION.to_string()],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn apply_open_badge_trust_package(
        &self,
        provenance: &OpenBadgeTrustPackageProvenance,
        methods: &[OpenBadgeVerificationMethod],
    ) -> Result<usize, StorageError> {
        self.apply_trust_package(provenance, &[], methods)
            .await
            .map(|result| result.open_badge_methods)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn package_provenance(
        domain: &str,
        sequence: u64,
        version: &str,
        day: u32,
        signer: &str,
        digest_byte: char,
    ) -> OpenBadgeTrustPackageProvenance {
        let created_at = Utc
            .with_ymd_and_hms(2026, 1, day, 0, 0, 0)
            .single()
            .unwrap();
        OpenBadgeTrustPackageProvenance {
            trust_domain: domain.to_string(),
            sequence,
            package_version: version.to_string(),
            created_at,
            expires_at: created_at + chrono::Duration::days(365),
            signer_key_id: signer.to_string(),
            package_digest: digest_byte.to_string().repeat(64),
            imported_at: created_at + chrono::Duration::hours(1),
        }
    }

    fn open_badge_method(id: &str, controller: &str) -> OpenBadgeVerificationMethod {
        OpenBadgeVerificationMethod {
            id: id.to_string(),
            document: serde_json::json!({
                "id": id,
                "type": "JsonWebKey2020",
                "controller": controller,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "public-key-material"
                }
            }),
            controller: Some(controller.to_string()),
            issuer: Some(controller.to_string()),
            kid: Some(id.to_string()),
            not_before: None,
            not_after: None,
            status: Some("active".to_string()),
            source: OpenBadgeKeySource::UsbImport,
            synced_at: Utc::now(),
        }
    }

    fn trust_anchor(
        certificate_der: &[u8],
        anchor_type: TrustAnchorType,
        jurisdiction: &str,
        created_at: chrono::DateTime<Utc>,
    ) -> TrustAnchor {
        let digest = blake3::hash(certificate_der).to_hex().to_string();
        TrustAnchor {
            id: digest.clone(),
            anchor_type,
            jurisdiction: jurisdiction.to_string(),
            subject: Some(format!("CN={jurisdiction}")),
            issuer: Some("CN=Marty Test Root".to_string()),
            serial_number: Some(hex::encode(certificate_der)),
            not_before: Some(created_at - chrono::Duration::days(1)),
            not_after: Some(created_at + chrono::Duration::days(365)),
            certificate_der: certificate_der.to_vec(),
            certificate_hash: digest,
            source: TrustAnchorSource::UsbImport,
            synced_at: created_at,
        }
    }

    // ====================================================================
    // Verification events
    // ====================================================================

    #[test]
    fn test_store_and_retrieve_verification_event() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            storage
                .store_verification_event("evt-1", "mDL", &"valid")
                .await
                .unwrap();

            let history = storage.get_verification_history(10).await.unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].id, "evt-1");
            assert_eq!(history[0].credential_type, "mDL");
        });
    }

    #[test]
    fn test_verification_history_ordering() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            storage
                .store_verification_event("evt-1", "mDL", &"valid")
                .await
                .unwrap();
            storage
                .store_verification_event("evt-2", "eMRTD", &"valid")
                .await
                .unwrap();

            let history = storage.get_verification_history(10).await.unwrap();
            assert_eq!(history.len(), 2);
            // Most recent first
            assert_eq!(history[0].id, "evt-2");
        });
    }

    #[test]
    fn test_verification_history_limit() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            for i in 0..5 {
                storage
                    .store_verification_event(&format!("evt-{}", i), "mDL", &"valid")
                    .await
                    .unwrap();
            }

            let history = storage.get_verification_history(2).await.unwrap();
            assert_eq!(history.len(), 2);
        });
    }

    #[test]
    fn test_clear_all_verification_history() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            storage
                .store_verification_event("evt-1", "mDL", &"valid")
                .await
                .unwrap();

            let deleted = storage.clear_verification_history(0).await.unwrap();
            assert_eq!(deleted, 1);

            let history = storage.get_verification_history(10).await.unwrap();
            assert!(history.is_empty());
        });
    }

    // ====================================================================
    // Trust anchors
    // ====================================================================

    #[test]
    fn test_store_and_get_trust_anchor() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let anchor = TrustAnchor {
                id: "anchor-1".to_string(),
                anchor_type: TrustAnchorType::Iaca,
                jurisdiction: "US".to_string(),
                subject: Some("CN=Test IACA".to_string()),
                issuer: Some("CN=Root CA".to_string()),
                serial_number: Some("1234".to_string()),
                not_before: None,
                not_after: None,
                certificate_der: vec![0x30, 0x82, 0x01],
                certificate_hash: "abc123".to_string(),
                source: TrustAnchorSource::AamvaDts,
                synced_at: Utc::now(),
            };
            storage.store_trust_anchor(&anchor).await.unwrap();

            let anchors = storage
                .get_trust_anchors(TrustAnchorType::Iaca, Some("US"))
                .await
                .unwrap();
            assert_eq!(anchors.len(), 1);
            assert_eq!(anchors[0].id, "anchor-1");
            assert_eq!(anchors[0].jurisdiction, "US");
        });
    }

    #[test]
    fn test_trust_anchor_filter_by_type() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let iaca = TrustAnchor {
                id: "iaca-1".to_string(),
                anchor_type: TrustAnchorType::Iaca,
                jurisdiction: "US".to_string(),
                subject: None,
                issuer: None,
                serial_number: None,
                not_before: None,
                not_after: None,
                certificate_der: vec![1],
                certificate_hash: "h1".to_string(),
                source: TrustAnchorSource::AamvaDts,
                synced_at: Utc::now(),
            };
            let csca = TrustAnchor {
                id: "csca-1".to_string(),
                anchor_type: TrustAnchorType::Csca,
                jurisdiction: "DE".to_string(),
                subject: None,
                issuer: None,
                serial_number: None,
                not_before: None,
                not_after: None,
                certificate_der: vec![2],
                certificate_hash: "h2".to_string(),
                source: TrustAnchorSource::IcaoPkd,
                synced_at: Utc::now(),
            };
            storage.store_trust_anchor(&iaca).await.unwrap();
            storage.store_trust_anchor(&csca).await.unwrap();

            let iaca_results = storage
                .get_trust_anchors(TrustAnchorType::Iaca, None)
                .await
                .unwrap();
            assert_eq!(iaca_results.len(), 1);
            assert_eq!(iaca_results[0].id, "iaca-1");
        });
    }

    #[test]
    fn test_count_trust_anchors() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let anchor = TrustAnchor {
                id: "a1".to_string(),
                anchor_type: TrustAnchorType::Csca,
                jurisdiction: "FR".to_string(),
                subject: None,
                issuer: None,
                serial_number: None,
                not_before: None,
                not_after: None,
                certificate_der: vec![0],
                certificate_hash: "h".to_string(),
                source: TrustAnchorSource::Manual,
                synced_at: Utc::now(),
            };
            storage.store_trust_anchor(&anchor).await.unwrap();

            assert_eq!(
                storage
                    .count_trust_anchors(TrustAnchorType::Csca)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                storage
                    .count_trust_anchors(TrustAnchorType::Iaca)
                    .await
                    .unwrap(),
                0
            );
        });
    }

    // ====================================================================
    // Mixed trust packages
    // ====================================================================

    #[test]
    fn mixed_package_replaces_all_domain_records_and_advances_metadata_once() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let first = package_provenance("usb:mixed", 1, "1.0.0", 1, "usb-root-1", 'a');
            let iaca = trust_anchor(&[1, 2, 3], TrustAnchorType::Iaca, "US-CO", first.created_at);
            let csca = trust_anchor(&[4, 5, 6], TrustAnchorType::Csca, "US", first.created_at);
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");

            let applied = storage
                .apply_trust_package(
                    &first,
                    &[iaca.clone(), csca.clone()],
                    std::slice::from_ref(&key),
                )
                .await
                .unwrap();
            assert_eq!(
                applied,
                TrustPackageApplyResult {
                    trust_anchors: 2,
                    open_badge_methods: 1,
                }
            );
            let iaca_records = storage
                .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                .await
                .unwrap();
            assert_eq!(iaca_records.len(), 1);
            assert_eq!(iaca_records[0].provenance.as_ref(), Some(&first));
            assert_eq!(
                storage.get_open_badge_trust_records().await.unwrap()[0]
                    .provenance
                    .as_ref(),
                Some(&first)
            );
            let sync = storage.get_sync_state().await.unwrap().unwrap();
            assert_eq!(sync.last_iaca_sync, Some(first.created_at));
            assert_eq!(sync.last_csca_sync, Some(first.created_at));
            assert_eq!(sync.iaca_version.as_deref(), Some("1.0.0"));

            let second = package_provenance("usb:mixed", 2, "2.0.0", 2, "usb-root-1", 'b');
            let replacement = trust_anchor(
                &[7, 8, 9],
                TrustAnchorType::Iaca,
                "US-UT",
                second.created_at,
            );
            let replacement_key =
                open_badge_method("did:example:issuer#key-2", "did:example:issuer");
            storage
                .apply_trust_package(
                    &second,
                    std::slice::from_ref(&replacement),
                    std::slice::from_ref(&replacement_key),
                )
                .await
                .unwrap();

            assert!(storage
                .get_trust_anchor_records(TrustAnchorType::Csca, None)
                .await
                .unwrap()
                .is_empty());
            let active = storage
                .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                .await
                .unwrap();
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].anchor.id, replacement.id);
            assert_eq!(active[0].provenance.as_ref(), Some(&second));
            let methods = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(methods.len(), 1);
            assert_eq!(methods[0].method.id, replacement_key.id);

            assert!(matches!(
                storage
                    .apply_trust_package(&first, &[iaca, csca], std::slice::from_ref(&key))
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageRollback { .. }
            ));
            let legacy_overwrite = storage.store_trust_anchor(&replacement).await.unwrap_err();
            assert!(matches!(
                legacy_overwrite,
                StorageError::TrustPackageConflict(_)
            ));

            let conn = storage.conn.lock().await;
            let audit_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE event_type = 'trust_package_applied'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(audit_count, 2);
            assert_eq!(
                load_open_badge_package_provenance(&conn, "usb:mixed").unwrap(),
                Some(second)
            );
        });
    }

    #[test]
    fn mixed_package_failure_after_delete_rolls_back_every_state_class() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let current = package_provenance("usb:mixed", 1, "1.0.0", 1, "usb-root-1", 'a');
            let anchor = trust_anchor(
                &[1, 2, 3],
                TrustAnchorType::Iaca,
                "US-CO",
                current.created_at,
            );
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_trust_package(
                    &current,
                    std::slice::from_ref(&anchor),
                    std::slice::from_ref(&key),
                )
                .await
                .unwrap();

            let mut legacy = trust_anchor(
                &[9, 9, 9],
                TrustAnchorType::Csca,
                "legacy",
                current.created_at,
            );
            legacy.source = TrustAnchorSource::Manual;
            storage.store_trust_anchor(&legacy).await.unwrap();

            let newer = package_provenance("usb:mixed", 2, "2.0.0", 2, "usb-root-1", 'b');
            let replacement =
                trust_anchor(&[4, 5, 6], TrustAnchorType::Iaca, "US-UT", newer.created_at);
            let conflicting = trust_anchor(
                &[9, 9, 9],
                TrustAnchorType::Csca,
                "legacy",
                newer.created_at,
            );
            let error = storage
                .apply_trust_package(&newer, &[replacement, conflicting], &[])
                .await
                .unwrap_err();
            assert!(matches!(error, StorageError::TrustPackageConflict(_)));

            let active = storage
                .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                .await
                .unwrap();
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].anchor.id, anchor.id);
            assert_eq!(active[0].provenance.as_ref(), Some(&current));
            let methods = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(methods.len(), 1);
            assert_eq!(methods[0].method.id, key.id);
            assert_eq!(methods[0].provenance.as_ref(), Some(&current));
            assert_eq!(
                storage
                    .get_sync_state()
                    .await
                    .unwrap()
                    .unwrap()
                    .iaca_version,
                Some("1.0.0".to_string())
            );

            let conn = storage.conn.lock().await;
            let audit_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE event_type = 'trust_package_applied'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(audit_count, 1);
            assert_eq!(
                load_open_badge_package_provenance(&conn, "usb:mixed").unwrap(),
                Some(current)
            );
        });
    }

    #[test]
    fn expired_package_fails_closed_without_mutating_trust_state() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let mut expired = package_provenance("usb:expired", 1, "1.0.0", 1, "usb-root-1", 'a');
            expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
            let anchor = trust_anchor(
                &[1, 2, 3],
                TrustAnchorType::Iaca,
                "US-CO",
                expired.created_at,
            );

            let error = storage
                .apply_trust_package(&expired, std::slice::from_ref(&anchor), &[])
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                StorageError::InvalidTrustPackage(message)
                    if message.contains("expiry time has passed")
            ));

            let conn = storage.conn.lock().await;
            for table in ["trust_anchors", "trust_packages", "audit_log"] {
                let count: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "expired package mutated {table}");
            }
            drop(conn);

            let active = package_provenance("usb:active", 1, "1.0.0", 1, "usb-root-1", 'b');
            let method = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_trust_package(
                    &active,
                    std::slice::from_ref(&anchor),
                    std::slice::from_ref(&method),
                )
                .await
                .unwrap();
            let past = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
            let conn = storage.conn.lock().await;
            conn.execute(
                "UPDATE trust_anchors SET package_expires_at = ? WHERE trust_domain = ?",
                rusqlite::params![past, active.trust_domain],
            )
            .unwrap();
            conn.execute(
                "UPDATE trust_packages SET package_expires_at = ? WHERE trust_domain = ?",
                rusqlite::params![past, active.trust_domain],
            )
            .unwrap();
            conn.execute(
                "UPDATE open_badge_keys SET package_expires_at = ? WHERE trust_domain = ?",
                rusqlite::params![past, active.trust_domain],
            )
            .unwrap();
            drop(conn);

            assert!(matches!(
                storage
                    .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                    .await,
                Err(StorageError::InvalidTrustPackage(message))
                    if message.contains("expiry time has passed")
            ));
            assert!(matches!(
                storage.get_open_badge_keys().await,
                Err(StorageError::InvalidTrustPackage(message))
                    if message.contains("expiry time has passed")
            ));
        });
    }

    #[test]
    fn package_creation_and_import_clock_skew_is_bounded() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let now = Utc::now();
            let mut within_skew =
                package_provenance("usb:skew-ok", 1, "1.0.0", 1, "usb-root-1", 'a');
            within_skew.created_at = now + chrono::Duration::minutes(5);
            within_skew.imported_at = now;
            within_skew.expires_at = now + chrono::Duration::days(1);
            storage
                .apply_trust_package(&within_skew, &[], &[])
                .await
                .unwrap();

            let mut future_creation = within_skew.clone();
            future_creation.trust_domain = "usb:skew-created".to_string();
            future_creation.created_at = now + chrono::Duration::minutes(6);
            assert!(matches!(
                storage.apply_trust_package(&future_creation, &[], &[]).await,
                Err(StorageError::InvalidTrustPackage(message))
                    if message.contains("creation time exceeds")
            ));

            let mut future_import = within_skew;
            future_import.trust_domain = "usb:skew-imported".to_string();
            future_import.imported_at = now + chrono::Duration::minutes(6);
            assert!(matches!(
                storage.apply_trust_package(&future_import, &[], &[]).await,
                Err(StorageError::InvalidTrustPackage(message))
                    if message.contains("import time exceeds")
            ));
        });
    }

    #[test]
    fn tampered_governed_anchor_fails_closed() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let package = package_provenance("usb:mixed", 1, "1.0.0", 1, "usb-root-1", 'a');
            let anchor = trust_anchor(
                &[1, 2, 3],
                TrustAnchorType::Iaca,
                "US-CO",
                package.created_at,
            );
            storage
                .apply_trust_package(&package, std::slice::from_ref(&anchor), &[])
                .await
                .unwrap();
            {
                let conn = storage.conn.lock().await;
                conn.execute(
                    "UPDATE trust_anchors SET not_before = 'not-a-time' WHERE id = ?",
                    [&anchor.id],
                )
                .unwrap();
            }
            assert!(matches!(
                storage
                    .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                    .await
                    .unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));
        });
    }

    #[test]
    fn raw_legacy_adapter_writes_cannot_strip_governed_provenance() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let package = package_provenance("usb:mixed", 1, "1.0.0", 1, "usb-root-1", 'a');
            let anchor = trust_anchor(
                &[1, 2, 3],
                TrustAnchorType::Iaca,
                "US-CO",
                package.created_at,
            );
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_trust_package(
                    &package,
                    std::slice::from_ref(&anchor),
                    std::slice::from_ref(&key),
                )
                .await
                .unwrap();

            {
                let conn = storage.conn.lock().await;
                assert!(conn
                    .execute(
                        r#"
                        INSERT OR REPLACE INTO trust_anchors
                            (id, anchor_type, jurisdiction, certificate_der,
                             certificate_hash, source, synced_at)
                        VALUES (?, 'iaca', 'legacy', X'01', ?, 'manual', ?)
                        "#,
                        rusqlite::params![anchor.id, anchor.id, Utc::now().to_rfc3339()],
                    )
                    .is_err());
                assert!(conn
                    .execute(
                        r#"
                        INSERT OR REPLACE INTO open_badge_keys
                            (id, document_json, source, synced_at)
                        VALUES (?, '{}', 'manual', ?)
                        "#,
                        rusqlite::params![key.id, Utc::now().to_rfc3339()],
                    )
                    .is_err());
                assert!(conn
                    .execute(
                        "UPDATE trust_anchors SET trust_domain = NULL WHERE id = ?",
                        [&anchor.id],
                    )
                    .is_err());
                assert!(conn
                    .execute(
                        "UPDATE open_badge_keys SET trust_domain = NULL WHERE id = ?",
                        [&key.id],
                    )
                    .is_err());
            }

            assert_eq!(
                storage
                    .get_trust_anchor_records(TrustAnchorType::Iaca, None)
                    .await
                    .unwrap()[0]
                    .provenance
                    .as_ref(),
                Some(&package)
            );
            assert_eq!(
                storage.get_open_badge_trust_records().await.unwrap()[0]
                    .provenance
                    .as_ref(),
                Some(&package)
            );
        });
    }

    // ====================================================================
    // Open Badge trust packages
    // ====================================================================

    #[test]
    fn open_badge_package_apply_records_provenance_and_replaces_domain() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let first = package_provenance("usb:default", 1, "1.0.0", 1, "usb-root-1", 'a');
            let key_one = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            let key_two = open_badge_method("did:example:issuer#key-2", "did:example:issuer");

            assert_eq!(
                storage
                    .apply_open_badge_trust_package(&first, &[key_one.clone(), key_two.clone()],)
                    .await
                    .unwrap(),
                2
            );
            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 2);
            assert!(records
                .iter()
                .all(|record| record.provenance.as_ref() == Some(&first)));
            assert!(records
                .iter()
                .all(|record| record.method.synced_at == first.created_at));

            let second = package_provenance("usb:default", 2, "2.0.0", 2, "usb-root-1", 'b');
            assert_eq!(
                storage
                    .apply_open_badge_trust_package(&second, std::slice::from_ref(&key_two))
                    .await
                    .unwrap(),
                1
            );
            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].method.id, key_two.id);
            assert_eq!(records[0].provenance.as_ref(), Some(&second));

            let legacy_overwrite = storage.store_open_badge_key(&key_two).await.unwrap_err();
            assert!(matches!(
                legacy_overwrite,
                StorageError::TrustPackageConflict(_)
            ));
            assert_eq!(
                storage.get_open_badge_trust_records().await.unwrap()[0]
                    .provenance
                    .as_ref(),
                Some(&second)
            );

            let empty = package_provenance("usb:default", 3, "3.0.0", 3, "usb-root-1", 'c');
            assert_eq!(
                storage
                    .apply_open_badge_trust_package(&empty, &[])
                    .await
                    .unwrap(),
                0
            );
            assert!(storage
                .get_open_badge_trust_records()
                .await
                .unwrap()
                .is_empty());
            let conn = storage.conn.lock().await;
            assert_eq!(
                load_open_badge_package_provenance(&conn, "usb:default").unwrap(),
                Some(empty)
            );
        });
    }

    #[test]
    fn open_badge_package_replay_and_rollback_leave_state_unchanged() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let current = package_provenance("usb:default", 2, "2.0.0", 2, "usb-root-1", 'b');
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_open_badge_trust_package(&current, std::slice::from_ref(&key))
                .await
                .unwrap();

            let replay = storage
                .apply_open_badge_trust_package(&current, std::slice::from_ref(&key))
                .await
                .unwrap_err();
            assert!(matches!(replay, StorageError::TrustPackageReplay { .. }));

            let rollback = package_provenance("usb:default", 1, "1.0.0", 1, "usb-root-1", 'a');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&rollback, std::slice::from_ref(&key))
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageRollback { .. }
            ));

            let equal_sequence_conflict =
                package_provenance("usb:default", 2, "2.0.1", 3, "usb-root-1", 'c');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(
                        &equal_sequence_conflict,
                        std::slice::from_ref(&key),
                    )
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageConflict(_)
            ));

            let equal_version_conflict =
                package_provenance("usb:default", 3, "2.0.0", 3, "usb-root-1", 'c');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(
                        &equal_version_conflict,
                        std::slice::from_ref(&key),
                    )
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageConflict(_)
            ));

            let signer_change = package_provenance("usb:default", 3, "3.0.0", 3, "usb-root-2", 'c');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&signer_change, std::slice::from_ref(&key))
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageSignerChange(_)
            ));

            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].provenance.as_ref(), Some(&current));
        });
    }

    #[test]
    fn invalid_or_cross_domain_open_badge_package_is_atomic() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let first = package_provenance("usb:one", 1, "1.0.0", 1, "usb-root-1", 'a');
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_open_badge_trust_package(&first, std::slice::from_ref(&key))
                .await
                .unwrap();

            let second = package_provenance("usb:two", 1, "1.0.0", 1, "usb-root-1", 'b');
            let other_key = open_badge_method("did:example:other#key-1", "did:example:other");
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&second, &[key.clone(), other_key.clone()],)
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageConflict(_)
            ));

            let duplicate = package_provenance("usb:three", 1, "1.0.0", 1, "usb-root-1", 'c');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&duplicate, &[other_key.clone(), other_key])
                    .await
                    .unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));

            let mut private_key =
                open_badge_method("did:example:private#key-1", "did:example:private");
            private_key.document["secretKeyMultibase"] = serde_json::json!("zPrivate");
            let private_package =
                package_provenance("usb:private", 1, "1.0.0", 1, "usb-root-1", 'd');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&private_package, &[private_key])
                    .await
                    .unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));

            let mut invalid_interval =
                open_badge_method("did:example:interval#key-1", "did:example:interval");
            invalid_interval.not_before = Some(Utc.with_ymd_and_hms(2026, 2, 2, 0, 0, 0).unwrap());
            invalid_interval.not_after = Some(Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap());
            let interval_package =
                package_provenance("usb:interval", 1, "1.0.0", 1, "usb-root-1", 'e');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&interval_package, &[invalid_interval])
                    .await
                    .unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));

            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].method.id, key.id);
            assert_eq!(records[0].provenance.as_ref(), Some(&first));

            let conn = storage.conn.lock().await;
            assert!(load_open_badge_package_provenance(&conn, "usb:two")
                .unwrap()
                .is_none());
            assert!(load_open_badge_package_provenance(&conn, "usb:three")
                .unwrap()
                .is_none());
            assert!(load_open_badge_package_provenance(&conn, "usb:private")
                .unwrap()
                .is_none());
            assert!(load_open_badge_package_provenance(&conn, "usb:interval")
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn open_badge_package_conflict_after_domain_delete_rolls_back_transaction() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let current = package_provenance("usb:one", 1, "1.0.0", 1, "usb-root-1", 'a');
            let current_key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_open_badge_trust_package(&current, std::slice::from_ref(&current_key))
                .await
                .unwrap();

            let legacy_key = open_badge_method("did:example:legacy#key-1", "did:example:legacy");
            storage.store_open_badge_key(&legacy_key).await.unwrap();

            let replacement = open_badge_method("did:example:issuer#key-2", "did:example:issuer");
            let newer = package_provenance("usb:one", 2, "2.0.0", 2, "usb-root-1", 'b');
            assert!(matches!(
                storage
                    .apply_open_badge_trust_package(&newer, &[replacement, legacy_key.clone()],)
                    .await
                    .unwrap_err(),
                StorageError::TrustPackageConflict(_)
            ));

            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 2);
            assert!(records.iter().any(|record| {
                record.method.id == current_key.id && record.provenance.as_ref() == Some(&current)
            }));
            assert!(records.iter().any(|record| {
                record.method.id == legacy_key.id && record.provenance.is_none()
            }));
            let conn = storage.conn.lock().await;
            assert_eq!(
                load_open_badge_package_provenance(&conn, "usb:one").unwrap(),
                Some(current)
            );
        });
    }

    #[test]
    fn tampered_open_badge_package_provenance_fails_closed() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let package = package_provenance("usb:one", 1, "1.0.0", 1, "usb-root-1", 'a');
            let key = open_badge_method("did:example:issuer#key-1", "did:example:issuer");
            storage
                .apply_open_badge_trust_package(&package, std::slice::from_ref(&key))
                .await
                .unwrap();

            {
                let conn = storage.conn.lock().await;
                conn.execute(
                    "UPDATE open_badge_keys SET synced_at = '2026-01-02T00:00:00Z' WHERE id = ?",
                    [&key.id],
                )
                .unwrap();
            }
            assert!(matches!(
                storage.get_open_badge_trust_records().await.unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));

            {
                let conn = storage.conn.lock().await;
                conn.execute(
                    "UPDATE open_badge_keys SET synced_at = ?, package_digest = 'BAD' WHERE id = ?",
                    rusqlite::params![package.created_at.to_rfc3339(), key.id],
                )
                .unwrap();
                conn.execute(
                    "UPDATE trust_packages SET package_digest = 'BAD' WHERE trust_domain = ?",
                    [&package.trust_domain],
                )
                .unwrap();
            }
            assert!(matches!(
                storage.get_open_badge_trust_records().await.unwrap_err(),
                StorageError::InvalidTrustPackage(_)
            ));
        });
    }

    // ====================================================================
    // Offline queue
    // ====================================================================

    #[test]
    fn test_queue_and_retrieve_events() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let payload = serde_json::json!({"type": "verification", "status": "ok"});
            let id = storage
                .queue_event("verification_complete", &payload)
                .await
                .unwrap();
            assert!(!id.is_empty());

            let pending = storage.get_pending_events(10).await.unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].event_type, "verification_complete");
            assert_eq!(pending[0].payload["type"], "verification");
        });
    }

    #[test]
    fn test_remove_queued_event() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let payload = serde_json::json!({"x": 1});
            let id = storage.queue_event("test", &payload).await.unwrap();

            storage.remove_queued_event(&id).await.unwrap();
            let pending = storage.get_pending_events(10).await.unwrap();
            assert!(pending.is_empty());
        });
    }

    #[test]
    fn test_queue_status() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let status = storage.get_queue_status().await.unwrap();
            assert_eq!(status.pending_events, 0);
            assert_eq!(status.data_size_bytes, 0);

            storage
                .queue_event("test", &serde_json::json!({"a":"b"}))
                .await
                .unwrap();
            let status = storage.get_queue_status().await.unwrap();
            assert_eq!(status.pending_events, 1);
            assert!(status.data_size_bytes > 0);
        });
    }

    // ====================================================================
    // License state
    // ====================================================================

    #[test]
    fn test_license_state_initially_none() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let state = storage.get_license_state().await.unwrap();
            assert!(state.is_none());
        });
    }

    #[test]
    fn test_update_and_get_license_state() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let state = LicenseState {
                license_jwt: Some("eyJ...".to_string()),
                validated_at: Some(Utc::now()),
                hardware_fingerprint: Some("fp-abc".to_string()),
                verifications_today: 42,
                verifications_date: Some("2026-03-28".to_string()),
                verifications_total: 1000,
                grace_period_started: None,
            };
            storage.update_license_state(&state).await.unwrap();

            let stored = storage.get_license_state().await.unwrap().unwrap();
            assert_eq!(stored.license_jwt, Some("eyJ...".to_string()));
            assert_eq!(stored.verifications_today, 42);
            assert_eq!(stored.verifications_total, 1000);
            assert_eq!(stored.hardware_fingerprint, Some("fp-abc".to_string()));
        });
    }

    // ====================================================================
    // Sync state
    // ====================================================================

    #[test]
    fn test_sync_state_initially_none() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let state = storage.get_sync_state().await.unwrap();
            assert!(state.is_none());
        });
    }

    #[test]
    fn test_update_and_get_sync_state() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let state = SyncState {
                last_iaca_sync: Some(Utc::now()),
                last_csca_sync: None,
                last_crl_sync: None,
                iaca_version: Some("v2".to_string()),
                csca_version: None,
                sync_in_progress: false,
                last_error: None,
            };
            storage.update_sync_state(&state).await.unwrap();

            let stored = storage.get_sync_state().await.unwrap().unwrap();
            assert_eq!(stored.iaca_version, Some("v2".to_string()));
            assert!(!stored.sync_in_progress);
        });
    }

    // ====================================================================
    // Audit log
    // ====================================================================

    #[test]
    fn test_add_audit_log() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            storage
                .add_audit_log(
                    "license_validated",
                    Some("operator-1"),
                    Some("license-123"),
                    Some(&serde_json::json!({"result": "ok"})),
                )
                .await
                .unwrap();
            // No getter method yet, just verify it doesn't error
        });
    }

    #[test]
    fn test_add_audit_log_minimal() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            storage
                .add_audit_log("startup", None, None, None)
                .await
                .unwrap();
        });
    }

    // ====================================================================
    // Schema / migration helpers
    // ====================================================================

    #[test]
    fn test_schema_version_stored() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let conn = storage.conn.lock().await;
            let version = get_schema_version(&conn).unwrap();
            assert_eq!(version, SCHEMA_VERSION);
        });
    }

    #[test]
    fn test_column_exists_positive() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let conn = storage.conn.lock().await;
            assert!(column_exists(&conn, "verification_events", "credential_type").unwrap());
        });
    }

    #[test]
    fn test_column_exists_negative() {
        let rt = runtime();
        rt.block_on(async {
            let storage = SecureStorage::new_in_memory().unwrap();
            let conn = storage.conn.lock().await;
            assert!(!column_exists(&conn, "verification_events", "nonexistent_column").unwrap());
        });
    }

    #[test]
    fn open_badge_provenance_migrates_shared_newer_schema_without_losing_legacy_rows() {
        let rt = runtime();
        rt.block_on(async {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE open_badge_keys (
                    id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    controller TEXT,
                    issuer TEXT,
                    kid TEXT,
                    not_before TEXT,
                    not_after TEXT,
                    status TEXT,
                    source TEXT,
                    synced_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO open_badge_keys
                    (id, document_json, source, synced_at)
                VALUES
                    ('legacy-key', '{"id":"legacy-key"}', 'manual', '2026-01-01T00:00:00Z');
                CREATE TABLE open_badge_trust_packages (
                    trust_domain TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    package_version TEXT NOT NULL,
                    package_created_at TEXT NOT NULL,
                    signer_key_id TEXT NOT NULL,
                    package_digest TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO open_badge_trust_packages
                    (trust_domain, sequence, package_version, package_created_at,
                     signer_key_id, package_digest, imported_at)
                VALUES
                    ('usb:migrated', 1, '1.0.0', '2026-01-01T00:00:00Z',
                     'usb-root-1',
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     '2026-01-01T01:00:00Z');
                "#,
            )
            .unwrap();

            // The app storage adapter currently writes a numerically newer
            // shared schema version. Mirror production's schema-then-migrate
            // initialization order, and ensure physical migration still runs.
            conn.execute_batch(SCHEMA).unwrap();
            migrate_schema(&conn, 4).unwrap();
            for column in [
                "trust_domain",
                "package_sequence",
                "package_version",
                "package_created_at",
                "package_expires_at",
                "package_signer_key_id",
                "package_digest",
                "package_imported_at",
            ] {
                assert!(column_exists(&conn, "open_badge_keys", column).unwrap());
                assert!(column_exists(&conn, "trust_anchors", column).unwrap());
            }
            let package_table: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'trust_packages'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(package_table, 1);
            assert!(column_exists(&conn, "trust_packages", "package_expires_at").unwrap());
            assert!(!table_exists(&conn, "open_badge_trust_packages").unwrap());
            assert!(matches!(
                load_open_badge_package_provenance(&conn, "usb:migrated"),
                Err(StorageError::InvalidTrustPackage(message))
                    if message.contains("missing signed expiry")
            ));
            let trust_domain_index: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_open_badge_keys_trust_domain'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(trust_domain_index, 1);

            let storage = SecureStorage {
                conn: Arc::new(Mutex::new(conn)),
            };
            let records = storage.get_open_badge_trust_records().await.unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].method.id, "legacy-key");
            assert!(records[0].provenance.is_none());
        });
    }
}
