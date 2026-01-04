//! Secure database operations

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::encryption::PiiEncryptor;
use crate::error::StorageError;
use crate::keychain::KeychainManager;
use crate::models::*;
use crate::schema::{SCHEMA, SCHEMA_VERSION};

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
    #[allow(dead_code)]
    pii_encryptor: Option<PiiEncryptor>,
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
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('schema_version', ?)",
            [SCHEMA_VERSION.to_string()],
        )?;

        tracing::info!(?db_path, "Secure storage initialized");

        // Initialize PII encryptor
        let pii_key = keychain.get_or_create_pii_key()?;
        let pii_encryptor = Some(PiiEncryptor::new(&pii_key)?);

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            pii_encryptor,
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

        let rows = stmt.query_map([limit], |row| {
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
            conn.query_row("SELECT COUNT(*) FROM offline_queue", [], |row| row.get(0))?;

        let oldest_event: Option<String> = conn
            .query_row("SELECT MIN(created_at) FROM offline_queue", [], |row| {
                row.get(0)
            })
            .ok();

        // Estimate data size
        let data_size_bytes: usize = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM offline_queue",
            [],
            |row| row.get(0),
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

        conn.execute(
            r#"
            INSERT OR REPLACE INTO trust_anchors 
                (id, anchor_type, jurisdiction, subject, issuer, serial_number,
                 not_before, not_after, certificate_der, certificate_hash, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        Ok(())
    }

    /// Store a trusted Open Badge verification method
    pub async fn store_open_badge_key(
        &self,
        method: &OpenBadgeVerificationMethod,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let document_json = serde_json::to_string(&method.document)?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO open_badge_keys
                (id, document_json, controller, issuer, kid, not_before, not_after, status, source, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        Ok(())
    }

    /// Get trust anchors by type and jurisdiction
    pub async fn get_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
        jurisdiction: Option<&str>,
    ) -> Result<Vec<TrustAnchor>, StorageError> {
        let conn = self.conn.lock().await;

        let sql = if jurisdiction.is_some() {
            r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at
            FROM trust_anchors
            WHERE anchor_type = ? AND jurisdiction = ?
            "#
        } else {
            r#"
            SELECT id, anchor_type, jurisdiction, subject, issuer, serial_number,
                   not_before, not_after, certificate_der, certificate_hash, source, synced_at
            FROM trust_anchors
            WHERE anchor_type = ?
            "#
        };

        let mut stmt = conn.prepare(sql)?;

        let rows = if let Some(jur) = jurisdiction {
            stmt.query_map(
                [anchor_type.to_string(), jur.to_string()],
                Self::map_trust_anchor,
            )?
        } else {
            stmt.query_map([anchor_type.to_string()], Self::map_trust_anchor)?
        };

        let mut anchors = Vec::new();
        for row in rows {
            anchors.push(row?);
        }

        Ok(anchors)
    }

    fn map_trust_anchor(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrustAnchor> {
        let anchor_type_str: String = row.get(1)?;
        let source_str: String = row.get(10)?;

        Ok(TrustAnchor {
            id: row.get(0)?,
            anchor_type: match anchor_type_str.as_str() {
                "iaca" => TrustAnchorType::Iaca,
                "csca" => TrustAnchorType::Csca,
                "dsc" => TrustAnchorType::Dsc,
                _ => TrustAnchorType::Iaca,
            },
            jurisdiction: row.get(2)?,
            subject: row.get(3)?,
            issuer: row.get(4)?,
            serial_number: row.get(5)?,
            not_before: row.get::<_, Option<String>>(6)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            not_after: row.get::<_, Option<String>>(7)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            certificate_der: row.get(8)?,
            certificate_hash: row.get(9)?,
            source: match source_str.as_str() {
                "aamva_dts" => TrustAnchorSource::AamvaDts,
                "icao_pkd" => TrustAnchorSource::IcaoPkd,
                "usb_import" => TrustAnchorSource::UsbImport,
                _ => TrustAnchorSource::Manual,
            },
            synced_at: row
                .get::<_, String>(11)
                .ok()
                .and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now),
        })
    }

    /// Get all trusted Open Badge verification methods
    pub async fn get_open_badge_keys(
        &self,
    ) -> Result<Vec<OpenBadgeVerificationMethod>, StorageError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_json, controller, issuer, kid, not_before, not_after, status, source, synced_at
            FROM open_badge_keys
            "#,
        )?;

        let rows = stmt.query_map([], Self::map_open_badge_key)?;
        let mut methods = Vec::new();
        for row in rows {
            methods.push(row?);
        }

        Ok(methods)
    }

    /// Count trusted Open Badge verification methods
    pub async fn count_open_badge_keys(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().await;
        let count: usize =
            conn.query_row("SELECT COUNT(*) FROM open_badge_keys", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Get latest Open Badge trust list sync timestamp
    pub async fn get_latest_open_badge_sync(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, StorageError> {
        let conn = self.conn.lock().await;
        let synced_at: Option<String> = conn
            .query_row("SELECT MAX(synced_at) FROM open_badge_keys", [], |row| {
                row.get(0)
            })
            .ok()
            .flatten();

        Ok(synced_at.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        }))
    }

    fn map_open_badge_key(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<OpenBadgeVerificationMethod> {
        let source_str: String = row.get(8)?;
        let document_json: String = row.get(1)?;
        let document: Value =
            serde_json::from_str(&document_json).unwrap_or(serde_json::Value::Null);

        Ok(OpenBadgeVerificationMethod {
            id: row.get(0)?,
            document,
            controller: row.get(2)?,
            issuer: row.get(3)?,
            kid: row.get(4)?,
            not_before: row.get::<_, Option<String>>(5)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            not_after: row.get::<_, Option<String>>(6)?.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            status: row.get(7)?,
            source: match source_str.as_str() {
                "sync" => OpenBadgeKeySource::Sync,
                "usb_import" => OpenBadgeKeySource::UsbImport,
                _ => OpenBadgeKeySource::Manual,
            },
            synced_at: row
                .get::<_, String>(9)
                .ok()
                .and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now),
        })
    }

    /// Count trust anchors by type
    pub async fn count_trust_anchors(
        &self,
        anchor_type: TrustAnchorType,
    ) -> Result<usize, StorageError> {
        let conn = self.conn.lock().await;
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM trust_anchors WHERE anchor_type = ?",
            [anchor_type.to_string()],
            |row| row.get(0),
        )?;
        Ok(count)
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

        let rows = stmt.query_map([limit], |row| {
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
        let details_str = details.map(|d| serde_json::to_string(d)).transpose()?;

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

fn get_schema_version(conn: &Connection) -> Result<i32, StorageError> {
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(version
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0))
}

fn migrate_schema(conn: &Connection, current_version: i32) -> Result<(), StorageError> {
    if current_version < 2 {
        if !column_exists(conn, "license_state", "verifications_total")? {
            conn.execute(
                "ALTER TABLE license_state ADD COLUMN verifications_total INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
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
