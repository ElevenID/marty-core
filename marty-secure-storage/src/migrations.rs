//! Additive migrations and legacy schema compatibility.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension};

const PROVENANCE_COLUMNS: &[(&str, &str)] = &[
    ("trust_domain", "TEXT"),
    ("package_sequence", "INTEGER"),
    ("package_version", "TEXT"),
    ("package_created_at", "TEXT"),
    ("package_expires_at", "TEXT"),
    ("package_signer_key_id", "TEXT"),
    ("package_digest", "TEXT"),
    ("package_imported_at", "TEXT"),
];

pub(super) fn get_schema_version(conn: &Connection) -> Result<i32, StorageError> {
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(version.and_then(|v| v.parse::<i32>().ok()).unwrap_or(0))
}

pub(super) fn migrate_schema(conn: &Connection, current_version: i32) -> Result<(), StorageError> {
    if current_version < 2 && !column_exists(conn, "license_state", "verifications_total")? {
        conn.execute(
            "ALTER TABLE license_state ADD COLUMN verifications_total INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    // Legacy application versions shared the core marker. Physical checks keep
    // those databases compatible; current application versions use their own marker.
    for table in ["open_badge_keys", "trust_anchors"] {
        for (column, definition) in PROVENANCE_COLUMNS {
            if !column_exists(conn, table, column)? {
                conn.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
    }
    conn.execute_batch(concat!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_open_badge_keys_trust_domain
            ON open_badge_keys(trust_domain);
        CREATE INDEX IF NOT EXISTS idx_trust_anchors_trust_domain
            ON trust_anchors(trust_domain);
"#,
        include_str!("schema/trust_packages.sql"),
        r#"
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
    ))?;
    if !column_exists(conn, "trust_packages", "package_expires_at")? {
        // Pre-release package state did not persist a signed expiry. Leave the
        // migrated value null so governed reads fail closed instead of
        // synthesizing security metadata that was never authenticated.
        conn.execute(
            "ALTER TABLE trust_packages ADD COLUMN package_expires_at TEXT",
            [],
        )?;
    }
    for (column, definition) in [
        ("next_signer_key_id", "TEXT"),
        ("recovery_signer_key_id", "TEXT"),
    ] {
        if !column_exists(conn, "trust_packages", column)? {
            conn.execute(
                &format!("ALTER TABLE trust_packages ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
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

pub(super) fn column_exists(
    conn: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, StorageError> {
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

pub(super) fn table_exists(conn: &Connection, table: &str) -> Result<bool, StorageError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
        [table],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_schema_repeated_migration_preserves_rows_and_guards() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::schema::SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO config (key,value) VALUES ('schema_version','99')",
            [],
        )
        .unwrap();
        for _ in 0..2 {
            migrate_schema(&conn, 99).unwrap();
            assert_eq!(get_schema_version(&conn).unwrap(), 99);
            for table in ["open_badge_keys", "trust_anchors"] {
                for (column, _) in PROVENANCE_COLUMNS {
                    assert!(column_exists(&conn, table, column).unwrap());
                }
            }
            let triggers: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN ('prevent_legacy_open_badge_overwrite','prevent_open_badge_provenance_removal','prevent_legacy_anchor_overwrite','prevent_anchor_provenance_removal')", [], |row| row.get(0)).unwrap();
            assert_eq!(triggers, 4);
        }
    }

    #[test]
    fn additive_migration_participates_in_caller_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE open_badge_keys (id TEXT PRIMARY KEY); CREATE TABLE trust_anchors (id TEXT PRIMARY KEY); CREATE TABLE license_state (id TEXT PRIMARY KEY); INSERT INTO open_badge_keys VALUES ('legacy');").unwrap();
        {
            let tx = conn.transaction().unwrap();
            migrate_schema(&tx, 1).unwrap();
            assert!(column_exists(&tx, "open_badge_keys", "package_digest").unwrap());
            tx.rollback().unwrap();
        }
        assert!(!column_exists(&conn, "open_badge_keys", "package_digest").unwrap());
        assert!(!table_exists(&conn, "trust_packages").unwrap());
        migrate_schema(&conn, 1).unwrap();
        let id: String = conn
            .query_row("SELECT id FROM open_badge_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(id, "legacy");
    }
}
