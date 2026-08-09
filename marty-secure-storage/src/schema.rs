//! Database schema definitions

/// SQL schema for secure storage
pub const SCHEMA: &str = r#"
-- Verification events table
CREATE TABLE IF NOT EXISTS verification_events (
    id TEXT PRIMARY KEY,
    credential_type TEXT NOT NULL,
    status TEXT NOT NULL,
    issuer_jurisdiction TEXT,
    trust_chain_type TEXT,
    offline_verified INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT NOT NULL,
    synced INTEGER NOT NULL DEFAULT 0,
    synced_at TEXT,
    -- Encrypted PII fields (optional, based on config)
    encrypted_subject_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_verification_events_verified_at 
    ON verification_events(verified_at);
CREATE INDEX IF NOT EXISTS idx_verification_events_synced 
    ON verification_events(synced);
CREATE INDEX IF NOT EXISTS idx_verification_events_credential_type 
    ON verification_events(credential_type);

-- Trust anchors cache (IACA/CSCA certificates)
CREATE TABLE IF NOT EXISTS trust_anchors (
    id TEXT PRIMARY KEY,
    anchor_type TEXT NOT NULL, -- 'iaca', 'csca', 'dsc'
    jurisdiction TEXT NOT NULL,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    certificate_der BLOB NOT NULL,
    certificate_hash TEXT NOT NULL,
    source TEXT, -- 'aamva_dts', 'icao_pkd', 'usb_import', 'manual'
    synced_at TEXT NOT NULL,
    trust_domain TEXT,
    package_sequence INTEGER,
    package_version TEXT,
    package_created_at TEXT,
    package_expires_at TEXT,
    package_signer_key_id TEXT,
    package_digest TEXT,
    package_imported_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_trust_anchors_type_jurisdiction 
    ON trust_anchors(anchor_type, jurisdiction);
CREATE INDEX IF NOT EXISTS idx_trust_anchors_hash 
    ON trust_anchors(certificate_hash);
CREATE INDEX IF NOT EXISTS idx_trust_anchors_trust_domain
    ON trust_anchors(trust_domain);

-- Open Badge verification methods (trusted public keys)
CREATE TABLE IF NOT EXISTS open_badge_keys (
    id TEXT PRIMARY KEY,
    document_json TEXT NOT NULL, -- JSON verification method document
    controller TEXT,
    issuer TEXT,
    kid TEXT,
    not_before TEXT,
    not_after TEXT,
    status TEXT,
    source TEXT, -- 'sync', 'usb_import', 'manual'
    synced_at TEXT NOT NULL,
    trust_domain TEXT,
    package_sequence INTEGER,
    package_version TEXT,
    package_created_at TEXT,
    package_expires_at TEXT,
    package_signer_key_id TEXT,
    package_digest TEXT,
    package_imported_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_open_badge_keys_controller
    ON open_badge_keys(controller);
CREATE INDEX IF NOT EXISTS idx_open_badge_keys_status
    ON open_badge_keys(status);
-- Last accepted mixed trust package for each governed trust domain.
CREATE TABLE IF NOT EXISTS trust_packages (
    trust_domain TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    package_version TEXT NOT NULL,
    package_created_at TEXT NOT NULL,
    package_expires_at TEXT,
    signer_key_id TEXT NOT NULL,
    next_signer_key_id TEXT,
    recovery_signer_key_id TEXT,
    package_digest TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- CRL cache
CREATE TABLE IF NOT EXISTS crl_cache (
    id TEXT PRIMARY KEY,
    issuer_hash TEXT NOT NULL,
    crl_der BLOB NOT NULL,
    next_update TEXT,
    fetched_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_crl_cache_issuer 
    ON crl_cache(issuer_hash);

-- OCSP cache
CREATE TABLE IF NOT EXISTS ocsp_cache (
    id TEXT PRIMARY KEY,
    cert_hash TEXT NOT NULL,
    response_der BLOB NOT NULL,
    status TEXT NOT NULL, -- 'good', 'revoked', 'unknown'
    this_update TEXT,
    next_update TEXT,
    fetched_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ocsp_cache_cert 
    ON ocsp_cache(cert_hash);

-- Offline reporting queue
CREATE TABLE IF NOT EXISTS offline_queue (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL, -- JSON
    created_at TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_retry_at TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_offline_queue_created 
    ON offline_queue(created_at);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT, -- operator ID if applicable
    target TEXT, -- what was acted upon
    details TEXT, -- JSON
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created 
    ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type 
    ON audit_log(event_type);

-- License state
CREATE TABLE IF NOT EXISTS license_state (
    id TEXT PRIMARY KEY DEFAULT 'current',
    license_jwt TEXT,
    validated_at TEXT,
    hardware_fingerprint TEXT,
    verifications_today INTEGER NOT NULL DEFAULT 0,
    verifications_date TEXT,
    verifications_total INTEGER NOT NULL DEFAULT 0,
    grace_period_started TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sync state
CREATE TABLE IF NOT EXISTS sync_state (
    id TEXT PRIMARY KEY DEFAULT 'current',
    last_iaca_sync TEXT,
    last_csca_sync TEXT,
    last_crl_sync TEXT,
    iaca_version TEXT,
    csca_version TEXT,
    sync_in_progress INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Configuration storage
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// Schema version for migrations
pub const SCHEMA_VERSION: i32 = 3;
