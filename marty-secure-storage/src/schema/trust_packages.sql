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
