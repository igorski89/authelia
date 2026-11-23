CREATE TABLE IF NOT EXISTS webauthn_credentials_imported (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kid VARCHAR(512) NOT NULL,
    source VARCHAR(64) NOT NULL
);

CREATE UNIQUE INDEX webauthn_credentials_imported_kid_key ON webauthn_credentials_imported (kid);
