CREATE TABLE IF NOT EXISTS webauthn_credentials_imported (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kid VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
    source VARCHAR(64) COLLATE utf8mb4_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE UNIQUE INDEX webauthn_credentials_imported_kid_key ON webauthn_credentials_imported (kid);
