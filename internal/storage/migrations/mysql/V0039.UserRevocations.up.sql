CREATE TABLE IF NOT EXISTS user_revocations (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) COLLATE utf8mb4_bin NOT NULL,
    client_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
    revoked_at TIMESTAMP NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE UNIQUE INDEX user_revocations_lookup_key ON user_revocations (username, client_id);
