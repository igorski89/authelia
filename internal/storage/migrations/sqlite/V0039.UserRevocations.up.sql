CREATE TABLE IF NOT EXISTS user_revocations (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL,
    client_id VARCHAR(255) NOT NULL DEFAULT '',
    revoked_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX user_revocations_lookup_key ON user_revocations (username, client_id);
