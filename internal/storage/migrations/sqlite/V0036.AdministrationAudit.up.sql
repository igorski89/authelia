CREATE TABLE IF NOT EXISTS administration_audit (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    username VARCHAR(100) NULL DEFAULT NULL,
    group_name VARCHAR(100) NULL DEFAULT NULL,
    details TEXT NULL DEFAULT NULL
);

CREATE INDEX administration_audit_time_idx ON administration_audit (time);
CREATE INDEX administration_audit_username_idx ON administration_audit (username);
