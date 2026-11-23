CREATE TABLE IF NOT EXISTS administration_audit (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
    action VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    username VARCHAR(100) COLLATE utf8mb4_bin NULL DEFAULT NULL,
    group_name VARCHAR(100) COLLATE utf8mb4_bin NULL DEFAULT NULL,
    details TEXT NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE INDEX administration_audit_time_idx ON administration_audit (time);
CREATE INDEX administration_audit_username_idx ON administration_audit (username);
