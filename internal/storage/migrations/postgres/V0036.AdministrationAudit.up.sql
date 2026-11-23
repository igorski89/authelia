CREATE TABLE IF NOT EXISTS administration_audit (
    id SERIAL CONSTRAINT administration_audit_pkey PRIMARY KEY,
    time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    username VARCHAR(100) NULL DEFAULT NULL,
    group_name VARCHAR(100) NULL DEFAULT NULL,
    details TEXT NULL DEFAULT NULL
);

CREATE INDEX administration_audit_time_idx ON administration_audit (time);
CREATE INDEX administration_audit_username_idx ON administration_audit (username);
