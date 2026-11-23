CREATE TABLE IF NOT EXISTS saml_flows (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    flow_id CHAR(36) COLLATE utf8mb4_bin NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    service_provider VARCHAR(1024) COLLATE utf8mb4_bin NOT NULL,
    form TEXT NOT NULL,
    consumed_at TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE UNIQUE INDEX saml_flows_flow_id_key ON saml_flows (flow_id);
CREATE INDEX saml_flows_expires_at_idx ON saml_flows (expires_at);
