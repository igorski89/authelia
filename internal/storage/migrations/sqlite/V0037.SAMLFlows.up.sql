CREATE TABLE IF NOT EXISTS saml_flows (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    service_provider VARCHAR(1024) NOT NULL,
    form TEXT NOT NULL,
    consumed_at TIMESTAMP NULL DEFAULT NULL
);

CREATE UNIQUE INDEX saml_flows_flow_id_key ON saml_flows (flow_id);
CREATE INDEX saml_flows_expires_at_idx ON saml_flows (expires_at);
