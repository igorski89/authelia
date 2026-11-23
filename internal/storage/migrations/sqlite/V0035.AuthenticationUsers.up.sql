CREATE TABLE IF NOT EXISTS authentication_users (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    given_name VARCHAR(100) NOT NULL DEFAULT '',
    family_name VARCHAR(100) NOT NULL DEFAULT '',
    password VARCHAR(512) NULL DEFAULT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    signature VARCHAR(128) NOT NULL
);

CREATE UNIQUE INDEX authentication_users_username_key ON authentication_users (username);
CREATE UNIQUE INDEX authentication_users_email_key ON authentication_users (email);

CREATE TABLE IF NOT EXISTS authentication_groups (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(100) NOT NULL
);

CREATE UNIQUE INDEX authentication_groups_name_key ON authentication_groups (name);

CREATE TABLE IF NOT EXISTS authentication_user_groups (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signature VARCHAR(128) NOT NULL,
    PRIMARY KEY (user_id, group_id),
    CONSTRAINT authentication_user_groups_user_id_fkey
        FOREIGN KEY (user_id)
            REFERENCES authentication_users (id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT authentication_user_groups_group_id_fkey
        FOREIGN KEY (group_id)
            REFERENCES authentication_groups (id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX authentication_user_groups_group_id_idx ON authentication_user_groups (group_id);

CREATE TABLE IF NOT EXISTS authentication_users_deleted (
    username VARCHAR(100) NOT NULL PRIMARY KEY,
    deleted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
