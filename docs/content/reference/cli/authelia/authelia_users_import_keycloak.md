---
title: "authelia users import keycloak"
description: "Reference for the authelia users import keycloak command."
lead: ""
date: 2026-11-24T01:13:30+01:00
draft: false
images: []
weight: 905
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## authelia users import keycloak

Import the users and groups of a Keycloak realm export

### Synopsis

Import the users and groups of a Keycloak realm export.

The file is the export of one realm with its users in the same file: kc.sh export --realm <realm> --users same_file --file <file>. Only its users and groups are read.

Every group is created, and every user with its group memberships, profile, enabled state, password hash (argon2 and pbkdf2, kept as they are), and WebAuthn credentials (passkeys and security keys, with their sign counts). The Keycloak user ID becomes the user's OpenID Connect 1.0 subject identifier (for clients with public subjects) and WebAuthn user handle, so apps see the same subject and passkeys keep working. The backup flags of the WebAuthn credentials, which Keycloak doesn't keep, are taken from their first sign in.

Nothing is changed unless --apply is given: without it the import runs in a transaction which is rolled back, and reports what it would do. With it everything is imported in one transaction, or nothing. An existing username, email, or group fails the import. Anything which can't be imported (one-time password credentials, subgroups, federated users, usernames or emails Authelia can't hold, unknown hash algorithms) fails the import unless --skip-unsupported is given, which reports it instead. Password history is ignored, and service account users are always skipped.

The --webauthn-rpid must be the RP ID the realm's WebAuthn policies set, if they set one, and the host of a configured authelia_url or a configured WebAuthn relying party.

```
authelia users import keycloak <realm export file> [flags]
```

### Examples

```
authelia users import keycloak realm-export.json --webauthn-rpid example.com --config config.yml
authelia users import keycloak realm-export.json --webauthn-rpid example.com --apply --config config.yml
```

### Options

```
      --apply                           import, instead of a dry run
  -h, --help                            help for keycloak
      --skip-unsupported                skip and report what can't be imported, instead of failing
      --webauthn-rpid string            the WebAuthn RP ID the credentials were registered for, which must be Authelia's (required with WebAuthn credentials)
```

### Options inherited from parent commands

```
  -c, --config strings                                   configuration files or directories to load, for more information run 'authelia -h authelia config' (default [configuration.yml])
      --config.filters strings                           list of filters to apply to all configuration files, for more information run 'authelia -h authelia filters'
      --config.filters.template.delimiter.left string    sets the left delimiter for the 'template' filter
      --config.filters.template.delimiter.right string   sets the right delimiter for the 'template' filter
      --config.filters.values strings                    file paths of values files (.yml, .yaml, .json, .toml) to utilize with configuration file filters; files are loaded in order with later files deep-merged on top, for more information run 'authelia -h authelia filters'
      --encryption-key string                            the storage encryption key to use
      --mysql.address string                             the MySQL server address (default "tcp://127.0.0.1:3306")
      --mysql.database string                            the MySQL database name (default "authelia")
      --mysql.password string                            the MySQL password
      --mysql.username string                            the MySQL username (default "authelia")
      --postgres.address string                          the PostgreSQL server address (default "tcp://127.0.0.1:5432")
      --postgres.database string                         the PostgreSQL database name (default "authelia")
      --postgres.password string                         the PostgreSQL password
      --postgres.schema string                           the PostgreSQL schema name (default "public")
      --postgres.username string                         the PostgreSQL username (default "authelia")
      --sqlite.path string                               the SQLite database path
```

### SEE ALSO

* [authelia users import](authelia_users_import.md)	 - Import users from another identity provider

