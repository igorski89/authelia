---
title: "authelia storage encryption rotate hmac authentication-user"
description: "Reference for the authelia storage encryption rotate hmac authentication-user command."
lead: ""
date: 2026-11-23T18:00:00+01:00
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

## authelia storage encryption rotate hmac authentication-user

Rotate the authentication user HMAC key

### Synopsis

Rotate the authentication user HMAC key.

This subcommand allows rotation of the HMAC key used to sign the users and group memberships of the database authentication backend. In addition it signs every row in the 'authentication_users' and 'authentication_user_groups' tables again with the new key. If any row has a signature which is not valid for the current key nothing is changed, so the row can be investigated.

```
authelia storage encryption rotate hmac authentication-user [flags]
```

### Examples

```
authelia storage encryption rotate hmac authentication-user --config config.yml
authelia storage encryption rotate hmac authentication-user --encryption-key b3453fde-ecc2-4a1f-9422-2707ddbed495 --postgres.address tcp://postgres:5432 --postgres.password autheliapw
```

### Options

```
  -f, --force   force the rotation without confirmation
  -h, --help    help for authentication-user
```

### Options inherited from parent commands

```
  -c, --config strings                        configuration files or directories to load, for more information run 'authelia -h authelia config' (default [configuration.yml])
      --config.experimental.filters strings   list of filters to apply to all configuration files, for more information run 'authelia -h authelia filters'
      --encryption-key string                 the storage encryption key to use
      --mysql.address string                  the MySQL server address (default "tcp://127.0.0.1:3306")
      --mysql.database string                 the MySQL database name (default "authelia")
      --mysql.password string                 the MySQL password
      --mysql.username string                 the MySQL username (default "authelia")
      --postgres.address string               the PostgreSQL server address (default "tcp://127.0.0.1:5432")
      --postgres.database string              the PostgreSQL database name (default "authelia")
      --postgres.password string              the PostgreSQL password
      --postgres.schema string                the PostgreSQL schema name (default "public")
      --postgres.username string              the PostgreSQL username (default "authelia")
      --sqlite.path string                    the SQLite database path
```

### SEE ALSO

* [authelia storage encryption rotate hmac](authelia_storage_encryption_rotate_hmac.md)	 - Rotate HMAC keys

