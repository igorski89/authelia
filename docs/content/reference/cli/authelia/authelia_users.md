---
title: "authelia users"
description: "Reference for the authelia users command."
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

## authelia users

Manage the users of the database authentication backend

### Synopsis

Manage the users of the database authentication backend.

These commands change the storage database directly, with the same rules as the administration API. They require the 'authentication_backend.database' configuration and the storage configuration, which may be given with the same flags as the 'authelia storage' commands.

### Examples

```
authelia users list --config config.yml
authelia users create john --email john@example.com --display-name "John Smith" --group admins --config config.yml
authelia users password john --config config.yml
authelia users update john --disable --config config.yml
authelia users delete john --config config.yml
```

### Options

```
      --encryption-key string      the storage encryption key to use
  -h, --help                       help for users
      --mysql.address string       the MySQL server address (default "tcp://127.0.0.1:3306")
      --mysql.database string      the MySQL database name (default "authelia")
      --mysql.password string      the MySQL password
      --mysql.username string      the MySQL username (default "authelia")
      --postgres.address string    the PostgreSQL server address (default "tcp://127.0.0.1:5432")
      --postgres.database string   the PostgreSQL database name (default "authelia")
      --postgres.password string   the PostgreSQL password
      --postgres.schema string     the PostgreSQL schema name (default "public")
      --postgres.username string   the PostgreSQL username (default "authelia")
      --sqlite.path string         the SQLite database path
```

### Options inherited from parent commands

```
  -c, --config strings                                   configuration files or directories to load, for more information run 'authelia -h authelia config' (default [configuration.yml])
      --config.filters strings                           list of filters to apply to all configuration files, for more information run 'authelia -h authelia filters'
      --config.filters.template.delimiter.left string    sets the left delimiter for the 'template' filter
      --config.filters.template.delimiter.right string   sets the right delimiter for the 'template' filter
      --config.filters.values strings                    file paths of values files (.yml, .yaml, .json, .toml) to utilize with configuration file filters; files are loaded in order with later files deep-merged on top, for more information run 'authelia -h authelia filters'
```

### SEE ALSO

* [authelia](authelia.md)	 - authelia untagged-unknown-dirty (master, unknown)
* [authelia users audit](authelia_users_audit.md)	 - List the changes made to users and groups, newest first
* [authelia users create](authelia_users_create.md)	 - Create a user
* [authelia users delete](authelia_users_delete.md)	 - Delete a user
* [authelia users get](authelia_users_get.md)	 - Show a user
* [authelia users import](authelia_users_import.md)	 - Import users from another identity provider
* [authelia users list](authelia_users_list.md)	 - List the users
* [authelia users logout](authelia_users_logout.md)	 - End everything a user is logged in with
* [authelia users password](authelia_users_password.md)	 - Set or remove the password of a user
* [authelia users update](authelia_users_update.md)	 - Change the profile of a user, or disable or enable it

