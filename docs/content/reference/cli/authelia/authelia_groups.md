---
title: "authelia groups"
description: "Reference for the authelia groups command."
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

## authelia groups

Manage the groups of the database authentication backend

### Synopsis

Manage the groups of the database authentication backend.

These commands change the storage database directly, with the same rules as the administration API. They require the 'authentication_backend.database' configuration and the storage configuration, which may be given with the same flags as the 'authelia storage' commands.

### Examples

```
authelia groups list --config config.yml
authelia groups create admins --config config.yml
authelia groups add admins john jane --config config.yml
authelia groups members admins --config config.yml
```

### Options

```
      --encryption-key string      the storage encryption key to use
  -h, --help                       help for groups
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
* [authelia groups add](authelia_groups_add.md)	 - Add users to a group
* [authelia groups create](authelia_groups_create.md)	 - Create a group
* [authelia groups delete](authelia_groups_delete.md)	 - Delete a group and its memberships
* [authelia groups list](authelia_groups_list.md)	 - List the groups
* [authelia groups members](authelia_groups_members.md)	 - List the members of a group
* [authelia groups remove](authelia_groups_remove.md)	 - Remove users from a group

