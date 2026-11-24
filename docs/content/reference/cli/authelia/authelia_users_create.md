---
title: "authelia users create"
description: "Reference for the authelia users create command."
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

## authelia users create

Create a user

### Synopsis

Create a user.

The password is read from the terminal, or from the first line of the standard input with --password-stdin. A password digest in the PHC string format (for example one imported from another system) can be given with --password-digest instead, or the user can be created without a password with --no-password.

```
authelia users create <username> [flags]
```

### Options

```
      --disabled                      create the user disabled
      --display-name string           the display name of the user
      --email string                  the email of the user (required)
      --family-name string            the family name of the user
      --given-name string             the given name of the user
      --group strings                 a group to add the user to, which must exist; may be repeated
  -h, --help                          help for create
      --no-password                   no password: create the user without one, or remove it
      --password-digest string        a password digest in the PHC string format to store as it is
      --password-stdin                read the password from the first line of the standard input
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

* [authelia users](authelia_users.md)	 - Manage the users of the database authentication backend

