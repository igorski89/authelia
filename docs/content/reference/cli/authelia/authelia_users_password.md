---
title: "authelia users password"
description: "Reference for the authelia users password command."
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

## authelia users password

Set or remove the password of a user

### Synopsis

Set or remove the password of a user.

The password is read from the terminal, or from the first line of the standard input with --password-stdin. A password digest in the PHC string format can be given with --password-digest instead, and --no-password removes the password.

```
authelia users password <username> [flags]
```

### Options

```
  -h, --help                          help for password
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

