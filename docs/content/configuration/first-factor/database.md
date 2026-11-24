---
# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

title: "Database"
description: "Configuring the Authelia database first factor authentication provider, which keeps the users and groups in the storage database and manages them with the administration API and the CLI."
summary: "Authelia supports keeping the users and groups in its storage database. This section describes configuring this."
date: 2026-11-24T00:00:00+01:00
draft: false
images: []
weight: 102250
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The database backend keeps the users, groups, and group memberships in the [storage](../storage/introduction.md)
database, next to everything else Authelia stores. They are managed with the [administration API](../../reference/guides/administration-api.md)
and the [authelia users](../../reference/cli/authelia/authelia_users.md) and
[authelia groups](../../reference/cli/authelia/authelia_groups.md) commands, never by editing the database: every user
and group membership is signed with an HMAC key, and a row whose signature isn't valid is treated as a user which
doesn't exist.

## Configuration

{{< config-alert-example >}}

```yaml {title="configuration.yml"}
authentication_backend:
  database:
    search:
      email: false
    password:
      algorithm: 'argon2'
      argon2:
        variant: 'argon2id'
        iterations: 3
        memory: 65536
        parallelism: 4
        key_length: 32
        salt_length: 16
```

## Options

This section describes the individual configuration options.

### search

#### email

{{< confkey type="boolean" default="false" required="no" >}}

Allows users to log in with their email instead of their username. Usernames and emails are always matched regardless
of case, as they are stored in lowercase.

### password

{{< confkey type="structure" required="no" >}}

The password hashing options for passwords set by Authelia, with the same options as the
[file backend](file.md#password-options). Passwords imported as digests (for example from another identity provider)
are kept in their own algorithm and still work.

## Users

- Usernames are lowercase, start with a letter or digit, contain only letters, digits, `.`, `_`, `@`, and `-`, and can't
  be changed. A deleted username can never be used again, so a new user can't inherit anything still keyed by it.
- The email is required and unique, also across usernames when the email search is enabled.
- A disabled user can't log in, and disabling or deleting a user also revokes its OpenID Connect 1.0 tokens, consent,
  portal sessions, and pending email links. Tokens of a user who is no longer permitted are refused by the token,
  userinfo, and introspection endpoints.
- The user details are read from the database at every request (`refresh_interval` is `always`), so changes apply at
  once.
- New users can be invited by email with the administration API: the link lets them set a password and register a
  passkey.

## Keys

The HMAC key which signs the users and memberships is created in the storage database on first use, encrypted with the
storage encryption key. It can be rotated with
[authelia storage encryption rotate hmac authentication-user](../../reference/cli/authelia/authelia_storage_encryption_rotate_hmac_authentication-user.md),
which signs every row again and changes nothing if any row's signature isn't valid.

## Migrating from Keycloak

See [authelia users import keycloak](../../reference/cli/authelia/authelia_users_import_keycloak.md) and the
[guide](../../reference/guides/migrating-from-keycloak.md).
