---
# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

title: "Migrating from Keycloak"
description: "A guide to moving the users, groups, passwords, and passkeys of a Keycloak realm to Authelia's database authentication backend."
summary: "Moving a Keycloak realm's users, groups, passwords, and passkeys to Authelia so users and apps notice no change."
date: 2026-11-24T00:00:00+01:00
draft: false
images: []
weight: 221
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

[authelia users import keycloak](../cli/authelia/authelia_users_import_keycloak.md) imports a Keycloak realm export
into the [database authentication backend](../../configuration/first-factor/database.md): the groups, the users with
their memberships, their password hashes, and their WebAuthn credentials. Users keep their passwords and passkeys, and
apps see the same users.

## What carries over

| Keycloak                                 | Authelia                                                                 |
|:-----------------------------------------|:-------------------------------------------------------------------------|
| User ID                                  | OpenID Connect 1.0 subject (`sub`) for clients with public subjects, and the WebAuthn user handle |
| Username, email, first and last name     | Username, email, given and family name, display name                     |
| Enabled                                  | Disabled when not enabled                                                |
| Groups (top level)                       | Groups and memberships                                                   |
| `password` (argon2, pbkdf2)              | The same hash as a PHC digest                                            |
| `webauthn`, `webauthn-passwordless`      | WebAuthn credentials with their sign counts (second factor, or passkey)  |
| `password-history`                       | Ignored                                                                  |
| `otp`, subgroups, federated users        | Not imported (the import fails unless `--skip-unsupported`)              |
| Service account users                    | Skipped                                                                  |

Keycloak doesn't keep the backup flags of WebAuthn credentials; an imported credential takes them from its first sign
in.

## Steps

1. **Serve Authelia where Keycloak was.** Keep the hostname, so the WebAuthn RP ID stays the same, and keep the realm's
   URLs with a `server.address` path such as `/realms/<realm>`: the OpenID Connect 1.0 issuer then doesn't change. For
   SAML service providers enable [enable_keycloak_endpoints](../../configuration/identity-providers/saml.md#enable_keycloak_endpoints),
   and keep the realm's signing key and certificate, which service providers have pinned.
2. **Export the realm** with its users in the same file, with the Keycloak which holds them stopped or a copy of its
   database:

   ```bash
   kc.sh export --realm <realm> --users same_file --file /export/realm.json
   ```

   The stock Keycloak image runs as uid 1000, so the export directory must be writable by it. The export also holds the
   realm's keys and client secrets: keep it as a secret and delete it after the import, which only reads the users and
   groups.
3. **Dry run** against an empty Authelia database (`authelia storage migrate up` first), and compare the counts with
   Keycloak's:

   ```bash
   authelia users import keycloak /export/realm.json --webauthn-rpid auth.example.com --config configuration.yml
   ```

   The dry run imports everything in a transaction which is rolled back, so it finds conflicts and unsupported data
   without changing anything.
4. **Import** with `--apply`. Everything is imported in one transaction, or nothing.
5. **Check** a login with a password and a passkey, and that an app sees the same `sub` as before.

The `--webauthn-rpid` must be the RP ID the passkeys were registered for: the realm's WebAuthn policy RP ID if it set
one, otherwise Keycloak's hostname. The import refuses an RP ID which differs from the realm's, or which the
configuration doesn't use.
