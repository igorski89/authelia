---
# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

title: "Administration API"
description: "A guide to the administration API, which manages the users and groups of the database authentication backend."
summary: "The administration API manages the users and groups of the database authentication backend with OAuth 2.0 client credentials."
date: 2026-11-24T00:00:00+01:00
draft: false
images: []
weight: 220
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The administration API manages the users and groups of the [database authentication backend](../../configuration/first-factor/database.md).
It is served below `/api/admin` when the [OpenID Connect 1.0 Provider](../../configuration/identity-providers/openid-connect/provider.md)
and the database backend are configured, and documented route by route in the OpenAPI specification at `/api/openapi.yml`
(tag `Administration`). The [authelia users](../cli/authelia/authelia_users.md) and
[authelia groups](../cli/authelia/authelia_groups.md) commands make the same changes with the same rules.

## Authorization

Every request carries an Access Token of the client credentials grant as a Bearer token:

- the token must be granted the audience of the issuer followed by `/api/admin`;
- reading needs the `authelia.admin.read` scope, changing needs `authelia.admin.write` (which doesn't imply reading).

The client must be confidential, may only use the client credentials grant, and may only have these scopes:

```yaml {title="configuration.yml"}
identity_providers:
  oidc:
    clients:
      - client_id: 'admin-agent'
        client_secret: '$pbkdf2-sha512$310000$...'
        grant_types: ['client_credentials']
        response_types: []
        redirect_uris: []
        scopes: ['authelia.admin.read', 'authelia.admin.write']
        audience: ['https://auth.example.com/api/admin']
        token_endpoint_auth_method: 'client_secret_basic'
```

```bash
curl -s -u admin-agent:secret https://auth.example.com/api/oidc/token \
  -d grant_type=client_credentials -d 'scope=authelia.admin.read authelia.admin.write' \
  -d audience=https://auth.example.com/api/admin
curl -s -H "Authorization: Bearer $TOKEN" https://auth.example.com/api/admin/users
```

## Routes

| Route                                                     | Scope   | Purpose                                                    |
|:----------------------------------------------------------|:--------|:-----------------------------------------------------------|
| `GET /api/admin/whoami`                                   | either  | The client and scopes of the token                         |
| `GET, POST /api/admin/users`                              | r, w    | List users, create a user                                  |
| `GET, PATCH, DELETE /api/admin/users/{username}`          | r, w, w | A user with its credentials and sessions; change; delete  |
| `PUT, DELETE /api/admin/users/{username}/password`        | w       | Set a password or PHC digest; remove the password          |
| `PUT, DELETE /api/admin/users/{username}/groups/{group}`  | w       | Add to or remove from a group                              |
| `POST /api/admin/users/{username}/logout`                 | w       | Revoke tokens and consent (optionally of one `client_id`), and portal sessions |
| `POST /api/admin/users/{username}/invite`                 | w       | Mail a one-time link to set a password and a passkey       |
| `GET, POST /api/admin/groups`                             | r, w    | List groups, create a group                                |
| `DELETE /api/admin/groups/{group}`                        | w       | Delete a group and its memberships                         |
| `GET /api/admin/groups/{group}/members`                   | r       | The members of a group                                     |
| `GET /api/admin/audit`                                    | r       | Changes, newest first, with the actor                      |
| `GET /api/admin/events`                                   | r       | Authentication attempts, newest first                      |

Errors are JSON objects with `error` set to `invalid_request` (400), `not_found` (404), `conflict` (409), or
`server_error` (500). Every change is recorded in the audit with the client as the actor.

Disabling or deleting a user revokes its tokens, consent, portal sessions, and pending links. Invited users finish their
setup at `/account-setup`, which needs `identity_validation.reset_password.jwt_secret` and a notifier.
