<!--
SPDX-FileCopyrightText: 2026 SGNL fork contributors

SPDX-License-Identifier: Apache-2.0
-->

# SGNL's Authelia fork

This is a fork of [authelia/authelia](https://github.com/authelia/authelia), branch `sgnl`, kept in sync with upstream
`master`. It adds what SGNL needs to run its login on Authelia alone: users in the database, an admin API, invite onboarding,
revocation, and a SAML IdP. **Not affiliated with or endorsed by the Authelia project.** For Authelia itself, use
upstream.

Branches:

- `sgnl`: the fork (default branch). Releases are tagged `v<upstream version>-sgnl.<n>`.
- `master`: an untouched mirror of upstream `master`, or absent. Never commit to it.

## Principles

Decided by igor on 2026-11-23. They replace the earlier "thin seams" approach.

1. **Built as a native part of Authelia.** Features use Authelia's own packages, naming, config structure,
   database and migration track, as if upstream had designed them. There are no fork-only namespaces, files or
   config sections. The aim is the best architecture, not the smallest diff.
2. **One database, one migration track.** New tables are ordinary migrations in
   `internal/storage/migrations/<engine>/` for all three engines (upstream's tests require the same versions for all).
   **Numbering rule:**
   - Until a production database exists (cutover, M5): fork migrations stay numbered last. When a sync brings in
     upstream migrations, renumber ours after them.
   - After cutover: fork numbers are frozen, and incoming upstream migrations are renumbered after ours (with a
     check that they still apply).
   - Upstream's contiguity test (`internal/storage/migrations_test.go`) turns the nightly drift check red on a
     collision.
3. **Kept in sync with upstream `master`** (assumed to continue): merges, weekly and on releases. Syncs will conflict
   more often than with a thin fork; that cost is accepted. When upstream ships an equivalent feature, we compare the
   two and switch to theirs if we're ready to merge into it.
4. **Existing per-user data stays keyed by username.** No re-keying of upstream tables or foreign keys onto them.
5. **API first.** An admin REST API and a CLI are the product; a web admin UI is optional.
6. **Production runs on SQLite** (igor, 2026-11-23). PostgreSQL and MySQL stay supported and tested in CI.

## Changes from upstream

Every feature the fork adds or changes, with the upstream files it touches. Each sync checks this list.

| Feature | Upstream files changed | Since |
|---|---|---|
| Multi-segment server path (`server.address` path such as `/realms/<realm>`, keeps Keycloak's issuer) | `internal/configuration/validator/{server.go,const.go,server_test.go}`, `internal/configuration/provider_test.go`, `internal/middlewares/strip_path_test.go` | 2026-11-23 |
| Admin API authorization: scopes `authelia.admin.read` / `authelia.admin.write`; middleware `RequireBearerClientCredentials` admits only client-credentials Access Tokens with the route's scope and the audience `<issuer>/api/admin`; validator requires such clients to be confidential, `client_credentials`-only, admin-scopes-only, with an audience or resource; first route `GET /api/admin/whoami` | `internal/oidc/const.go`, `internal/middlewares/{require_bearer.go,const.go}`, `internal/handlers/{handler_admin.go,handler_admin_test.go}`, `internal/server/{handlers.go,const.go}`, `internal/configuration/validator/{identity_providers.go,const.go,identity_providers_test.go}` | 2026-11-23 |
| Users in the database, storage layer: tables `authentication_users`, `authentication_groups`, `authentication_user_groups`, `authentication_users_deleted` (migration V0035); usernames and emails stored lowercase; users and memberships HMAC-signed (key `authentication_user`, rotated by `authelia storage encryption rotate hmac authentication-user`, which aborts instead of deleting); deleted usernames never reused | `internal/storage/migrations/{sqlite,postgres,mysql}/V0035.AuthenticationUsers.*.sql`, `internal/storage/{migrations_test.go,const.go,errors.go,provider.go,sql_provider.go,sql_provider_backend_postgres.go,sql_provider_encryption.go,sql_provider_queries.go,sql_provider_authentication_users.go,sql_provider_authentication_users_test.go}`, `internal/model/authentication_user.go`, `internal/mocks/storage.go`, `internal/commands/{const.go,storage.go,storage_run.go}`, `docs/content/reference/cli/authelia/authelia_storage_encryption_rotate_hmac{,_authentication-user}.md` | 2026-11-23 |

Fork-only build files: `FORK.md`, `sgnl/` (image, CI scripts), `.github/workflows/sgnl-*.yml`, `.github/actions/sgnl-checkout/`.

## Backlog

Planned work that isn't started yet.

- **MCP login support** (for SGNL's MCP gateway; Keycloak 26.8.2's experimental `cimd:v1` is the reference):
  - Client ID Metadata Documents (CIMD): the `client_id` is an HTTPS URL to the client's metadata, so MCP clients log
    in without registering first; advertise `client_id_metadata_document_supported` in discovery.
  - Resource indicators / audience for the gateway's `/mcp` URL.
  - RFC 8693 token exchange: the gateway trades a user's token (audience = gateway) for a short-lived per-app token for
    the same user.

## Build

- CI: `.github/workflows/sgnl-ci.yml` runs Go tests with `-race`, golangci-lint, REUSE and yamllint, and the frontend
  build, tests and ESLint. It runs every migration up, one version down, and up again on real PostgreSQL and MySQL
  (upstream's unit tests only execute the SQLite SQL). It also builds the linux/amd64 image. It mirrors what upstream's Buildkite pipeline runs
  (`authelia-scripts ci`, `.buildkite/steps/lint.sh`).
- Nightly drift check: `.github/workflows/sgnl-upstream-nightly.yml` merges upstream `master` into `sgnl` inside the
  runner (never pushed) and runs the same CI. A red run means the next sync has work.
- Image: `sgnl/Dockerfile` builds the frontend and backend from source as a production build (no `dev` tag, version
  stamped by build args). Build it from the repository root:

  ```sh
  docker buildx build --platform linux/amd64 -f sgnl/Dockerfile \
    --build-arg BUILD_TAG=v4.40.0-sgnl.1 --build-arg BUILD_COMMIT="$(git rev-parse HEAD)" -t authelia-sgnl .
  ```

- Upstream's own workflows on the fork:
  - disabled in the Actions settings: `scorecard`, `pr-commentary`, `pr-labels`, `contributors` (upstream-only);
  - left active: `codeql-analysis` (weekly), `slsa` (fires only on upstream-style `vX.Y.Z` tags);
  - the files themselves are untouched.
- Local Go: the toolchain is pinned in `go.mod`. Use `mise x go@1.27.4 -- go ...` so that no tool file lands in the tree.
  Lint like CI: `mise x go@1.27.4 golangci-lint@2.15.0 -- golangci-lint run`.

## Sync log

Merge upstream `master` into `sgnl` at least weekly and on every upstream release. Merge, don't rebase.

| Date | Upstream commit | Result | Notes |
|---|---|---|---|
| 2026-11-23 | `b935f93f` (master, 2026-11-23) | fork point | `sgnl` created at this commit |

## Verified facts

Checks run against upstream code. Each fact names the commit it was checked on.

### CI environment

- **Upstream unit tests depend on the time zone** (2026-11-23, `b935f93f`). `internal/model` fails under `TZ=UTC`
  (`TestWebAuthnCredential`, `TestNewOAuth2DeviceCodeSessionFromRequest`) and under `Europe/Berlin` (the latter only).
  It passes under `Australia/Melbourne`, which is apparently the zone of upstream's Buildkite agents, where the same
  commit is green. The fork's CI sets `TZ=Australia/Melbourne` for the Go tests. Worth reporting upstream.
- **Flaky upstream test:** `internal/authentication` `TestShouldNotStartReloadCooldownWhenContentUnchanged` depends on
  timing. It failed once on a GitHub runner with `-race` (2026-11-23) and passed 6 of 6 locally. Re-run before
  investigating.

### M0 checks (on `b935f93f`)

Test setup: an untouched master binary, plus one scratch build for check 1 that is not committed. The Keycloak data is
from a local Keycloak 26.8.2 with a throwaway user, same password policy as production. No production data was used.

1. **Issuer under a two-segment base path (`/realms/<realm>`): not possible on untouched master.**
   - `server.address` with path `/realms/<realm>` is rejected by the validator
     (`internal/configuration/validator/server.go:116`: "must be a single subpath"). The validator also requires an
     alphanumeric path, so a realm name with `-` fails as well.
   - The router has no such limit: `middlewares.StripPath` matches the whole prefix with a regular expression.
   - With only the validator relaxed (scratch build), the following works under the two-segment prefix:
     - discovery reports `issuer` = `https://<host>/realms/<realm>`, and all endpoints are under it;
     - a full authorization code flow (first factor, consent, code, token) returns an ID token with
       `iss` = `https://<host>/realms/<realm>`.
   - Login portal: verified 2026-11-23 with the fork patch. The full image (real frontend) under
     `/realms/mimi-insights` was driven by headless Chrome (Playwright) through authorize, login page, password,
     consent page and redirect with code. No failed requests (assets, API). Other portal pages (reset password,
     settings) are not tested yet.
   - Caveat: the server also answers on `/` with issuer `https://<host>`, so the reverse proxy must route only the
     prefix (or redirect `/` to it).
   - Consequence: keeping the Keycloak issuer needs a change to the validator. igor approved it on 2026-11-23, and it is
     done (see "Changes from upstream").
2. **Keycloak password hashes: usable as-is.**
   - Keycloak 26.8.2 stores argon2id, v=19, m=7168, t=5, p=1, 32-byte hash, with salt and hash as standard base64 in
     `secret_data`.
   - Converted to PHC (`$argon2id$v=19$m=7168,t=5,p=1$<salt>$<hash>`, `=` padding removed), it verifies:
     - `authelia crypto hash validate` matches the right password and rejects a wrong one;
     - first-factor login works with the hash in the user file.
   - No password reset is needed for migrated users.
3. **Identifiers (`sub`): Keycloak user UUIDs can be kept.**
   - `authelia storage user identifiers import` accepts any UUID verbatim (service `openid`, empty `sector_id`).
   - After import, an authorization code flow returns an ID token with `sub` equal to the Keycloak user ID.
   - Apps that link accounts by `sub` keep their accounts.
4. **Passkeys: importable, with two steps the import CLI doesn't do. Verified from source; the end-to-end login test
   belongs to M4 (C8 rehearsal).**
   - **User handle.**
     - Keycloak registers the UTF-8 bytes of the Keycloak user ID as the WebAuthn user handle
       (keycloak 26.8.2 `WebAuthnRegister.java:156`).
     - Authelia's passkey (discoverable) login looks up `string(userHandle)` in `webauthn_users.userid`
       (`internal/handlers/webauthn.go`, `handlerWebAuthnDiscoverableLogin`).
     - `storage user webauthn import` doesn't write `webauthn_users`. So the C8 import must insert
       `(rpid, username, userid = <Keycloak user ID>)` itself, before the user's first passkey login (otherwise Authelia
       creates a random handle).
   - **Field mapping.**
     - Keycloak `credentialId` is standard base64, which matches Authelia's `kid`.
     - Keycloak `credentialPublicKey` is base64url CBOR of the COSE key (keycloak 26.8.2
       `CredentialPublicKeyConverter.java`, `convertToDatabaseColumn`). It must be re-encoded as standard base64 for
       `public_key`.
     - `aaguid`, `counter` and `transports` map directly.
     - `rpid` must be the same host as Keycloak's RP ID.
   - **Backup Eligible flag.**
     - go-webauthn rejects a login whose BE flag differs from the stored one
       (`webauthn/login.go:403`, "Backup Eligible flag inconsistency").
     - Keycloak doesn't store BE/BS, so C8 must set `backup_eligible` per credential: true for synced passkeys
       (iCloud Keychain, Google Password Manager; known by AAGUID).
     - A wrong value means the login is refused, not let through. Fallback: the user registers the passkey again
       (invite, C4).
   - **Discoverable flag.** With `webauthn.enable_passkey_upgrade` off (the default), passkey login loads only
     credentials with `discoverable = TRUE` (`internal/handlers/webauthn.go`, `LoadWebAuthnPasskeyCredentialsByUsername`;
     `internal/storage/sql_provider_queries.go:270,275`). C8 must set `discoverable: true` for Keycloak's passwordless
     credentials.
5. **Login matrix of SGNL's apps (config study; the live login test is M1/M4).**
   - There are 12 OIDC clients. The details, with real hostnames, are in SGNL's private instance repo.
   - **Unchanged or Authelia-config only (6):**
     - Vaultwarden: stores `<issuer>/<sub>`. The stored issuer has no trailing slash, which is the same form Authelia
       emits in check 1.
     - Bulwark and the Stalwart web UI: opaque access tokens validated via userinfo, which is Authelia's default.
     - Forgejo and Dashy: read `groups` from the ID token, so they need a `claims_policy` that puts `groups` (and
       email/name) into the ID token. By default Authelia's ID token carries no profile claims (verified in check 1's
       flow).
     - listmonk: links by email.
   - **App config change (1):** Grafana hardcodes Keycloak's `/protocol/openid-connect/*` URLs. Its sign-out URL has no
     Authelia equivalent until RP-initiated logout (authelia/authelia#13809).
   - **Need specific client settings (4 OpenCloud clients):**
     - The app verifies access tokens as JWTs, so set `access_token_signed_response_alg: RS256` per client.
     - The desktop client relies on Keycloak's `http://127.0.0.1/*` wildcard. Authelia accepts any loopback port for
       public/native clients (`authelia.com/provider/oauth2` `uri.go` `isMatchingLoopbackURI`), but the path must match
       exactly, so register the exact paths.
   - **Breaks by design (1):** the agent's client-credentials client calls Keycloak's admin REST API. It needs the fork's
     admin API (C3, M1).
   - Also to rebuild in Authelia config:
     - the group gates, as `authorization_policies`;
     - `offline_access` and refresh for 5 clients;
     - per-client token endpoint auth method, because Keycloak accepts both basic and post while Authelia pins one.
6. **Image: builds for linux/amd64** from `sgnl/Dockerfile` (local buildx, `build-info` reports linux/amd64,
   untagged clean, extra `sgnl`).
