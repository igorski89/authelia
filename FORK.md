<!--
SPDX-FileCopyrightText: 2026 SGNL fork contributors

SPDX-License-Identifier: Apache-2.0
-->

# SGNL's Authelia fork

This is a fork of [authelia/authelia](https://github.com/authelia/authelia), branch `sgnl`, kept in sync with upstream
`master`. It adds what SGNL needs to run its login on Authelia alone: users in SQLite, an admin API, invite onboarding,
revocation, and a SAML IdP. **Not affiliated with or endorsed by the Authelia project.** For Authelia itself, use
upstream.

Branches:

- `sgnl`: the fork (default branch). Releases are tagged `v<upstream version>-sgnl.<n>`.
- `master`: an untouched mirror of upstream `master`, or absent. Never commit to it.

## Principles

1. **Upstream-shaped.** Fork features sit behind upstream's own interfaces and designs (user provider, the user
   management interface proposed in authelia/authelia#12654, session repository, identity verification), so each can
   converge when upstream ships its version.
2. **Own migration track.** Fork tables live in a second track (table `sgnl_migrations`, files under
   `internal/storage/migrations/sgnl/`), run right after upstream's. Fork tables are prefixed `sgnl_`. Fork migrations
   never alter upstream tables or use upstream's version numbers.
3. **No carried open upstream PRs.** Upstream code arrives only through the sync, once merged. Where we need an open
   PR's feature, we mirror its interface in our own package.
4. **SQLite only** for fork code, written in portable SQL.
5. **Own config namespace:** a top-level `sgnl:` key. The only exception is `authentication_backend.sgnl_sql`.
6. **New packages, thin seams.** Fork code lives in `internal/sgnl/...`. Upstream files get registration lines only, and
   every touched upstream file is listed below.
7. **API first.** An admin REST API and a CLI are the product; a web admin UI is optional.

## Touched upstream files

Every upstream file the fork changes, with the reason. Each sync checks this list. Keep it short.

| File | Change | Since |
|---|---|---|
| _(none yet)_ | | |

Fork-only files (no upstream counterpart): `FORK.md`, `sgnl/`, `.github/workflows/sgnl-*.yml`,
`.github/actions/sgnl-checkout/`.

## Build

- CI: `.github/workflows/sgnl-ci.yml` runs Go tests with `-race`, golangci-lint, REUSE and yamllint, and the frontend
  build, tests and ESLint. It also builds the linux/amd64 image. It mirrors what upstream's Buildkite pipeline runs
  (`authelia-scripts ci`, `.buildkite/steps/lint.sh`).
- Nightly drift check: `.github/workflows/sgnl-upstream-nightly.yml` merges upstream `master` into `sgnl` inside the
  runner (never pushed) and runs the same CI. A red run means the next sync has work.
- Image: `sgnl/Dockerfile` builds the frontend and backend from source as a production build (no `dev` tag, version
  stamped by build args). Build it from the repository root:

  ```sh
  docker buildx build --platform linux/amd64 -f sgnl/Dockerfile \
    --build-arg BUILD_TAG=v4.40.0-sgnl.1 --build-arg BUILD_COMMIT="$(git rev-parse HEAD)" -t authelia-sgnl .
  ```

- Local Go: the toolchain is pinned in `go.mod`. Use `mise x go@1.27.4 -- go ...` so that no tool file lands in the tree.

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
   - Caveat: the server also answers on `/` with issuer `https://<host>`, so the reverse proxy must route only the
     prefix.
   - Consequence: keeping the Keycloak issuer needs a fork change to one upstream file (the validator). It is a candidate
     for M1, listed under "Touched upstream files" once made. Upstream may accept it (multi-segment base paths).
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
     - Keycloak `credentialPublicKey` is base64url COSE (webauthn4j), which must be re-encoded as standard base64 for
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
5. **Image: builds for linux/amd64** from `sgnl/Dockerfile` (local buildx, `build-info` reports linux/amd64,
   untagged clean, extra `sgnl`).
