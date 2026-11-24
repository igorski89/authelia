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
   - **Cutover freeze (agreed with sgnl-01, 2026-11-24):** only announced fixes are released until M5, and upstream
     syncs wait until after it. The cutover candidate is `v4.40.0-sgnl.9` (the security review fixes, with migration
     V0039), after `sgnl.8`.
3. **Kept in sync with upstream `master`**: merged by hand from time to time (igor, 2026-11-23). Syncs will conflict
   more often than with a thin fork; that cost is accepted. When upstream ships an equivalent feature, we compare the
   two and switch to theirs if we're ready to merge into it.
4. **Existing per-user data stays keyed by username.** No re-keying of upstream tables or foreign keys onto them.
5. **API first.** An admin REST API and a CLI are the product; a web admin UI is optional.
6. **Production runs on SQLite** (igor, 2026-11-23). PostgreSQL and MySQL stay supported and tested in CI.

## Changes from upstream

Every feature the fork adds or changes, with the upstream files it touches. Each sync checks this list.

| Feature | Upstream files changed | Since |
|---|---|---|
| Multi-segment server path (`server.address` path such as `/realms/<realm>`, keeps Keycloak's issuer; segments of ASCII letters, digits, `-` and `_`, since sgnl.9) | `internal/configuration/validator/{server.go,const.go,server_test.go}`, `internal/configuration/provider_test.go`, `internal/middlewares/strip_path_test.go` | 2026-11-23 |
| Admin API authorization: scopes `authelia.admin.read` / `authelia.admin.write`; middleware `RequireBearerClientCredentials` admits only client-credentials Access Tokens with the route's scope and the audience `<issuer>/api/admin`; validator requires such clients to be confidential, `client_credentials`-only, admin-scopes-only, with an audience or resource; first route `GET /api/admin/whoami` | `internal/oidc/const.go`, `internal/middlewares/{require_bearer.go,const.go}`, `internal/handlers/{handler_admin.go,handler_admin_test.go}`, `internal/server/{handlers.go,const.go}`, `internal/configuration/validator/{identity_providers.go,const.go,identity_providers_test.go}` | 2026-11-23 |
| Users in the database, storage layer: tables `authentication_users`, `authentication_groups`, `authentication_user_groups`, `authentication_users_deleted` (migration V0035); usernames and emails stored lowercase; users and memberships HMAC-signed (key `authentication_user`, rotated by `authelia storage encryption rotate hmac authentication-user`, which aborts instead of deleting); deleted usernames never reused; a row put back for a deleted username is treated as not found (sgnl.9). Limit: the signatures stop edits and forged rows, not putting back a whole older row of a user who still exists, such as a removed group membership, from an old copy of the database; write access to the database is outside what they protect | `internal/storage/migrations/{sqlite,postgres,mysql}/V0035.AuthenticationUsers.*.sql`, `internal/storage/{migrations_test.go,const.go,errors.go,provider.go,sql_provider.go,sql_provider_backend_postgres.go,sql_provider_encryption.go,sql_provider_queries.go,sql_provider_authentication_users.go,sql_provider_authentication_users_test.go}`, `internal/model/authentication_user.go`, `internal/mocks/storage.go`, `internal/commands/{const.go,storage.go,storage_run.go}`, `docs/content/reference/cli/authelia/authelia_storage_encryption_rotate_hmac{,_authentication-user}.md` | 2026-11-23 |
| Database authentication backend: `authentication_backend.database` (`password` like the file backend, `search.email`); provider `DatabaseUserProvider` (disabled, missing, or tampered users are "not found"; no cache; `refresh_interval` defaults to `always`); the `debug` commands don't support it yet (no storage there) | `internal/configuration/schema/{authentication.go,keys.go}`, `internal/configuration/validator/{authentication.go,authentication_test.go,const.go}`, `experimental/embed/config_test.go`, `internal/authentication/{database_user_provider.go,database_user_provider_test.go}`, `internal/middlewares/{util.go,util_test.go}`, `internal/commands/debug.go`, `internal/expression/user_attributes.go`, `internal/storage/errors.go` | 2026-11-23 |
| User management: package `internal/management` (validation, password policy or PHC digest import (hash schemes only, never `$plaintext$`/`$base64$`), atomic create with groups, delete with second factors and links in one transaction); CLI `authelia users {list,get,create,update,password,delete}` and `authelia groups {list,create,delete,members,add,remove}` | `internal/management/{users.go,users_test.go}`, `internal/commands/{users.go,storage.go,root.go}` (`addStoragePersistentFlags` extracted from `newStorageCmd`) | 2026-11-23 |
| Admin API for users and groups (registered only with OIDC and the database backend): `GET/POST /api/admin/users`, `GET/PATCH/DELETE /api/admin/users/{username}`, `PUT/DELETE /api/admin/users/{username}/password`, `PUT/DELETE /api/admin/users/{username}/groups/{group}`, `GET/POST /api/admin/groups`, `DELETE /api/admin/groups/{group}`, `GET /api/admin/groups/{group}/members`; reads need `authelia.admin.read`, changes `authelia.admin.write`; JSON errors `invalid_request` 400, `not_found` 404, `conflict` 409, `server_error` 500 (no details); every change is logged with the client id; documented in the OpenAPI spec | `internal/handlers/{handler_admin.go,handler_admin_test.go}`, `internal/server/{handlers.go,template.go}`, `api/openapi.yml` (tag, paths, `components.responses`, schemas, `admin_bearer` scheme) | 2026-11-23 |
| Revoke everything of a user (C5): `management.Service.RevokeUser` revokes the user's OAuth 2.0 / OpenID Connect 1.0 sessions (access, refresh, authorization code, device code, PKCE, OpenID Connect) and pre-configured consent for every subject identifier (public and pairwise), optionally for one client only, and destroys its portal sessions on every cookie domain (`session.Provider.{CountByUsername,DestroyByUsername}`); a full logout also revokes pending email links and one-time codes (identity verifications, such as invites). Disable and delete run it in their own transaction, so re-enabling a user doesn't bring old tokens back. Since sgnl.9 a revocation also writes a mark (table `user_revocations`, migration V0039, per user and optionally per client) in the same transaction, and the portal (`AutheliaCtx.GetSession` and `SessionUnlessRevoked` wherever a handler loads the session itself, such as the OpenID Connect 1.0 authorization endpoint and the password change, and forward auth; by the login time) and the token endpoint, introspection, userinfo, and bearer forward auth (by the exact time of the grant's authorization request, so a portal session which a logout of one client leaves may authorize that client again) refuse a session or grant from before the mark: a session or token which a request already running saves after the revocation dies at its next use, not atomically (portal login times have a resolution of a second, so a login in the same second as the revocation counts as after it). A mark keeps the later time on every engine. `POST /api/admin/users/{username}/logout` (optional `client_id`), CLI `authelia users logout [--client-id]` (the CLI reaches portal sessions only when they are kept in the database, the default). `GET /api/admin/users/{username}` also reports `credentials` and `sessions`; group members are user objects | `internal/session/{types.go,provider.go,provider_test.go}`, `internal/storage/{provider.go,sql_provider_oauth2_revoke_user.go,sql_provider_oauth2_revoke_user_test.go,sql_provider_user_revocations.go}`, `internal/storage/migrations/{sqlite,postgres,mysql}/V0039.UserRevocations.*.sql`, `internal/model/user_revocation.go`, `internal/middlewares/{user_revocation.go,authelia_context.go}`, `internal/handlers/{handler_authz_authn.go,handler_oauth2_token.go,handler_oauth2_introspection.go,handler_oauth2_oidc_userinfo.go}`, `internal/mocks/{storage.go,authelia_context.go}` (no revocation marks by default), `internal/handlers/{handler_admin.go,handler_admin_test.go}`, `internal/server/handlers.go`, `internal/commands/users.go`, `api/openapi.yml` | 2026-11-23 |
| Audit and events (C7): table `administration_audit` (migration V0036); every change of the management service writes an entry in its own transaction with the actor (`client:<client id>` for the API, `cli:<OS user>` for the CLI; a change without an actor is refused), the action, the user or group, and details such as the changed fields (never a password or digest). `GET /api/admin/audit` and `GET /api/admin/events` (authentication attempts from `authentication_logs`), both with `username`, `limit`, `page`; CLI `authelia users audit [username]` | `internal/storage/migrations/{sqlite,postgres,mysql}/V0036.AdministrationAudit.*.sql`, `internal/storage/{migrations_test.go,provider.go,sql_provider_administration_audit.go}`, `internal/model/administration_audit.go`, `internal/mocks/storage.go`, `internal/management/{audit.go,audit_test.go,users.go,users_test.go}`, `internal/handlers/handler_admin.go`, `internal/server/handlers.go`, `internal/commands/users.go`, `api/openapi.yml` | 2026-11-23 |
| Invites (C4): `POST /api/admin/users/{username}/invite` (`lifespan`, default 72h, at most 30 days) mails a one-time link (identity verification with action `AccountSetup`, signed with `identity_validation.reset_password.jwt_secret`, which it requires) using the new `AccountSetup` email template, revokes earlier invites, audits `user.invite`, and never returns the link; a failed mail revokes it; disabled users can't be invited. The portal route `/account-setup` (the reset-password step 2 view with props) redeems it (`POST /api/account-setup/identity/finish`, rate-limited like reset finish) and sets the password (`POST /api/account-setup`, audited `user.setup` with the user as actor), then logs the user in with an elevated session, so the existing passkey registration needs no extra one-time code. The session keeps the link's identifier and the password step checks it again, and revoking a user's links (new invite, logout, disable, delete) also revokes used ones, so a half-finished setup ends when its link is revoked. Activating the user (groups) stays with the agent, as with Keycloak's finish-invite. API only: the CLI has no issuer or notifier. The link is used up when the page opens, so an abandoned setup needs a new invite | `internal/management/{invite.go,invite_test.go}`, `internal/handlers/{handler_account_setup.go,handler_admin_test.go}`, `internal/server/handlers.go`, `internal/session/{types_msgp.go,types_msgp_gen.go,user_session.go}` (`AccountSetupUsername`), `internal/templates/{const.go,types.go,provider.go,embed/notification/AccountSetup.*,src/index.tsx,src/emails/AccountSetup.tsx}`, `examples/templates/notifications/no-preview/AccountSetup.html`, `web/src/{App.tsx,constants/Routes.ts,services/Api.ts,services/AccountSetup.ts,views/AccountSetup/AccountSetup.tsx,views/ResetPassword/ResetPasswordStep2.tsx}`, `internal/server/locales/en/portal.json`, `api/openapi.yml` | 2026-11-23 |
| Default claims policy: `identity_providers.oidc.default_claims_policy` names a claims policy applied to every client without its own `claims_policy` (Keycloak puts groups, email and name in every ID token; without this, apps such as Grafana silently downgrade admins at cutover) | `internal/configuration/schema/{identity_providers.go,keys.go}`, `internal/configuration/validator/{identity_providers.go,identity_providers_test.go}` | 2026-11-23 |
| Tokens of users who are no longer permitted (any backend): the token endpoint refuses authorization code, refresh token, and device code grants for a user the provider reports as not found (deleted or disabled) with `invalid_grant`, userinfo answers 401 instead of the claims from when the token was issued, and introspection reports such a token inactive. Transient lookup errors are a server error, not a refusal. (Since M2, disabling a user also revokes its tokens, so re-enabling doesn't bring them back.) Already-issued JWT access tokens validated by apps themselves stay valid until they expire | `internal/handlers/{handler_oauth2_token.go,handler_oauth2_oidc_userinfo.go,handler_oauth2_introspection.go,handler_oauth2_token_user_test.go}` | 2026-11-23 |
| SAML 2.0 identity provider (C6), built on `authelia.com/provider/saml` (pinned commit `b4f25e2888ed`, unpublished; not upstream's own integration): `identity_providers.saml` (`key`, `certificate_chain`, `entity_id` (default: the issuer), `assertion_lifespan` (default 5m), `enable_keycloak_endpoints`, `service_providers` with `entity_id`, `assertion_consumer_service_urls` (https), `certificate` (requests must then be signed), `name_id_format` (`email`/`unspecified`, forced whatever the request asks, as Keycloak's "force name ID format"), `authorization_policy` (`one_factor`/`two_factor`, default `two_factor`), `groups` (others get `RequestDenied`), `sign` (`both`/`response`/`assertion`), `attributes` (only these are released)). Endpoints `/api/saml/metadata` and `/api/saml/sso` (HTTP-Redirect and HTTP-POST), and with `enable_keycloak_endpoints` also Keycloak's `/protocol/saml` and `/protocol/saml/descriptor`, which the metadata then publishes, so SPs moved from Keycloak (Stripe) keep their stored URLs. Served only at a configured session `authelia_url` (404 elsewhere, so the per-issuer identity providers are bounded). SP-initiated only. A pending request is kept in table `saml_flows` (migration V0037; login replaces the session) and goes through the portal's flow mechanism (`flow=saml`, `flow_id`); the resume endpoint consumes it once. The response page submits itself with one script allowed by its hash in the Content-Security-Policy. `ForceAuthn` ends the portal session and asks the user to log in again, and the resumed request is only answered for a login after it (sgnl.9; it was refused with `AuthnFailed` before). A requested authentication context is only refused when the session is weaker than every requested class (password < PasswordProtectedTransport < refeds MFA); stronger sessions and unranked classes are answered, as Keycloak doesn't enforce them (sgnl.9). The SAMLRequest is limited to 16 KB and the RelayState to 1 KB, the single sign-on endpoints are rate limited (`server.endpoints.rate_limits.saml_single_sign_on`), and the replay store, shared by every issuer, holds 262,144 request IDs (sgnl.9). Like OIDC flows, a flow ID isn't bound to the browser that started it (for the M4 review). The NameID policy check of the library is switched off as a whole (`nameIDPolicyEnforcer`), not just the format check (for the M4 review). Groups and email are read from the user at each request, and disabled or deleted users get no assertion. A resumed request whose session doesn't satisfy the SP gets 403 instead of another trip through the portal (no loop when the portal considers one factor complete, for users without second-factor methods). Documented in the OpenAPI spec (tag SAML 2.0). The portal resumes a SAML flow at once for a user who is already fully authenticated (a cross-site HTTP-POST request doesn't carry the Lax session cookie, so it arrives anonymous) | `go.mod`, `go.sum`, `internal/configuration/schema/{identity_providers.go,keys.go}`, `internal/configuration/validator/{identity_providers.go,identity_providers_saml.go,identity_providers_saml_test.go}`, `internal/samlidp/` (new), `internal/handlers/{handler_saml.go,response.go}`, `internal/middlewares/{types.go,util.go}`, `internal/server/{handlers.go,template.go,template_test.go}`, `api/openapi.yml`, `internal/storage/migrations/{sqlite,postgres,mysql}/V0037.SAMLFlows.*.sql`, `internal/storage/{migrations_test.go,provider.go,sql_provider_saml.go}`, `internal/model/saml_flow.go`, `internal/mocks/storage.go`, `web/src/{constants/SearchParams.ts,services/Api.ts,views/LoginPortal/LoginPortal.tsx}` | 2026-11-23 |
| Keycloak import (C8): `authelia users import keycloak <export.json> --webauthn-rpid <rp id> [--apply] [--skip-unsupported]` (management `Service.ImportKeycloak`) reads only the users and groups of a realm export (`kc.sh export --realm <r> --users same_file --file <f>`; the rest, such as realm keys and client secrets, is never decoded or printed) and imports, in one transaction: the groups (flat; subgroups are unsupported), the users with profile, enabled state, and memberships, the Keycloak user ID as the OpenID Connect 1.0 subject identifier (service `openid`, public sector, so apps keep their `sub`) and as the WebAuthn user handle (Keycloak's handle is the UTF-8 of the user ID, so resident passkeys match), password hashes as PHC strings (argon2id/i/d, pbkdf2-sha1/sha256/sha512, verified to match), password history ignored, and WebAuthn credentials (`webauthn` and `webauthn-passwordless`, with credential ID, COSE public key, AAGUID, transports, sign count) marked as imported. Without `--apply` the import runs in a rolled-back transaction (a dry run against the real database). Existing usernames, emails, or groups fail the whole import; OTP credentials, subgroups, federated users, non-UUID user IDs, usernames or emails Authelia can't hold, and unknown hash algorithms fail it unless skipped; a `--webauthn-rpid` other than the realm's WebAuthn RP ID or one the configuration uses is refused; service accounts are always skipped. Reports counts only, never secrets; audited `user.import` with the CLI actor. Management changes made within another change now join its transaction | `internal/management/{import_keycloak.go,import_keycloak_test.go,users.go,testdata/keycloak-realm-export.json}`, `internal/commands/users.go` | 2026-11-23 |
| Imported WebAuthn credentials adopt their backup flags: Keycloak doesn't keep the backup eligible (BE) and backup state flags, and go-webauthn refuses a sign in whose BE flag differs from the stored one, so every synced passkey (iCloud, Google) would fail after an import. Table `webauthn_credentials_imported` (migration V0038, keyed by credential ID, not a column of `webauthn_credentials`, which an upstream table rebuild could drop) marks imported credentials; when the stored BE flag differs from the assertion's, a marked credential takes the assertion's flags (covered by its signature) before validation, and the mark is removed once they are saved. Unmarked credentials keep the check, and matching flags don't even look up the mark. Both the second factor and the passkey sign in | `internal/storage/migrations/{sqlite,postgres,mysql}/V0038.WebAuthnCredentialsImported.*.sql`, `internal/storage/{migrations_test.go,provider.go,sql_provider_webauthn_imported.go}`, `internal/mocks/storage.go`, `internal/handlers/{webauthn.go,webauthn_test.go,webauthn_imported_test.go,handler_sign_webauthn.go,handler_firstfactor_passkey.go}` (`handlerWebAuthnDiscoverableLogin` takes the assertion) | 2026-11-23 |
| Implicit consent for offline access (deliberate, opt-in deviation from upstream's default): client option `consent_implicit_offline_access` (only with `consent_mode: implicit` on a confidential client; the validator refuses anything else). Upstream always shows the consent screen for an authorization code request with `offline` / `offline_access`, and its implicit grant drops those scopes, so apps which need refresh tokens showed consent at every login (Keycloak never asked). With the option, the administrator's configuration is the "other condition permitting offline access" of OpenID Connect Core 1.0 Section 11: the request is evaluated by upstream's `RequesterRequiresExplicitConsent` without its offline scopes (so `prompt=consent`, `prompt=login`, the bearer authorization scope, and any rule upstream adds later still require consent; a unit test compares with upstream), and the implicit grant also grants the requested offline scopes. Public clients keep upstream's behaviour (their identity can't carry the administrator's consent). Pre-configured consent is unchanged | `internal/configuration/schema/{identity_providers.go,keys.go}`, `internal/configuration/validator/{identity_providers.go,identity_providers_consent.go,identity_providers_consent_test.go}`, `internal/oidc/{client.go,client_policy.go,consent_offline_access.go,consent_offline_access_test.go}`, `internal/handlers/{handler_oauth2_authorization_consent_core.go,handler_oauth2_authorization_consent_implicit.go}` | 2026-11-24 |
| Docs for the fork's features: `configuration/first-factor/database.md`, `configuration/identity-providers/saml.md`, `default_claims_policy` (provider) and `consent_implicit_offline_access` (clients), the guides `reference/guides/administration-api.md` and `reference/guides/migrating-from-keycloak.md`, and the CLI reference of `authelia users` and `authelia groups` (generated; the generator's churn in other pages is not kept) | `docs/content/configuration/{first-factor/database.md,identity-providers/saml.md,identity-providers/openid-connect/provider.md,identity-providers/openid-connect/clients.md}`, `docs/content/reference/guides/{administration-api.md,migrating-from-keycloak.md}`, `docs/content/reference/cli/authelia/{authelia.md,authelia_users*.md,authelia_groups*.md}` | 2026-11-24 |

Fork-only build files: `FORK.md`, `sgnl/` (image, CI scripts, the end-to-end tests in `sgnl/e2e/`, and the browser test in
`sgnl/e2e/browser/`, run by hand as it needs Chrome and Docker), `.github/workflows/sgnl-*.yml`, `.github/actions/sgnl-checkout/`.

## Backlog

Planned work that isn't started yet.

- **SAML `ForceAuthn` interstitial** (see the M4 delta reviews): ask before ending the portal session for a forced
  login, so another site can't end it; or a per-service-provider `force_authn` option.
- **After M5, log clarity:** an implicit consent which can't be granted logs "the subject is null, the consent has
  already been granted, or the consent session is a pre-configured session", but the check is `!granted && now <
  expires_at`; name an expired consent separately (cost the rehearsal an hour, 2026-11-24).

- **MCP login support** (for SGNL's MCP gateway; Keycloak 26.8.2's experimental `cimd:v1` is the reference):
  - Client ID Metadata Documents (CIMD): the `client_id` is an HTTPS URL to the client's metadata, so MCP clients log
    in without registering first; advertise `client_id_metadata_document_supported` in discovery.
  - Resource indicators / audience for the gateway's `/mcp` URL.
  - RFC 8693 token exchange: the gateway trades a user's token (audience = gateway) for a short-lived per-app token for
    the same user.

## Build

- CI: `.github/workflows/sgnl-ci.yml` runs Go tests with `-race`, golangci-lint, REUSE and yamllint, and the frontend
  build, tests and ESLint. It runs every migration up, one version down, and up again on real PostgreSQL and MySQL,
  then manages users and groups with the CLI on both (`sgnl/ci-storage-engines.sh`; upstream's unit tests only execute
  the SQLite SQL). It also runs the end-to-end tests (`sgnl/e2e/run.sh`) against a live instance. It also builds the linux/amd64 image. It mirrors what upstream's Buildkite pipeline runs
  (`authelia-scripts ci`, `.buildkite/steps/lint.sh`).
- Nightly drift check: `.github/workflows/sgnl-upstream-nightly.yml` merges upstream `master` into `sgnl` inside the
  runner (never pushed) and runs the same CI. A red run means the next sync has work.
- Releases: pushing a tag `v<version>-sgnl.<n>` runs `.github/workflows/sgnl-release.yml`, which runs the CI and then
  publishes the image to `ghcr.io/igorski89/authelia:<tag>` (public, igor 2026-11-23) for linux/amd64 and linux/arm64
  (from `-sgnl.2`, igor 2026-11-23), each built on a native runner and joined into one multi-platform tag. `<version>` is the upstream
  release the build leads up to, so `v4.40.0-sgnl.1` is built from upstream `master` before 4.40.0.
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

Merge upstream `master` into `sgnl` by hand from time to time (igor, 2026-11-23). Merge, don't rebase. The nightly
drift check only reports whether the next merge would pass; it never pushes.

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
     `/realms/<realm>` was driven by headless Chrome (Playwright) through authorize, login page, password,
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

### M1 exit test (2026-11-23, `sgnl/e2e/run.sh`, also run by CI)

A live instance with the database backend and a throwaway SQLite database. The agent is a client-credentials client
with both admin scopes. 23 of 23 checks pass:

- the agent gets a token and creates a group;
- the agent imports a user with a Keycloak argon2id digest, and the user logs in by email with the Keycloak password;
- an app with a claims policy gets `groups`, `email`, `name`, and `preferred_username` in the ID token, and the
  issuer is the realm path;
- a JWT access token is issued where the client asks for one;
- introspection reports the user's access token active, then inactive once the agent disables the user;
- after the agent disables the user, the refresh token is refused;
- after the agent sets a new password, the old one is refused and the new one is accepted with the username in any
  case;
- after the agent deletes the user, the user can't log in and the username can't be reused;
- the admin API refuses a user's token, a request without a token, a browser session, a client without an admin
  scope, and an expired token.

Also verified by hand on a live instance: after a user is disabled, forward-auth and OIDC authorize on an existing
session are refused, userinfo with an existing access token returns 401, passkey login checks the user too (in the
code), and password reset sends nothing. A storage outage is not
mistaken for a deleted user: forward-auth returns an error and keeps the session (`handler_authz_authn.go`).

Not covered yet:

- **SGNL's real apps.** The login matrix against SGNL's apps is SGNL-side work and needs a published image.
- **The merge exercise.** Upstream `master` hasn't moved since the fork point, so the first real merge is still ahead;
  the nightly drift check will report it.
- **Upstream's integration suites** (`internal/suites`, Buildkite) are not run by the fork's CI. The unit tests are.
  The token, userinfo, and introspection changes are what those suites would exercise.
- **JWT access tokens** that an app validates itself stay valid after a disable until they expire. Keep their
  lifespans short (SGNL uses 5 minutes).

### M4 security review (2026-11-24, of `v4.40.0-sgnl.8`, three independent reviewers set up by sgnl-01)

No critical or high findings. Fixed in `sgnl.9`, each with a regression test which failed before the fix:

1. A `{CRYPT}`-prefixed plaintext digest stored the password: digests are refused by their decoded type.
2. Password reset links survived a logout (stored as typed) and an opened reset wasn't checked again: the canonical
   username is stored, and the link is checked again when the password is set.
3. Revocation races: revocation marks (V0039), see the C5 row; disable and delete revoke in their own transaction.
4. SAML: requested authentication contexts are only refused for a weaker session; `ForceAuthn` asks for a new login.
5. and 6. SAML pending requests and replay keys are bounded (size limits, rate limit, larger shared replay store).
7. A deleted user's row put back by hand isn't a user; what the signatures don't cover is documented.
8. An opened invite link which expired can't finish the setup.
- Low: exact admin audience; no reads by write-only tokens (empty `PATCH` refused, `204` without the read scope);
  generic 404/409 bodies; optimistic locking of user updates; import marks removed with their credential; no client IP
  in SAML assertions; ASCII-only server path segments.

Accepted, with the reviewers' agreement:

- A SAML flow ID isn't bound to the browser which started it, as with OpenID Connect 1.0 flows (not exploitable).
- The library's NameID policy check is off as a whole, for Stripe's forced emailAddress format.
- The SAML replay store is per process; a database store can follow after M5 if Authelia runs as several instances.
- The first verified assertion of an imported passkey sets its backup flags (signed, and limited to marked credentials).
- JWT access tokens which apps verify themselves stay valid until they expire (5 minutes).
- The SAML idle session timeout is the portal's, as for OpenID Connect 1.0.
- In-progress consent sessions aren't revoked: they need a portal session, which the revocation mark refuses.

Delta reviews of `sgnl.9` (2026-11-24, two reviewers): no critical or high findings. Fixed in `sgnl.10`: the OpenID
Connect 1.0 authorization endpoint and the password change checked no revocation mark (they load the session
themselves); bearer forward auth didn't either; grants are compared exactly; marks keep the later time (upsert);
userinfo fails closed; SAML requests in `SAMLRedirectQuery` and the body bypassed the size caps (a regression of
`sgnl.9`); only requests which keep a pending request count against the SAML rate limit; the common multi-factor
context classes are ranked and `better` is strict; an update of a user deleted meanwhile is not found.

Accepted for the cutover, reconsidered with the Stripe test:

- Logout CSRF through `ForceAuthn`: any page can end a user's portal session (not its app sessions or tokens) by
  sending the browser an unsigned `ForceAuthn` request for a service provider whose requests aren't signed, such as
  Stripe. Visible to the user and no access gained (low). The fix, an interstitial in the portal ("<service provider>
  asks you to sign in again: Continue / Cancel") where only the same-origin Continue ends the session, is on the
  backlog; whether Stripe sends `ForceAuthn` at all is seen in its captured request.
- The client IP is the first `X-Forwarded-For` value, as upstream: the proxy in front of Authelia must not pass a
  client's header through (SGNL's kamal-proxy has `forward_headers: false`, 2026-11-24).

### Consent tests (2026-11-24, `sgnl/e2e/m4_consent_test.py` in CI, 7 checks)

- implicit consent without offline_access: a code at once; with offline_access and without the option: the consent
  screen, as upstream;
- with the option: a code at once, a refresh token with `offline_access` granted, and a working refresh grant;
  `prompt=consent` still shows the consent screen; `prompt=none` gets a code.

### C8 Keycloak import tests (2026-11-23)

- **Fixture:** a synthetic Keycloak 26.8.2 realm export made by sgnl-01 (users alice-test, bob-test, carol-test; groups;
  argon2 passwords with Keycloak's default parameters; `webauthn` second-factor passkeys registered and used with Chrome's
  virtual authenticator, carol's resident, backup eligible, and backed up like a synced passkey). Stripped to users and
  groups in `internal/management/testdata/` and `sgnl/e2e/browser/fixtures/` (with the virtual credentials).
- **Unit (SQLite):** dry run keeps nothing; import; the argon2id hash matches the throwaway password; subject = Keycloak
  ID; WebAuthn user ID = Keycloak's user handle; imported mark; audit; a second import fails whole; unsupported data
  fails or is skipped and reported; PBKDF2-SHA256 conversion matches. Flag adoption rules (handlers).
- **CI on PostgreSQL and MySQL** (`sgnl/ci-storage-engines.sh`): dry run, import, groups, refused second import, audit,
  HMAC key rotation over the imported users.
- **Browser (`sgnl/e2e/browser/import_keycloak.sh`, by hand, 10 checks in two modes, each from an empty database):**
  - second factor (as in Keycloak): the image's CLI imports the export; every user logs in through the portal with the
    Keycloak password and the same virtual passkey; carol's synced style passkey logs in a second time;
  - passkey login (`enable_passkey_login` and `experimental_enable_passkey_upgrade`): carol signs in with her passkey
    alone, twice; alice and bob as above;
  - in each mode the flags were adopted exactly once, for carol only (second factor and passkey login handlers).
  - Keycloak ran at `localhost`, which Authelia can't serve (a cookie domain needs a period), so the test imports for the
    RP ID `id.example.com` and gives the virtual authenticator the same credentials (ID and key pair) for it.
- **Rehearsal (sgnl-01, SGNL's `tests/authelia-import/`, 2026-11-24):** identical dry run and import counts; every user
  logs in through an OIDC client with the Keycloak password and passkey; the ID token's `sub` is the Keycloak user ID,
  and `preferred_username`, `email`, and `groups` match the export.
- **RP ID:** the import refuses an RP ID which differs from the realm's `webAuthnPolicyRpId` (when set), and the CLI one
  which isn't the host of a configured `authelia_url` or a configured WebAuthn relying party. SGNL's production realm
  leaves both WebAuthn RP IDs empty (Keycloak used its hostname, which Authelia keeps), its hashes are all argon2, it
  has no credential types the import can't take, and its passkeys are second factor only (confirmed by sgnl-01,
  2026-11-24), so the import needs no `--skip-unsupported` and no passkey login.
- **Passkey login policy:** Keycloak's `webauthn` credentials are second factors, and are imported as such. With
  passkey login enabled, Authelia only offers them for passkey login with `experimental_enable_passkey_upgrade`.

### M3 SAML tests (2026-11-23, `sgnl/e2e/m3_saml_test.py` in CI with the local SP `sgnl/e2e/samlsp/`; `sgnl/e2e/browser/saml_passkey.mjs` by hand)

- **API (36 checks):**
  - metadata at both paths, entity ID = issuer, SSO URL = Keycloak's path;
  - an issuer which isn't a configured `authelia_url` gets 404;
  - an anonymous user is sent to the portal and resumed after login;
  - the response page is HTML with a hash-only CSP; NameID = email (emailAddress format); RelayState comes back;
  - only the configured attributes are released;
  - a resumed or unknown flow is refused; resuming with an insufficient session gets 403 (no loop);
  - an expired flow (aged in the database) is neither resumed after login nor at the resume endpoint;
  - `sign: both` signs the response and the assertion; metadata is XML;
  - HTTP-POST binding with a session answers at once;
  - step-up: a one-factor session is asked for the second factor at a `two_factor` SP;
  - with an SP certificate: unsigned and tampered requests get no assertion; signed ones do, for both bindings, with a
    session and through the portal;
  - a replayed request gets no second assertion;
  - an unregistered ACS URL gets no response;
  - groups and email are fresh with a live session (removed from the group: `RequestDenied`; new email: new NameID);
  - an unknown SP gets no response; `ForceAuthn` gets a status, no loop;
  - a disabled user with a live session gets no assertion.
- **Browser (7 checks, Chrome with a virtual authenticator, a `two_factor` SP):**
  - SP request → portal → password → passkey → the response page submits itself to the ACS with no CSP violation;
  - the SP accepts it (NameID, RelayState);
  - an already logged in user whose request arrives as a cross-site HTTP-POST gets the response without logging in
    again (found by this test: the portal stalled, and resumed twice; fixed).
- The real Stripe test is at the dress rehearsal (SGNL side).
- **Storage queries on PostgreSQL and MySQL** (`TestEngines` in `internal/storage/sql_provider_engines_test.go`, run by
  the CI job 'Migrations on PostgreSQL and MySQL', skipped elsewhere): SAML flows (save, expiry cleanup, use once),
  the events query (newest first, paging), and the WebAuthn import marks.
- **Unit:** the portal resumes a SAML flow once, only for a complete authentication (`LoginPortal.test.tsx`, checked to
  fail without the guard); the endpoints and routes with and without `enable_keycloak_endpoints`
  (`internal/samlidp/provider_test.go`, `internal/server/handlers_saml_test.go`).

### M2 tests (2026-11-23, `sgnl/e2e/run.sh` in CI, `sgnl/e2e/browser/run.sh` by hand)

- **Revoke (15 checks):**
  - a per-client logout ends that client's tokens only;
  - a full logout ends portal sessions, every client's tokens, and pending links;
  - disable then enable leaves the old refresh token and session dead.
- **Audit (5 checks):** changes are listed newest first with the client as actor and the changed fields, never a
  password; events list the login attempts.
- **Invite (17 checks):**
  - the link arrives by mail only, with the invite wording;
  - redeeming it sets a password and logs the user in with an elevated session;
  - a used, expired, superseded, or disabled-user link is refused, also after re-enabling the user;
  - disabled and unknown users can't be invited, and the lifespan is bounded.
- **Browser (8 checks, Chrome with a virtual authenticator):**
  - an invited user sets a password and lands on the passkey settings already logged in;
  - the passkey is registered without another one-time code;
  - passkey login works;
  - passkey login is refused once the user is disabled ("user not found", not a sign-count error).

- **Half-finished setup (2 checks):** a session which redeemed a link but hasn't set the password yet can't finish
  after a new invite, or after the user is disabled and enabled again (found by review, fixed in `sgnl.4`).

Not covered yet:

- **The suspend test** against SGNL's real apps is SGNL-side work.
