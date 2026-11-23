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

### M0 checks (on `b935f93f`)

_In progress; see below._
