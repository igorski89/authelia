#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Runs every storage migration up, one version down, and up again on the PostgreSQL and MySQL services of the CI job
# 'Migrations on PostgreSQL and MySQL', then manages users and groups with the CLI on both. Upstream's unit tests only
# execute the SQLite SQL.
set -euo pipefail

go build -o authelia ./cmd/authelia

echo '---' > ci-empty.yml

cat > ci-users.yml <<'YAML'
---
authentication_backend:
  database:
    search:
      email: true
...
YAML

# expect_output runs a command whose output must match the extended regular expression given first.
expect_output() {
  local pattern="$1" output

  shift

  output="$("$@")"

  if ! grep -qE "${pattern}" <<< "${output}"; then
    printf 'expected output matching %s from: %s\n%s\n' "${pattern}" "$*" "${output}" >&2

    exit 1
  fi
}

# expect_fail runs a command which must fail.
expect_fail() {
  if "$@"; then
    echo "expected failure: $*" >&2

    exit 1
  fi
}

dir=internal/storage/migrations/postgres
latest="$(find "${dir}" -name 'V*.up.sql' -exec basename {} \; | cut -c2-5 | sort -n | tail -1)"
latest="$((10#${latest}))"

for engine in postgres mysql; do
  if [ "${engine}" = postgres ]; then port="${POSTGRES_PORT:-5432}"; else port="${MYSQL_PORT:-3306}"; fi

  args=(-c ci-empty.yml "--${engine}.address" "tcp://127.0.0.1:${port}" "--${engine}.username" authelia
    "--${engine}.password" authelia "--${engine}.database" authelia)

  ./authelia storage migrate up "${args[@]}"
  ./authelia storage migrate down --target "$((latest - 1))" --destroy-data "${args[@]}"
  ./authelia storage migrate up "${args[@]}"
  expect_output "Schema Version: ${latest}$" ./authelia storage schema-info "${args[@]}"

  users=(-c ci-users.yml "${args[@]:2}")

  # The Keycloak import: a dry run changes nothing, the import is one transaction, and a second import fails whole.
  export_file=internal/management/testdata/keycloak-realm-export.json
  expect_output '^  users: 3 ' ./authelia users import keycloak "${export_file}" --webauthn-rpid localhost "${users[@]}"
  if [ "$(./authelia users list "${users[@]}" | wc -l)" -ne 1 ]; then
    echo 'the dry run of the import kept users' >&2
    exit 1
  fi
  expect_output '^Imported:' ./authelia users import keycloak "${export_file}" --webauthn-rpid localhost --apply \
    "${users[@]}"
  expect_output 'Groups: +admins, forgejo_users, sgnl_users$' ./authelia users get bob-test "${users[@]}"
  expect_fail ./authelia users import keycloak "${export_file}" --webauthn-rpid localhost --apply "${users[@]}"
  expect_output 'cli:.*user\.import +carol-test' ./authelia users audit carol-test "${users[@]}"

  ./authelia groups create staff "${users[@]}"
  ./authelia groups create Users "${users[@]}"
  echo 'a-long-password-1' | ./authelia users create Alice --email Alice@Example.com --group staff --group Users \
    --password-stdin "${users[@]}"
  ./authelia users create bob --email bob@example.com --no-password "${users[@]}"
  expect_fail ./authelia users create ALICE --email x@example.com --no-password "${users[@]}"
  expect_fail ./authelia users create carol --email ALICE@example.com --no-password "${users[@]}"
  ./authelia users update bob --email BOB2@example.com --disable "${users[@]}"
  expect_output 'Groups: +Users, staff$' ./authelia users get alice "${users[@]}"
  expect_output '^bob +bob2@example.com .*true' ./authelia users list "${users[@]}"
  expect_output '^Revoked [0-9]+ token session' ./authelia users logout bob "${users[@]}"
  ./authelia users delete alice --force "${users[@]}"
  expect_fail ./authelia users create alice --email new@example.com --no-password "${users[@]}"
  expect_output 'cli:.*user\.delete +alice' ./authelia users audit alice "${users[@]}"
  expect_output 'cli:.*group\.create +Users' ./authelia users audit "${users[@]}"
  ./authelia storage encryption rotate hmac authentication-user --force "${users[@]}"
  expect_output 'Disabled: +true$' ./authelia users get bob "${users[@]}"
done
