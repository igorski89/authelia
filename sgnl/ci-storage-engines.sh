#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Runs every storage migration up, one version down, and up again on the PostgreSQL and MySQL services of the CI job
# 'Migrations on PostgreSQL and MySQL'. Upstream's unit tests only execute the SQLite migrations.
set -euo pipefail

go build -o authelia ./cmd/authelia

echo '---' > ci-empty.yml

dir=internal/storage/migrations/postgres
latest="$(find "${dir}" -name 'V*.up.sql' -exec basename {} \; | cut -c2-5 | sort -n | tail -1)"
latest="$((10#${latest}))"

for engine in postgres mysql; do
  if [ "${engine}" = postgres ]; then port=5432; else port=3306; fi

  args=(-c ci-empty.yml "--${engine}.address" "tcp://127.0.0.1:${port}" "--${engine}.username" authelia
    "--${engine}.password" authelia "--${engine}.database" authelia)

  ./authelia storage migrate up "${args[@]}"
  ./authelia storage migrate down --target "$((latest - 1))" --destroy-data "${args[@]}"
  ./authelia storage migrate up "${args[@]}"
  ./authelia storage schema-info "${args[@]}" | tee schema.txt
  grep -q "Schema Version: ${latest}$" schema.txt
done
