#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Runs the M1 exit test: builds Authelia, starts it on 127.0.0.1:9091 with a throwaway SQLite database and test
# configuration, and drives the administration API and login flows with exit_test.py.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="$(mktemp -d)"
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "${dir}"' EXIT

go build -o "${dir}/authelia" ./cmd/authelia
openssl genrsa -out "${dir}/jwk.pem" 2048 2>/dev/null
sed "s|\${DIR}|${dir}|g" "${here}/configuration.yml.tmpl" > "${dir}/configuration.yml"

export X_AUTHELIA_CONFIG_FILTERS=template
"${dir}/authelia" storage migrate up -c "${dir}/configuration.yml" > /dev/null
"${dir}/authelia" -c "${dir}/configuration.yml" > "${dir}/run.log" 2>&1 &
pid=$!

for _ in $(seq 1 30); do
  curl -sf -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: id.example.com' \
    http://127.0.0.1:9091/realms/test/api/health > /dev/null && break
  sleep 1
done

python3 "${here}/exit_test.py" | tee "${dir}/result.txt"
! grep -q '^FAIL' "${dir}/result.txt"
