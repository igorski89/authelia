#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Runs the end-to-end tests: builds Authelia, starts it on 127.0.0.1:9091 with a throwaway SQLite database and test
# configuration, and runs every *_test.py here against it in name order. Pass test file names to run only those.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="$(mktemp -d)"
trap 'kill "${pid:-0}" 2>/dev/null || true; [ -n "${E2E_KEEP:-}" ] && cp "${dir}/authelia.log" "${E2E_KEEP}"; rm -rf "${dir}"' EXIT

go build -o "${dir}/authelia" ./cmd/authelia
openssl genrsa -out "${dir}/jwk.pem" 2048 2>/dev/null
sed "s|\${DIR}|${dir}|g" "${here}/configuration.yml.tmpl" > "${dir}/configuration.yml"

export X_AUTHELIA_CONFIG_FILTERS=template PYTHONDONTWRITEBYTECODE=1 E2E_DIR="${dir}"
"${dir}/authelia" storage migrate up -c "${dir}/configuration.yml" > /dev/null
"${dir}/authelia" -c "${dir}/configuration.yml" > "${dir}/run.log" 2>&1 &
pid=$!

for _ in $(seq 1 30); do
  curl -sf -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: id.example.com' \
    http://127.0.0.1:9091/realms/test/api/health > /dev/null && break
  sleep 1
done

status=0

if [ "$#" -eq 0 ]; then
  set -- "${here}"/*_test.py
fi

for test in "$@"; do
  echo "== $(basename "${test}")"

  python3 "${test}" || status=1
done

exit "${status}"
