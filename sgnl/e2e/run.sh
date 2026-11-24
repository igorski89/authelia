#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Runs the end-to-end tests: builds Authelia, starts it on 127.0.0.1:9091 with a throwaway SQLite database and test
# configuration, and runs every *_test.py here against it in name order. Pass test file names to run only those.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="$(mktemp -d)"
trap '[ -n "${pid:-}" ] && kill "${pid}" 2>/dev/null; [ -n "${E2E_KEEP:-}" ] && cp "${dir}/authelia.log" "${E2E_KEEP}"; rm -rf "${dir}"' EXIT

go build -o "${dir}/authelia" ./cmd/authelia
openssl genrsa -out "${dir}/jwk.pem" 2048 2>/dev/null
for name in saml sp; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=${name}.example.com" \
    -keyout "${dir}/${name}.key" -out "${dir}/${name}.crt" 2> /dev/null
done
go build -o "${dir}/samlsp" ./sgnl/e2e/samlsp
# A test CA Authelia trusts, and the certificate of the Client ID Metadata Document server on localhost.
mkdir -p "${dir}/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e test CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" -keyout "${dir}/ca.key" -out "${dir}/certs/ca.crt" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "${dir}/docs.key" -out "${dir}/docs.csr" 2> /dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "${dir}/docs.ext"
openssl x509 -req -in "${dir}/docs.csr" -CA "${dir}/certs/ca.crt" -CAkey "${dir}/ca.key" -CAcreateserial -days 1 \
  -extfile "${dir}/docs.ext" -out "${dir}/docs.crt" 2> /dev/null
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
