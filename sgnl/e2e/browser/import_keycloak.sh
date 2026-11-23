#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Imports the synthetic Keycloak realm export of fixtures/ into a local Authelia, then logs every user in through the
# portal in a headless Chrome (which must be installed) with the same virtual passkeys which registered in Keycloak.
# Keycloak ran at localhost, which Authelia can't serve (a session cookie domain needs a period), so the passkeys are
# imported for the RP ID id.example.com and the virtual authenticator holds the same credentials (ID and key pair) for
# it: what is tested is the imported credential ID, public key, sign count, user handle, and flags.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"
dir="$(mktemp -d)"
name=sgnl-e2e-import
image=sgnl-e2e-browser
trap 'docker rm -f "${name}" > /dev/null 2>&1 || true; rm -rf "${dir}"' EXIT

docker build -f "${root}/sgnl/Dockerfile" -t "${image}" "${root}"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=id.example.com' -addext 'subjectAltName=DNS:id.example.com' \
  -keyout "${dir}/tls.key" -out "${dir}/tls.crt" 2> /dev/null
chmod 0644 "${dir}/tls.key"
sed '/^#/d' "${here}/import_keycloak.yml" > "${dir}/configuration.yml"
mkdir -p "${dir}/data"
chmod 0777 "${dir}/data"

authelia() {
  docker run --rm --entrypoint authelia -v "${dir}:/config" -v "${dir}/data:/data" -v "${here}/fixtures:/fixtures:ro" \
    "${image}" "$@" -c /config/configuration.yml
}

authelia storage migrate up > /dev/null
authelia users import keycloak /fixtures/keycloak-realm-export.json --webauthn-rpid id.example.com
authelia users import keycloak /fixtures/keycloak-realm-export.json --webauthn-rpid id.example.com --apply

docker run -d --name "${name}" -p 9095:9095 -v "${dir}:/config" -v "${dir}/data:/data" "${image}" > /dev/null
sleep 8

status=0
(cd "${here}" && npm install --silent > /dev/null && node import_keycloak.mjs "${here}/fixtures") || status=$?

# Only carol-test's passkey reports backup flags which differ from the imported ones, so only it adopts them, once.
adopted="$(docker logs "${name}" 2>&1 | grep -c 'Adopted the backup flags' || true)"
if [ "${adopted}" -eq 1 ]; then
  echo 'PASS the backup flags were adopted once, for the synced passkey only'
else
  echo "FAIL the backup flags were adopted ${adopted} times, not once"
  status=1
fi

exit "${status}"
