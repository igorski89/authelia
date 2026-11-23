#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Builds the image for this machine's platform, starts it with TLS on 127.0.0.1:9091, and drives the invite and
# passkey flow, then SAML single sign-on with a passkey against a local service provider, in a headless Chrome (which
# must be installed) with a virtual authenticator.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"
dir="$(mktemp -d)"
trap '[ -n "${sp:-}" ] && kill "${sp}" 2> /dev/null; docker rm -f sgnl-e2e-browser > /dev/null 2>&1 || true; rm -rf "${dir}"' EXIT

docker build -f "${root}/sgnl/Dockerfile" -t sgnl-e2e-browser "${root}"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=id.example.com' \
  -addext 'subjectAltName=DNS:id.example.com' -keyout "${dir}/tls.key" -out "${dir}/tls.crt" 2> /dev/null
openssl genrsa -out "${dir}/jwk.pem" 2048 2> /dev/null
for name in saml sp; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=${name}.example.com" \
    -keyout "${dir}/${name}.key" -out "${dir}/${name}.crt" 2> /dev/null
done
chmod 0644 "${dir}"/*.key
(cd "${root}" && go build -o "${dir}/samlsp" ./sgnl/e2e/samlsp)
sed '/^#/d' "${here}/configuration.yml.tmpl" > "${dir}/configuration.yml"
mkdir -p "${dir}/data"
chmod 0777 "${dir}/data"

docker run -d --name sgnl-e2e-browser -p 9091:9091 -e X_AUTHELIA_CONFIG_FILTERS=template \
  -v "${dir}:/config" -v "${dir}/data:/data" sgnl-e2e-browser > /dev/null

sleep 8

curl -sfk -H 'X-Forwarded-Proto: https' --resolve id.example.com:9091:127.0.0.1 \
  https://id.example.com:9091/realms/test/api/saml/metadata > "${dir}/idp-metadata.xml"
"${dir}/samlsp" -listen 127.0.0.1:9102 -entity-id https://sp2.example.com/saml/metadata \
  -acs https://sp2.example.com/saml/acs -idp-metadata "${dir}/idp-metadata.xml" -key "${dir}/sp.key" -cert "${dir}/sp.crt" &
sp=$!

(cd "${here}" && npm install --silent > /dev/null && node invite_passkey.mjs "${dir}/data/notif.txt" \
  && node saml_passkey.mjs "${dir}/data/notif.txt")
