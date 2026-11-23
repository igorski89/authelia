#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# Builds the image for this machine's platform, starts it with TLS on 127.0.0.1:9091, and drives the invite and
# passkey flow in a headless Chrome (which must be installed) with a virtual authenticator.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"
dir="$(mktemp -d)"
trap 'docker rm -f sgnl-e2e-browser > /dev/null 2>&1 || true; rm -rf "${dir}"' EXIT

docker build -f "${root}/sgnl/Dockerfile" -t sgnl-e2e-browser "${root}"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=id.example.com' \
  -addext 'subjectAltName=DNS:id.example.com' -keyout "${dir}/tls.key" -out "${dir}/tls.crt" 2> /dev/null
openssl genrsa -out "${dir}/jwk.pem" 2048 2> /dev/null
sed '/^#/d' "${here}/configuration.yml.tmpl" > "${dir}/configuration.yml"
mkdir -p "${dir}/data"
chmod 0777 "${dir}/data"

docker run -d --name sgnl-e2e-browser -p 9091:9091 -e X_AUTHELIA_CONFIG_FILTERS=template \
  -v "${dir}:/config" -v "${dir}/data:/data" sgnl-e2e-browser > /dev/null

sleep 8

(cd "${here}" && npm install --silent > /dev/null && node invite_passkey.mjs "${dir}/data/notif.txt")
