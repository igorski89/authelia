# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Concurrent token exchanges of one subject token, as an MCP client calling several gateway tools at once."""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import threading
import urllib.parse

from lib import BASE, Client, admin_headers, basic, check, claims, introspect, summary

EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token'
REDIRECT = 'http://127.0.0.1:47621/callback'
SAMPLES = os.path.join(os.environ['E2E_DIR'], 'token-exchange-samples.json')

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/groups', {'name': 'sgnl_users'}, A)
api.req('POST', '/api/admin/users', {'username': 'mcpuser', 'email': 'mcpuser@example.com', 'display_name': 'Mcp User',
                                     'groups': ['sgnl_users'], 'password': 'a-long-password-x'}, A)


def header(jwt):
    segment = jwt.split('.')[0]

    return json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))


def pkce_login(username='mcpuser', password='a-long-password-x', client='mcp-login', **extra):
    """Logs in at the portal and runs the authorization code flow of the public client with PKCE."""
    user = Client()
    user.req('POST', '/api/firstfactor', {'username': username, 'password': password})

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    query = urllib.parse.urlencode({'client_id': client, 'response_type': 'code', 'scope': extra.pop('scope', 'openid profile email groups'),
                                    'redirect_uri': REDIRECT, 'state': secrets.token_hex(12), 'nonce': secrets.token_hex(12),
                                    'code_challenge': challenge, 'code_challenge_method': 'S256', **extra})
    _, headers, _ = user.req('GET', '/api/oidc/authorization?' + query)
    location = headers.get('Location', '')

    # A public client with a loopback redirect URI gets the consent screen.
    if 'flow_id=' in location:
        flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)['flow_id'][0]
        _, _, body = user.req('POST', '/api/oidc/consent', {'flow_id': flow, 'client_id': client, 'consent': True, 'pre_configure': False})
        redirect = urllib.parse.urlparse(json.loads(body)['data']['redirect_uri'])
        _, headers, _ = user.req('GET', redirect.path[len(BASE):] + '?' + redirect.query)
        location = headers.get('Location', '')

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('code', [''])[0]
    _, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT,
                                                          'client_id': client, 'code_verifier': verifier, **extra}, form=True)

    return json.loads(body)


def exchange(subject_token, client='mcp-gateway', secret=None, **extra):
    """A token exchange of the client, returning the status and the JSON response."""
    form = {'grant_type': EXCHANGE, 'subject_token': subject_token, 'subject_token_type': ACCESS_TOKEN,
            'requested_token_type': ACCESS_TOKEN, 'scope': 'openid profile email groups', **extra}
    headers = basic(client)

    if secret is not None:
        headers = {'Authorization': 'Basic ' + base64.b64encode(f'{client}:{secret}'.encode()).decode()}

    st, _, body = Client().req('POST', '/api/oidc/token', form, headers, form=True)

    try:
        return st, json.loads(body)
    except ValueError:
        return st, {'raw': body[:200]}


ROUNDS, PARALLEL = 5, 10
failures = []

for _ in range(ROUNDS):
    login_token = pkce_login().get('access_token', '')
    results = [None] * PARALLEL

    def run(i, token=login_token):
        results[i] = exchange(token)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(PARALLEL)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    failures += [(st, body) for st, body in results if st != 200]

check(f'{ROUNDS} rounds of {PARALLEL} parallel exchanges of one subject token all succeed', not failures, f'{len(failures)} failed: {failures[:2]}')

sys.exit(summary())
