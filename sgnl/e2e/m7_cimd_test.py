# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Client ID Metadata Documents: a client identified by the URL of its document, from a host with a rule only. The
documents are served over HTTPS on localhost with a certificate of a test CA Authelia trusts, which the guard allows
for the tests only (special_use_address_guard.allowed_networks)."""

import base64
import hashlib
import http.server
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

from lib import BASE, Client, admin_headers, basic, check, claims, summary

E2E = os.environ['E2E_DIR']
PORT = 47643
ORIGIN = f'https://localhost:{PORT}'
CLAUDE = ORIGIN + '/claude.json'
WEB = ORIGIN + '/web.json'
REDIRECT = 'http://127.0.0.1:47621/callback'
MCP_RESOURCE = 'http://localhost:8765/mcp'
EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token'

fetches = []


def document(client_id, redirect_uris, **extra):
    return {'client_id': client_id, 'client_name': 'Totally The Bank', 'redirect_uris': redirect_uris,
            'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'],
            'token_endpoint_auth_method': 'none', 'scope': 'openid profile email groups offline_access', **extra}


DOCUMENTS = {
    '/claude.json': document(CLAUDE, [REDIRECT], application_type='native'),
    '/web.json': document(WEB, [ORIGIN + '/cb']),
    '/big.json': document(ORIGIN + '/big.json', [REDIRECT], application_type='native', padding='x' * 8000),
    '/wrong-id.json': document(ORIGIN + '/other.json', [REDIRECT], application_type='native'),
}
for n in range(8):
    DOCUMENTS[f'/many{n}.json'] = document(f'{ORIGIN}/many{n}.json', [REDIRECT], application_type='native')


class Documents(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        fetches.append(self.path)

        if self.path == '/redirect.json':
            self.send_response(302)
            self.send_header('Location', '/claude.json')
            self.end_headers()

            return

        doc = DOCUMENTS.get(self.path)
        if doc is None:
            self.send_response(404)
            self.end_headers()

            return

        body = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'max-age=3600')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.path.join(E2E, 'docs.crt'), os.path.join(E2E, 'docs.key'))
servers = []

# The documents are also served on a port the rule doesn't list, so a missing port check would show as a fetch.
for port in (PORT, PORT + 1):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Documents)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/groups', {'name': 'sgnl_users'}, A)
api.req('POST', '/api/admin/users', {'username': 'cimduser', 'email': 'cimduser@example.com', 'display_name': 'Cimd User',
                                     'groups': ['sgnl_users'], 'password': 'a-long-password-x'}, A)


def authorize(client_id, redirect_uri=REDIRECT, port=9091, consent=True, **extra):
    """Runs the authorization code flow with PKCE as the user; returns (tokens or None, consent data, location)."""
    user = Client(port)
    user.req('POST', '/api/firstfactor', {'username': 'cimduser', 'password': 'a-long-password-x'})

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    query = urllib.parse.urlencode({'client_id': client_id, 'response_type': 'code', 'redirect_uri': redirect_uri,
                                    'scope': extra.pop('scope', 'openid profile email groups offline_access'),
                                    'state': secrets.token_hex(12), 'nonce': secrets.token_hex(12),
                                    'code_challenge': challenge, 'code_challenge_method': 'S256', **extra})
    st, headers, _ = user.req('GET', '/api/oidc/authorization?' + query)
    location, data = headers.get('Location', ''), {}

    if 'flow_id=' in location:
        flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)['flow_id'][0]
        _, _, body = user.req('GET', '/api/oidc/consent?flow_id=' + flow)
        data = json.loads(body).get('data', {})

        if not consent:
            return None, data, location

        _, _, body = user.req('POST', '/api/oidc/consent', {'flow_id': flow, 'client_id': client_id, 'consent': True, 'pre_configure': False})
        redirect = urllib.parse.urlparse(json.loads(body)['data']['redirect_uri'])
        _, headers, _ = user.req('GET', redirect.path[len(BASE):] + '?' + redirect.query)
        location = headers.get('Location', '')

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('code', [''])[0]
    if not code:
        return None, data, location or str(st)

    _, _, body = Client(port).req('POST', '/api/oidc/token', {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri,
                                                              'client_id': client_id, 'code_verifier': verifier, **extra}, form=True)

    return json.loads(body), data, location


def refused(location):
    """Whether an authorization request was refused: no code was issued and it didn't go on to consent."""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)

    return 'code' not in query and 'flow_id' not in query


def exchange(subject_token, client='mcp-gateway'):
    st, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': EXCHANGE, 'subject_token': subject_token, 'subject_token_type': ACCESS_TOKEN,
                                                           'requested_token_type': ACCESS_TOKEN, 'scope': 'openid profile email groups'}, basic(client), form=True)

    return st, json.loads(body)


def refresh(token, port=9091):
    st, _, body = Client(port).req('POST', '/api/oidc/token', {'grant_type': 'refresh_token', 'refresh_token': token, 'client_id': CLAUDE,
                                                               'resource': MCP_RESOURCE}, form=True)

    return st, body


# Discovery.
_, _, body = Client().req('GET', '/.well-known/openid-configuration')
discovery = json.loads(body)
check('discovery advertises client_id_metadata_document_supported', discovery.get('client_id_metadata_document_supported') is True, discovery.get('client_id_metadata_document_supported'))
check('discovery advertises the iss authorization response parameter', discovery.get('authorization_response_iss_parameter_supported') is True)

# A login with the client of a document, as Claude Code names its resource.
_, consent, _ = authorize(CLAUDE, consent=False, resource=MCP_RESOURCE)
check('consent: shows the host (with its port) of the document', consent.get('metadata_document_host') == f'localhost:{PORT}', consent)
check('consent: the name is the host, never the document\'s client_name', consent.get('client_description') == f'localhost:{PORT}', consent.get('client_description'))
check('consent: says the client returns to the user\'s computer', consent.get('loopback') is True, consent)

fetched_before = fetches.count('/claude.json')
tokens, _, location = authorize(CLAUDE, resource=MCP_RESOURCE)
token = (tokens or {}).get('access_token', '')
token_claims = claims(token) if token.count('.') == 2 else {}
check('login: the client of a document gets tokens', token and (tokens or {}).get('refresh_token'), f'{location} {tokens}')
check('login: aud has the resource and the gateway (from the rule)', set(token_claims.get('aud') or []) >= {MCP_RESOURCE, 'mcp-gateway'}, token_claims.get('aud'))
check('login: the claims policy of the rule applies', token_claims.get('preferred_username') == 'cimduser' and token_claims.get('groups') == ['sgnl_users'], token_claims)
check('cache: a second login doesn\'t fetch the document again', fetches.count('/claude.json') == fetched_before and fetched_before >= 1, fetches)

st, _, body = Client().req('GET', '/api/oidc/userinfo', None, {'Authorization': f'Bearer {token}'})
check('userinfo accepts the token of the document client', st == 200, f'{st} {body[:120]}')

# The token exchange, which only the rule permits.
st, body = exchange(token)
check('exchange by the client the rule permits: 200', st == 200 and body.get('access_token'), f'{st} {body}')
st, body = exchange(token, client='not-permitted')
check('exchange by a client the rule doesn\'t permit: refused', st == 400 and 'access_token' not in body, f'{st} {body}')

# Refusals.
count = len(fetches)
_, _, location = authorize('https://unknown.invalid/client.json')
check('a host without a rule is refused, without a fetch', refused(location) and len(fetches) == count, f'{location} {fetches[count:]}')
# The rule's domain is matched exactly: the library's own check lets a subdomain through, the rule refuses it.
_, _, location = authorize(f'https://docs.localhost:{PORT}/claude.json')
time.sleep(0.2)
logged = any('no rule permits the host' in line and 'host=docs.localhost' in line for line in open(os.path.join(E2E, 'authelia.log')))
check('a subdomain of an exact rule domain is refused by the rule, without a fetch', refused(location) and logged and len(fetches) == count, f'{logged} {fetches[count:]}')
# Spellings of a client identifier which would be another client of the same host, and a port the rule doesn't list.
for variant, name in ((f'https://LOCALHOST:{PORT}/claude.json', 'upper case'), (f'https://localhost.:{PORT}/claude.json', 'a trailing dot'),
                      (f'https://localhost:{PORT + 1}/claude.json', 'a port the rule doesn\'t list (served there too)'), ('https://localhost/claude.json', 'the default port, not in the rule')):
    count = len(fetches)
    _, _, location = authorize(variant)
    check(f'a client identifier with {name} is refused, without a fetch', refused(location) and len(fetches) == count, f'{location[:120]} {fetches[count:]}')

count = len(fetches)
_, _, location = authorize(ORIGIN + '/redirect.json')
check('a document served with a redirect is refused (redirects aren\'t followed)', refused(location) and '/claude.json' not in fetches[count:], f'{location} {fetches[count:]}')
_, _, location = authorize(ORIGIN + '/big.json')
check('an oversized document is refused', refused(location), location)
_, _, location = authorize(ORIGIN + '/wrong-id.json')
check('a document naming another client_id is refused', refused(location), location)
_, _, location = authorize(CLAUDE, redirect_uri='http://127.0.0.1:47621/other')
check('a redirect URI not in the document (another path) is refused', refused(location), location)
_, _, location = authorize(CLAUDE, redirect_uri='http://127.0.0.1:40000/callback', consent=False)
check('a loopback redirect URI of the document on another port is accepted (RFC 8252 Section 7.3)', not refused(location), location)
_, _, location = authorize(WEB, redirect_uri=ORIGIN + '/cb')
check('a web document with a redirect URI on localhost is refused', refused(location), location)
_, _, location = authorize(CLAUDE, scope='openid authelia.bearer.authz')
check('a scope outside the rule is refused', refused(location), location)

refused_many = [refused(authorize(f'{ORIGIN}/many{n}.json', consent=False)[2]) for n in range(8)]
check('the documents of one host are capped (max_documents_per_host)', any(refused_many) and not all(refused_many), refused_many)

# Pushed authorization requests: the stored request of a document client is loaded with its client again.
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
st, _, body = Client().req('POST', '/api/oidc/pushed-authorization-request', {
    'client_id': CLAUDE, 'response_type': 'code', 'redirect_uri': REDIRECT, 'scope': 'openid profile', 'state': secrets.token_hex(12),
    'code_challenge': challenge, 'code_challenge_method': 'S256'}, form=True)
request_uri = json.loads(body).get('request_uri', '') if st in (200, 201) else ''
check('PAR: a document client pushes its authorization request', request_uri, f'{st} {body[:200]}')
par_user = Client()
par_user.req('POST', '/api/firstfactor', {'username': 'cimduser', 'password': 'a-long-password-x'})
_, headers, _ = par_user.req('GET', '/api/oidc/authorization?' + urllib.parse.urlencode({'client_id': CLAUDE, 'request_uri': request_uri}))
check('PAR: the pushed request of a document client is used at the authorization endpoint', 'flow_id=' in headers.get('Location', '') or 'code=' in headers.get('Location', ''), headers.get('Location', ''))

# A logout ends the tokens of the document client, like those of a registered client.
second, _, _ = authorize(CLAUDE, resource=MCP_RESOURCE)
api.req('POST', '/api/admin/users/cimduser/logout', None, A)
st, _, _ = Client().req('GET', '/api/oidc/userinfo', None, {'Authorization': f"Bearer {second['access_token']}"})
check('after a logout: userinfo refuses the token', st == 401, st)
st, body = refresh(second['refresh_token'])
check('after a logout: its refresh token is refused', st in (400, 401), f'{st} {body[:200]}')

# Other instances, on a copy of the database with a valid refresh token of the document client.
third, _, _ = authorize(CLAUDE, resource=MCP_RESOURCE)
db = os.path.join(E2E, 'db.sqlite3')
config = open(os.path.join(E2E, 'configuration.yml')).read()


def instance(name, port, change):
    directory = os.path.join(E2E, name)
    os.makedirs(directory, exist_ok=True)

    for suffix in ('', '-wal', '-shm'):
        if os.path.exists(db + suffix):
            shutil.copy(db + suffix, os.path.join(directory, 'db.sqlite3' + suffix))

    text = change(config.replace('127.0.0.1:9091', f'127.0.0.1:{port}').replace(os.path.join(E2E, 'db.sqlite3'), os.path.join(directory, 'db.sqlite3'))
                  .replace(os.path.join(E2E, 'authelia.log'), os.path.join(directory, 'authelia.log')))
    path = os.path.join(directory, 'configuration.yml')
    open(path, 'w').write(text)

    process = subprocess.Popen([os.path.join(E2E, 'authelia'), '-c', path], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    for _ in range(30):
        try:
            if Client(port).req('GET', '/api/health')[0] == 200:
                break
        except OSError:
            pass
        time.sleep(1)

    return process


# The guard without the test exception: the document is never fetched from localhost, and a refresh is refused cleanly.
process = instance('guarded', 9096, lambda c: c.replace("allowed_networks: ['127.0.0.1/32', '::1/128']", 'allowed_networks: []'))  # noqa: E501
try:
    count = len(fetches)
    st, body = refresh(third['refresh_token'], port=9096)
    # The library treats a document it can't fetch as temporarily unavailable (503), never as a server error.
    check('SSRF guard: a refresh needing a document on a loopback address is refused cleanly', 400 <= st < 500 or (st == 503 and 'temporarily_unavailable' in body), f'{st} {body[:200]}')
    _, _, location = authorize(CLAUDE, port=9096)
    check('SSRF guard: a login with a document on a loopback address is refused', refused(location), location)
    check('SSRF guard: the document server got no request', len(fetches) == count, fetches[count:])
finally:
    process.terminate()
    process.wait()

# The rule removed: the host's existing tokens are refused cleanly.
process = instance('removed', 9097, lambda c: c.replace("- domain: 'localhost'", "- domain: 'other.example'"))
try:
    count = len(fetches)
    st, body = refresh(third['refresh_token'], port=9097)
    check('rule removed: the refresh token of its host is refused cleanly', 400 <= st < 500, f'{st} {body[:200]}')
    check('rule removed: no document is fetched', len(fetches) == count, fetches[count:])
finally:
    process.terminate()
    process.wait()

for server in servers:
    server.shutdown()

sys.exit(summary())
