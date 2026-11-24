# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the end-to-end tests, which drive a live instance started by run.sh."""

import base64
import http.client
import json
import secrets
import urllib.parse

BASE = '/realms/test'
ISS = 'https://id.example.com/realms/test'
ADMIN_AUDIENCE = ISS + '/api/admin'
HEADERS = {'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'id.example.com', 'Host': 'id.example.com'}

results = []


def check(name, ok, detail=''):
    """Record and print one check."""
    results.append(bool(ok))
    print(('PASS ' if ok else 'FAIL ') + name + (f'  [{detail}]' if detail and not ok else ''))


def summary():
    """Print the summary line and return the process exit code."""
    print(f'{sum(results)}/{len(results)} passed')

    return 0 if all(results) else 1


class Client:
    """An HTTP client with a cookie jar, talking to the instance on 127.0.0.1:9091 through the realm path."""

    def __init__(self, port=9091):
        self.cookies = {}
        self.port = port

    def req(self, method, path, body=None, headers=None, form=False):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)
        h = dict(HEADERS)
        h.update(headers or {})

        if self.cookies:
            h['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())

        data = None

        if body is not None:
            if form:
                data, h['Content-Type'] = urllib.parse.urlencode(body), 'application/x-www-form-urlencoded'
            else:
                data, h['Content-Type'] = json.dumps(body), 'application/json'

        conn.request(method, BASE + path, data, h)
        r = conn.getresponse()
        b = r.read().decode()

        for k, v in r.getheaders():
            if k.lower() == 'set-cookie':
                name, value = v.split(';')[0].split('=', 1)
                self.cookies[name] = value

        return r.status, dict(r.getheaders()), b


def basic(client_id):
    """The Authorization header of a client authenticating with client_secret_basic (every test secret is the same)."""
    return {'Authorization': 'Basic ' + base64.b64encode(f'{client_id}:insecure_secret'.encode()).decode()}


def claims(jwt):
    """The claims of a JWT, without verifying it."""
    return json.loads(base64.urlsafe_b64decode(jwt.split('.')[1] + '=='))


def admin_headers(client_id='agent', scope='authelia.admin.read authelia.admin.write'):
    """The Authorization header with a client credentials token for the administration API."""
    status, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': 'client_credentials', 'scope': scope,
                                                               'audience': ADMIN_AUDIENCE}, basic(client_id), form=True)

    return {'Authorization': 'Bearer ' + json.loads(body)['access_token']}


def login(username, password):
    """A client logged in to the portal with a password, and the status of the login."""
    client = Client()
    status, _, _ = client.req('POST', '/api/firstfactor', {'username': username, 'password': password})

    return client, status


def authorize(client, client_id, scope='openid profile email groups offline_access'):
    """Runs an authorization code flow with the client's portal session and returns the token response."""
    query = urllib.parse.urlencode({'client_id': client_id, 'response_type': 'code', 'scope': scope,
                                    'redirect_uri': 'https://app.example.com/cb', 'state': secrets.token_hex(12),
                                    'nonce': secrets.token_hex(12)})
    _, headers, _ = client.req('GET', '/api/oidc/authorization?' + query)
    location = headers.get('Location', '')

    if 'flow_id=' in location:
        flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)['flow_id'][0]
        _, _, body = client.req('POST', '/api/oidc/consent', {'flow_id': flow, 'client_id': client_id, 'consent': True,
                                                               'pre_configure': False})
        redirect = urllib.parse.urlparse(json.loads(body)['data']['redirect_uri'])
        _, headers, _ = client.req('GET', redirect.path[len(BASE):] + '?' + redirect.query)
        location = headers.get('Location', '')

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)['code'][0]
    _, _, body = client.req('POST', '/api/oidc/token', {'grant_type': 'authorization_code', 'code': code,
                                                         'redirect_uri': 'https://app.example.com/cb'},
                            basic(client_id), form=True)

    return json.loads(body)


def forward_auth(client):
    """The status of a forward-auth request with the client's portal session."""
    return client.req('GET', '/api/authz/forward-auth', None, {'X-Forwarded-Method': 'GET', 'X-Forwarded-Uri': '/',
                                                                'X-Forwarded-Host': 'app.example.com'})[0]


def introspect(client_id, token):
    """Whether introspection reports the access token active."""
    return json.loads(Client().req('POST', '/api/oidc/introspection', {'token': token}, basic(client_id),
                                   form=True)[2]).get('active')


def refresh(client_id, refresh_token):
    """The status of a refresh token grant."""
    return Client().req('POST', '/api/oidc/token', {'grant_type': 'refresh_token', 'refresh_token': refresh_token},
                        basic(client_id), form=True)[0]
