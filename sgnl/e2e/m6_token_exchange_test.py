# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""RFC 8693 token exchange for an MCP gateway: a person logs in with a public PKCE client whose access tokens are for
the gateway, and the gateway exchanges such a token for one of its own for the same person."""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
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


def pkce_login(username='mcpuser', password='a-long-password-x'):
    """Logs in at the portal and runs the authorization code flow of the public client with PKCE."""
    user = Client()
    user.req('POST', '/api/firstfactor', {'username': username, 'password': password})

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    query = urllib.parse.urlencode({'client_id': 'mcp-login', 'response_type': 'code', 'scope': 'openid profile email groups',
                                    'redirect_uri': REDIRECT, 'state': secrets.token_hex(12), 'nonce': secrets.token_hex(12),
                                    'code_challenge': challenge, 'code_challenge_method': 'S256'})
    _, headers, _ = user.req('GET', '/api/oidc/authorization?' + query)
    location = headers.get('Location', '')

    # A public client with a loopback redirect URI gets the consent screen.
    if 'flow_id=' in location:
        flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)['flow_id'][0]
        _, _, body = user.req('POST', '/api/oidc/consent', {'flow_id': flow, 'client_id': 'mcp-login', 'consent': True, 'pre_configure': False})
        redirect = urllib.parse.urlparse(json.loads(body)['data']['redirect_uri'])
        _, headers, _ = user.req('GET', redirect.path[len(BASE):] + '?' + redirect.query)
        location = headers.get('Location', '')

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('code', [''])[0]
    _, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT,
                                                          'client_id': 'mcp-login', 'code_verifier': verifier}, form=True)

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


# The login token of the public client.
login = pkce_login()
login_token = login.get('access_token', '')
login_claims = claims(login_token) if login_token.count('.') == 2 else {}
check('login: the public PKCE client gets a JWT access token', login_token.count('.') == 2, json.dumps(login)[:200])
check('login: its aud contains the gateway', 'mcp-gateway' in (login_claims.get('aud') or []), login_claims.get('aud'))
check('login: it carries the person\'s claims', login_claims.get('preferred_username') == 'mcpuser' and login_claims.get('groups') == ['sgnl_users'], login_claims)

# The exchange.
st, exchanged = exchange(login_token)
token = exchanged.get('access_token', '')
ex_claims = claims(token) if token.count('.') == 2 else {}
check('exchange: 200 with an access token', st == 200 and token, f'{st} {exchanged}')
check('exchange: issued_token_type is access_token and there is no refresh token', exchanged.get('issued_token_type') == ACCESS_TOKEN and 'refresh_token' not in exchanged, exchanged)
check('exchange: a JWT access token (typ at+jwt)', token.count('.') == 2 and header(token).get('typ') == 'at+jwt', header(token) if token else None)
check('exchange: azp or client_id is the gateway', 'mcp-gateway' in (ex_claims.get('azp'), ex_claims.get('client_id')), {k: ex_claims.get(k) for k in ('azp', 'client_id')})
check('exchange: the same person claims as the login token',
      all(ex_claims.get(k) == login_claims.get(k) for k in ('preferred_username', 'email', 'name', 'groups')),
      {k: (login_claims.get(k), ex_claims.get(k)) for k in ('preferred_username', 'email', 'name', 'groups')})
check('exchange: the openid scope', 'openid' in exchanged.get('scope', '').split(), exchanged.get('scope'))
# The login token lives 2 minutes and the gateway's exchanged tokens 1 hour, so the cap is what limits it.
check('exchange: never outlives the login token (capped below the 1 hour lifespan)', 0 < ex_claims.get('exp', 0) <= login_claims.get('exp', 0) and exchanged.get('expires_in', 3600) <= 120, (ex_claims.get('exp'), login_claims.get('exp'), exchanged.get('expires_in')))
check('exchange: the same issuer', ex_claims.get('iss') == login_claims.get('iss'), ex_claims.get('iss'))

st, _, body = Client().req('GET', '/api/oidc/userinfo', None, {'Authorization': f'Bearer {token}'})
check('userinfo accepts the exchanged token', st == 200 and json.loads(body).get('preferred_username') == 'mcpuser', f'{st} {body[:160]}')
check('introspection reports the exchanged token active', introspect('mcp-gateway', token) is True)

with open(SAMPLES, 'w') as f:
    json.dump({'login_token': {'header': header(login_token), 'claims': login_claims},
               'exchanged_token': {'header': header(token) if token else None, 'claims': ex_claims, 'response': {k: v for k, v in exchanged.items() if k != 'access_token'}}}, f, indent=2)

# Audiences.
st, body = exchange(login_token, audience='test')
aud_claims = claims(body['access_token']) if st == 200 else {}
check('exchange with audience test (a one factor app): its aud contains test', 'test' in (aud_claims.get('aud') or []), f'{st} {aud_claims.get("aud")}')
st, body = exchange(login_token, audience='evil')
check('exchange with an audience outside the client\'s list is refused', st == 400, f'{st} {body}')

# Refusals.
# The client may request openid, so only the permission of the login client can refuse it.
st, body = exchange(login_token, client='not-permitted', scope='openid')
check('a client the login client doesn\'t permit is refused, for that reason', st == 400 and 'access_token' not in body and body.get('error') != 'invalid_scope', f'{st} {body}')
# 'aud-only' is in the login token's audience and may request openid, so only subject_token_clients_supported of the
# login client refuses it.
st, body = exchange(login_token, client='aud-only', scope='openid')
check('a client in the audience but not permitted by the login client is refused', st == 400 and 'access_token' not in body, f'{st} {body}')

# The audience of the exchanged token must permit the user too: 'strict-app' requires two factors, the login one.
st, body = exchange(login_token, audience='strict-app')
check('an audience whose authorization policy the login doesn\'t satisfy is refused', st == 400 and 'access_token' not in body, f'{st} {body}')

# Delegation isn't supported.
st, body = exchange(login_token, actor_token=login_token, actor_token_type=ACCESS_TOKEN)
check('an actor_token is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
st, body = exchange(login_token, secret='wrong-secret')
check('a wrong client secret is refused (invalid_client)', st == 401 and body.get('error') == 'invalid_client', f'{st} {body}')
st, body = exchange(login_token[:-4] + 'AAAA')
check('a tampered subject token is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
# A changed payload keeps the signature the token is looked up by, so this reaches the signature verification.
head, payload, signature = login_token.split('.')
forged = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
forged['groups'] = ['admins']
forged_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b'=').decode()
st, body = exchange(f'{head}.{forged_payload}.{signature}')
check('a subject token with a changed payload (signature kept) is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
tampered_error = body.get('error')
st, body = exchange(login_token, requested_token_type='urn:ietf:params:oauth:token-type:refresh_token')
check('a refresh token can\'t be requested', st == 400 and 'refresh_token' not in body, f'{st} {body}')
st, body = exchange(login_token, scope='openid offline_access')
check('a scope the login token wasn\'t granted is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
st, body = exchange(token)
check('an exchanged token can\'t be exchanged again (own token)', st == 400 and 'access_token' not in body, f'{st} {body}')
st, _, body = Client().req('GET', '/api/admin/whoami', None, {'Authorization': f'Bearer {token}'})
check('the exchanged token is no administration token', st in (401, 403), f'{st} {body[:120]}')

# A disabled user's login token can't be exchanged; enabled again, a new login works.
api.req('PATCH', '/api/admin/users/mcpuser', {'disabled': True}, A)
st, body = exchange(login_token)
check('a disabled user\'s login token is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
api.req('PATCH', '/api/admin/users/mcpuser', {'disabled': False}, A)
login_token = pkce_login().get('access_token', '')
st, exchanged = exchange(login_token)
token = exchanged.get('access_token', '')
check('enabled again: a new login is exchanged', st == 200 and token, f'{st} {exchanged}')

# A logout ends the exchanged token, and the login token can't be exchanged any more.
api.req('POST', '/api/admin/users/mcpuser/logout', None, A)
check('after a logout: the exchanged token is inactive', introspect('mcp-gateway', token) is False)
st, _, body = Client().req('GET', '/api/oidc/userinfo', None, {'Authorization': f'Bearer {token}'})
check('after a logout: userinfo refuses the exchanged token', st == 401, f'{st} {body[:120]}')
st, body = exchange(login_token)
check('after a logout: the old login token is refused', st == 400 and 'access_token' not in body, f'{st} {body}')
revoked_error = body.get('error')

# The race: a request which was already running saves the login token's row again after the logout. The revocation
# mark still refuses its exchange.
db = sqlite3.connect(os.path.join(os.environ['E2E_DIR'], 'db.sqlite3'))
subjects = [row[0] for row in db.execute("SELECT identifier FROM user_opaque_identifier WHERE username = 'mcpuser'")]
restored = db.execute(f"UPDATE oauth2_access_token_session SET revoked = FALSE WHERE subject IN ({','.join('?' * len(subjects))})", subjects).rowcount
db.commit()
db.close()
st, body = exchange(login_token)
check('after a logout: a login token whose row was put back is still refused', restored > 0 and st == 400 and 'access_token' not in body, f'{restored} {st} {body}')

print(f'INFO error codes: tampered subject token -> {tampered_error}, revoked subject token -> {revoked_error}')

sys.exit(summary())
