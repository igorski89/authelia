# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Implicit consent and offline_access: consent_implicit_offline_access lets an implicit consent client get offline
access without the consent screen; everything else which requires the consent screen still does."""

import secrets
import sys
import urllib.parse

from lib import Client, admin_headers, basic, check, refresh, summary
import json

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/users', {'username': 'connie', 'email': 'connie@example.com', 'password': 'a-long-password-7'}, A)

user = Client()
user.req('POST', '/api/firstfactor', {'username': 'connie', 'password': 'a-long-password-7'})


def authorization(client_id, scope, **extra):
    """The Location of an authorization request of the logged in user."""
    query = {'client_id': client_id, 'response_type': 'code', 'scope': scope, 'redirect_uri': 'https://app.example.com/cb',
             'state': secrets.token_hex(12), 'nonce': secrets.token_hex(12), **extra}
    _, headers, _ = user.req('GET', '/api/oidc/authorization?' + urllib.parse.urlencode(query))

    return headers.get('Location', '')


location = authorization('test', 'openid profile')
check('implicit consent without offline_access: a code at once', 'code=' in location, location)

location = authorization('test', 'openid profile offline_access')
check('implicit consent with offline_access, without the option: the consent screen (as upstream)', 'consent' in location and 'code=' not in location, location)

location = authorization('implicit-offline', 'openid profile offline_access')
check('with consent_implicit_offline_access: a code at once', 'code=' in location, location)

code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('code', [''])[0]
_, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': 'authorization_code', 'code': code,
                                                      'redirect_uri': 'https://app.example.com/cb'},
                          basic('implicit-offline'), form=True)
tokens = json.loads(body)
check('the token response has a refresh token (offline_access granted)', 'refresh_token' in tokens and 'offline_access' in tokens.get('scope', ''), body[:200])
check('the refresh token works', refresh('implicit-offline', tokens.get('refresh_token', '')) == 200)

location = authorization('implicit-offline', 'openid profile offline_access', prompt='consent')
check('prompt=consent still shows the consent screen', 'consent' in location and 'code=' not in location, location)

location = authorization('implicit-offline', 'openid profile offline_access', prompt='none')
check('prompt=none gets a code, not consent_required', 'code=' in location, location)

sys.exit(summary())
