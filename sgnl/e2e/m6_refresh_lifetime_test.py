# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Refresh token lifetimes: each refresh starts the idle lifetime (lifespans.refresh_token) again, and no refresh
token is issued after the maximum (lifespans.refresh_token_maximum) from the first one. The client 'capped' has an idle
lifetime of 3 seconds and a maximum of 6."""

import json
import sys
import time

from lib import Client, admin_headers, authorize, basic, check, login, summary

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/users', {'username': 'refresher', 'email': 'refresher@example.com', 'password': 'a-long-password-r'}, A)


def refresh(token):
    st, _, body = Client().req('POST', '/api/oidc/token', {'grant_type': 'refresh_token', 'refresh_token': token}, basic('capped'), form=True)

    return st, json.loads(body)


user, _ = login('refresher', 'a-long-password-r')

# Idle: a refresh token unused for longer than its lifetime is refused.
tokens = authorize(user, 'capped', scope='openid offline_access')
check('setup: a refresh token is issued', 'refresh_token' in tokens, tokens)
time.sleep(4)
st, body = refresh(tokens['refresh_token'])
check('idle: a refresh token unused for longer than its lifetime is refused', st != 200, f'{st} {body}')

# Maximum: refreshing within the idle lifetime keeps the grant going only until the maximum.
tokens = authorize(user, 'capped', scope='openid offline_access')
current = tokens['refresh_token']
results = []

for _ in range(4):
    time.sleep(2)
    st, body = refresh(current)
    results.append(st)

    if st != 200:
        break

    current = body['refresh_token']

check('maximum: refreshes within the idle lifetime work until the maximum, then stop', results[:2] == [200, 200] and results[-1] != 200, results)

sys.exit(summary())
