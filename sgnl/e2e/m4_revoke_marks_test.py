# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Revocation marks only end what they revoke: after a per-client logout the user's other logins and new grants keep
working, and every way of logging in works after an old mark. The marks have a resolution of a second, so each check
waits for the next one."""

import json
import os
import re
import sys
import time

from lib import Client, admin_headers, authorize, check, forward_auth, introspect, login, refresh, summary

NOTIFICATIONS = os.path.join(os.environ['E2E_DIR'], 'notif.txt')

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/users', {'username': 'marked', 'email': 'marked@example.com', 'password': 'a-long-password-m'}, A)

# A per-client logout leaves the portal session and lets the same portal session authorize that client again.
user, _ = login('marked', 'a-long-password-m')
old = authorize(user, 'app')
other = authorize(user, 'test')
time.sleep(1.1)
api.req('POST', '/api/admin/users/marked/logout', {'client_id': 'app'}, A)
time.sleep(1.1)
check('per-client logout: the old grant of the client is refused', refresh('app', old['refresh_token']) != 200)
check('per-client logout: the portal session stays', forward_auth(user) == 200)
check('per-client logout: the grant of another client stays', refresh('test', other['refresh_token']) == 200)
new = authorize(user, 'app')
check('per-client logout: the same portal session authorizes the client again', 'refresh_token' in new, json.dumps(new)[:200])
time.sleep(1.1)
check('per-client logout: the new access token is active', introspect('app', new.get('access_token', '')) is True)
check('per-client logout: the new grant refreshes', refresh('app', new.get('refresh_token', '')) == 200)

# After a full logout every way of logging in works again, once the mark is older than a second.
api.req('POST', '/api/admin/users/marked/logout', None, A)
time.sleep(1.1)
again, st = login('marked', 'a-long-password-m')
check('after a full logout: password login', st == 200 and forward_auth(again) == 200)
tokens = authorize(again, 'app')
time.sleep(1.1)
check('after a full logout: a new grant refreshes', refresh('app', tokens.get('refresh_token', '')) == 200)

# An invited user who was disabled and enabled before logs in with the account setup.
api.req('PATCH', '/api/admin/users/marked', {'disabled': True}, A)
api.req('PATCH', '/api/admin/users/marked', {'disabled': False}, A)
time.sleep(1.1)
st, _, _ = api.req('POST', '/api/admin/users/marked/invite', None, A)
with open(NOTIFICATIONS) as f:
    token = (re.findall(r'/realms/test/account-setup\?token=([A-Za-z0-9._-]+)', f.read()) or [None])[-1]
setup = Client()
setup.req('POST', '/api/account-setup/identity/finish', {'token': token})
_, _, b = setup.req('POST', '/api/account-setup', {'password': 'a-new-password-m'})
check('after a disable: the account setup logs the user in', st == 202 and '"OK"' in b and forward_auth(setup) == 200, b)

sys.exit(summary())
