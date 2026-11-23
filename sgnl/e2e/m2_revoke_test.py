# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""M2 (C5): logging a user out, per client or completely, and disable ending everything."""

import json
import sys

from lib import Client, admin_headers, authorize, check, forward_auth, introspect, login, refresh, summary

api, A = Client(), admin_headers()

api.req('POST', '/api/admin/groups', {'name': 'staff'}, A)
api.req('POST', '/api/admin/users', {'username': 'rev', 'email': 'rev@example.com', 'groups': ['staff'],
                                     'password': 'a-long-password-9'}, A)

u1, _ = login('rev', 'a-long-password-9')
t1 = authorize(u1, 'app')
u2, _ = login('rev', 'a-long-password-9')
t2 = authorize(u2, 'test')

st, _, b = api.req('GET', '/api/admin/users/rev', None, A)
d = json.loads(b)
check('show: credentials and 2 sessions', d.get('credentials') == ['password'] and d.get('sessions') == 2, b)

st, _, b = api.req('POST', '/api/admin/users/rev/logout', {'client_id': 'app'}, A)
check('per-client logout', st == 200, b)
check('  app token inactive', introspect('app', t1['access_token']) is False)
check('  app refresh refused', refresh('app', t1['refresh_token']) == 400)
check('  other client token still active', introspect('test', t2['access_token']) is True)
check('  portal session kept', forward_auth(u2) == 200)

st, _, b = api.req('POST', '/api/admin/users/rev/logout', None, A)
r = json.loads(b)
check('full logout without disabling', st == 200 and r.get('sessions') == 2 and r.get('tokens', 0) > 0, b)
check('  portal session ended', forward_auth(u2) == 401)
check('  other client token inactive', introspect('test', t2['access_token']) is False)
check('  other client refresh refused', refresh('test', t2['refresh_token']) == 400)
check('  user can log in again', login('rev', 'a-long-password-9')[1] == 200)

u3, _ = login('rev', 'a-long-password-9')
t3 = authorize(u3, 'app')
api.req('PATCH', '/api/admin/users/rev', {'disabled': True}, A)
api.req('PATCH', '/api/admin/users/rev', {'disabled': False}, A)
check('disable then enable: old refresh token stays dead', refresh('app', t3['refresh_token']) == 400)
check('disable then enable: old session stays dead', forward_auth(u3) == 401)

st, _, b = api.req('GET', '/api/admin/users/rev', None, A)
check('show: no sessions left after disable', json.loads(b).get('sessions') == 0, b)

st, _, b = api.req('GET', '/api/admin/groups/staff/members', None, A)
m = json.loads(b)['members']
check('members carry email and disabled', m and m[0]['email'] == 'rev@example.com' and m[0]['disabled'] is False, b)

sys.exit(summary())
