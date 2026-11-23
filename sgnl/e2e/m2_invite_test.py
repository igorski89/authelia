# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""M2 (C4): inviting a user, who sets a password with a one-time link and is logged in with an elevated session."""

import json
import os
import re
import sys
import time

from lib import Client, admin_headers, check, forward_auth, login, summary

NOTIFICATIONS = os.path.join(os.environ['E2E_DIR'], 'notif.txt')

api, A = Client(), admin_headers()


def invite(username, lifespan=None):
    """Invites the user and returns the status, the response, and the token of the link mailed to it."""
    st, _, b = api.req('POST', f'/api/admin/users/{username}/invite', {'lifespan': lifespan} if lifespan else None, A)

    token = None

    if st == 202:
        # The filesystem notifier replaces the file with each mail, so the last link is the new one.
        with open(NOTIFICATIONS) as f:
            links = re.findall(r'/realms/test/account-setup\?token=([A-Za-z0-9._-]+)', f.read())
            token = links[-1] if links else None

    return st, b, token


def redeem(token, password='an-invited-password-1'):
    """Redeems the link and sets the password, returning the client and both statuses."""
    client = Client()
    _, _, finish = client.req('POST', '/api/account-setup/identity/finish', {'token': token})
    _, _, setup = client.req('POST', '/api/account-setup', {'password': password})

    return client, json.loads(finish).get('status'), json.loads(setup).get('status')


api.req('POST', '/api/admin/users', {'username': 'invited', 'email': 'invited@example.com', 'display_name': 'Invited'}, A)

st, b, token = invite('invited')
check('agent invites a user without a password', st == 202 and token is not None, b)
check('the response never carries the link', 'token' not in b and 'account-setup' not in b, b)

with open(NOTIFICATIONS) as f:
    mail = f.read()

check('the mail is the invite, not a password reset', 'Set up your account' in mail and 'requested action' not in mail)

client, finish, setup = redeem(token)
check('the user redeems the link and sets a password', finish == 'OK' and setup == 'OK', f'{finish} {setup}')
check('the user is logged in afterwards', forward_auth(client) == 200)

st, _, b = client.req('GET', '/api/user/session/elevation')
check('the session is elevated for passkey registration', st == 200 and json.loads(b).get('data', {}).get('elevated') is True, b)

check('the new password works', login('invited', 'an-invited-password-1')[1] == 200)

_, finish, _ = redeem(token)
check('a used link is refused', finish == 'KO', finish)

st, _, b = api.req('GET', '/api/admin/audit?username=invited', None, A)
actions = [e['action'] for e in json.loads(b)['entries']]
check('the audit records the invite and the setup', actions[:2] == ['user.setup', 'user.invite'], actions)

st, b, old = invite('invited')
st, b, new = invite('invited')
_, finish, _ = redeem(old)
check('a new invite revokes the earlier link', finish == 'KO', finish)

api.req('PATCH', '/api/admin/users/invited', {'disabled': True}, A)
api.req('PATCH', '/api/admin/users/invited', {'disabled': False}, A)
_, finish, _ = redeem(new)
check('disabling a user revokes its link, also after enabling it again', finish == 'KO', finish)

# A session which redeemed a link but has not set the password yet loses it when the link is superseded or the user
# is disabled.
for name, supersede in [('a new invite', lambda: invite('invited')),
                        ('disabling the user', lambda: (api.req('PATCH', '/api/admin/users/invited', {'disabled': True}, A),
                                                        api.req('PATCH', '/api/admin/users/invited', {'disabled': False}, A)))]:
    st, b, pending = invite('invited')
    half = Client()
    _, _, f = half.req('POST', '/api/account-setup/identity/finish', {'token': pending})
    supersede()
    _, _, setup = half.req('POST', '/api/account-setup', {'password': 'a-hijacked-password-1'})
    check(f'{name} ends a half-finished setup', json.loads(f).get('status') == 'OK' and json.loads(setup).get('status') == 'KO', f'{f} {setup}')

st, b, short = invite('invited', '1s')
time.sleep(2)
_, finish, _ = redeem(short)
check('an expired link is refused', finish == 'KO', finish)

api.req('PATCH', '/api/admin/users/invited', {'disabled': True}, A)
st, b, _ = invite('invited')
check('a disabled user can not be invited', st == 400, b)

st, b, _ = invite('invited', '90d')
check('the lifespan is bounded', st == 400, b)

st, b, _ = invite('nobody')
check('an unknown user can not be invited', st == 404, b)

sys.exit(summary())
