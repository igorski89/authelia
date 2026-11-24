# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Password reset links end with a logout: also when the reset was asked for by email or in another case, and also
when the link was opened but the password not set yet."""

import json
import os
import re
import sys
import time

from lib import Client, admin_headers, check, login, summary

NOTIFICATIONS = os.path.join(os.environ['E2E_DIR'], 'notif.txt')

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/users', {'username': 'resetter', 'email': 'resetter@example.com', 'password': 'a-long-password-9'}, A)


def request_reset(typed):
    """Asks for a reset link as typed (username, email, any case) and returns the token mailed."""
    before = os.path.getmtime(NOTIFICATIONS) if os.path.exists(NOTIFICATIONS) else 0
    Client().req('POST', '/api/reset-password/identity/start', {'username': typed})

    for _ in range(20):
        if os.path.exists(NOTIFICATIONS) and os.path.getmtime(NOTIFICATIONS) != before:
            break
        time.sleep(0.2)

    with open(NOTIFICATIONS) as f:
        links = re.findall(r'/realms/test/reset-password/step2\?token=([A-Za-z0-9._-]+)', f.read())

    return links[-1] if links else None


def open_link(token):
    client = Client()
    st, _, body = client.req('POST', '/api/reset-password/identity/finish', {'token': token})

    try:
        return client, json.loads(body).get('status')
    except ValueError:
        return client, f'http {st}: {body[:80]}'



for typed in ['resetter@example.com', 'RESETTER']:
    token = request_reset(typed)
    api.req('POST', '/api/admin/users/resetter/logout', None, A)
    _, status = open_link(token)
    check(f'a reset link asked for as {typed!r} is revoked by a logout', token is not None and status == 'KO', f'{token is not None} {status}')

# A link opened before the logout can't set the password after it.
token = request_reset('resetter')
client, status = open_link(token)
api.req('POST', '/api/admin/users/resetter/logout', None, A)
_, _, body = client.req('POST', '/api/reset-password', {'password': 'a-hijacked-password-9'})
check('an opened reset link can not set the password after a logout', status == 'OK' and json.loads(body).get('status') == 'KO', f'{status} {body}')

# A reset which isn't interrupted still works.
token = request_reset('resetter')
client, status = open_link(token)
st, _, body = client.req('POST', '/api/reset-password', {'password': 'a-new-password-9'})
check('an uninterrupted reset sets the password', status == 'OK' and st == 200 and login('resetter', 'a-new-password-9')[1] == 200, f'{status} {st} {body[:200]}')

sys.exit(summary())
