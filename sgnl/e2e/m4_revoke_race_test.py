# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""A revocation outlives a request which was already running: the portal session and the tokens which such a request
saves after a logout are refused. The race is reproduced by restoring the rows the logout ended."""

import os
import sqlite3
import sys
import time

from lib import Client, admin_headers, authorize, check, forward_auth, introspect, login, refresh, summary

DB = os.path.join(os.environ['E2E_DIR'], 'db.sqlite3')

api, A = Client(), admin_headers()
api.req('POST', '/api/admin/users', {'username': 'racer', 'email': 'racer@example.com', 'password': 'a-long-password-8'}, A)

user, _ = login('racer', 'a-long-password-8')
tokens = authorize(user, 'app')
check('logged in: portal session and tokens work', forward_auth(user) == 200 and introspect('app', tokens['access_token']) is True)

db = sqlite3.connect(DB)
sessions = db.execute("SELECT * FROM session WHERE username = 'racer'").fetchall()
subjects = [row[0] for row in db.execute("SELECT identifier FROM user_opaque_identifier WHERE username = 'racer'")]
db.close()

# The logout must start in a later second than the login, as login times have a resolution of a second.
time.sleep(1.1)
api.req('POST', '/api/admin/users/racer/logout', None, A)

# What a request which was already running could save after the logout: the session and the tokens.
db = sqlite3.connect(DB)
for row in sessions:
    db.execute('INSERT OR REPLACE INTO session VALUES (' + ','.join('?' * len(row)) + ')', row)
for table in ['oauth2_access_token_session', 'oauth2_refresh_token_session', 'oauth2_openid_connect_session']:
    db.execute(f"UPDATE {table} SET revoked = FALSE WHERE subject IN ({','.join('?' * len(subjects))})", subjects)
db.commit()
restored = db.execute("SELECT COUNT(*) FROM session WHERE username = 'racer'").fetchone()[0]
db.close()

check('the race is reproduced: the session row is back', restored == len(sessions) and restored > 0, restored)
check('a portal session saved after the logout is refused (forward auth)', forward_auth(user) != 200)
check('a refresh token from before the logout is refused', refresh('app', tokens['refresh_token']) != 200)
check('an access token from before the logout is inactive', introspect('app', tokens['access_token']) is False)

# A login after the logout is not affected.
again, st = login('racer', 'a-long-password-8')
tokens = authorize(again, 'app')
check('a new login after the logout works', st == 200 and forward_auth(again) == 200 and refresh('app', tokens['refresh_token']) == 200)

sys.exit(summary())
