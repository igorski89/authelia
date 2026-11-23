# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""M2 (C7): the audit of administration changes and the authentication events."""

import json
import sys

from lib import Client, admin_headers, check, login, summary

api, A = Client(), admin_headers()

api.req('POST', '/api/admin/users', {'username': 'audited', 'email': 'audited@example.com',
                                     'password': 'a-long-password-7'}, A)
api.req('PATCH', '/api/admin/users/audited', {'display_name': 'Audited'}, A)
login('audited', 'a-long-password-7')
login('audited', 'wrong-password')

st, _, b = api.req('GET', '/api/admin/audit?username=audited', None, A)
entries = json.loads(b).get('entries', [])
check('audit lists the changes newest first', st == 200 and [e['action'] for e in entries] == ['user.update', 'user.create'], b[:300])
check('audit records the client as the actor', entries and all(e['actor'] == 'client:agent' for e in entries), b[:300])
check('audit records the changed fields, never the password',
      entries and entries[0].get('details') == {'fields': ['display_name']} and 'a-long-password-7' not in b, b[:300])

st, _, b = api.req('GET', '/api/admin/events?username=audited', None, A)
events = json.loads(b).get('events', [])
check('events list the login attempts, newest first',
      st == 200 and [e['successful'] for e in events[:2]] == [False, True] and events[0]['type'] == '1FA', b[:300])

st, _, b = api.req('GET', '/api/admin/audit', None, admin_headers('agent-short', 'authelia.admin.read'))
check('a read-only token reads the audit', st == 200, b[:100])

sys.exit(summary())
