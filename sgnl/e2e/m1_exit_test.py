# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""M1 exit test: the agent manages users with the administration API, and users log in to apps."""

import json
import sys
import time

from lib import ISS, Client, admin_headers, authorize, basic, check, claims, login, summary

# A throwaway Keycloak 26.8.2 argon2id hash (m=7168, t=5, p=1) of the password 'test-pass-123'.
KC = '$argon2id$v=19$m=7168,t=5,p=1$dk016MYDrSYOe3uI8Hj8Hg$JkADnvsSGzIE22w4StMki1156N6zJRBSoOA2GZ/j17s'

api = Client()
A = admin_headers()
check('agent gets a client-credentials token', A['Authorization'].startswith('Bearer '))

st, _, b = api.req('POST', '/api/admin/groups', {'name': 'staff'}, A)
check('agent creates group', st in (201, 409), b)

st, _, b = api.req('POST', '/api/admin/users', {'username': 'KC.User', 'email': 'KC.User@Example.com',
                                                'display_name': 'KC User', 'given_name': 'KC', 'family_name': 'User',
                                                'groups': ['staff'], 'password_digest': KC}, A)
check('agent imports user with Keycloak argon2id digest', st == 201, b)

u, st = login('kc.user@example.com', 'test-pass-123')
check('imported user logs in by email with the Keycloak password', st == 200)

t = authorize(u, 'app')
idt = claims(t['id_token'])
check('ID token carries groups, email, name, preferred_username',
      idt.get('groups') == ['staff'] and idt.get('email') == 'kc.user@example.com' and idt.get('name') == 'KC User'
      and idt.get('preferred_username') == 'kc.user', json.dumps(idt))
check('ID token issuer is the realm path', idt.get('iss') == ISS, idt.get('iss'))
check('access token is a JWT (OpenCloud-style clients)', t['access_token'].count('.') == 2)

idt_default = claims(authorize(u, 'test')['id_token'])
check('a client without its own claims policy gets the default one (groups in the ID token)',
      idt_default.get('groups') == ['staff'] and idt_default.get('email') == 'kc.user@example.com', json.dumps(idt_default))

st, _, b = u.req('POST', '/api/oidc/introspection', {'token': t['access_token']}, basic('app'), form=True)
check('introspection reports the access token active', st == 200 and json.loads(b).get('active') is True, b[:120])

st, _, b = api.req('PATCH', '/api/admin/users/kc.user', {'disabled': True}, A)
check('agent disables user', st == 200, b)

st, _, b = u.req('POST', '/api/oidc/introspection', {'token': t['access_token']}, basic('app'), form=True)
check('introspection reports the access token inactive for a disabled user',
      st == 200 and json.loads(b).get('active') is False, b[:160])

st, _, b = u.req('POST', '/api/oidc/token', {'grant_type': 'refresh_token', 'refresh_token': t['refresh_token']},
                 basic('app'), form=True)
check('refresh token refused for disabled user', st == 400 and 'invalid_grant' in b, b[:120])

api.req('PATCH', '/api/admin/users/kc.user', {'disabled': False}, A)

st, _, b = api.req('PUT', '/api/admin/users/kc.user/password', {'password': 'a-brand-new-password-1'}, A)
check('agent sets a new password', st == 204, b)
check('old password refused', login('kc.user', 'test-pass-123')[1] == 401)
check('new password accepted, username any case', login('KC.USER', 'a-brand-new-password-1')[1] == 200)

st, _, b = api.req('DELETE', '/api/admin/users/kc.user', None, A)
check('agent deletes user', st == 204, b)
check('deleted user cannot log in', login('kc.user', 'a-brand-new-password-1')[1] == 401)

st, _, b = api.req('POST', '/api/admin/users', {'username': 'kc.user', 'email': 'other@example.com'}, A)
check('deleted username never reused', st == 409, b)

st, _, b = api.req('GET', '/api/admin/users', None, {'Authorization': 'Bearer ' + t['access_token']})
check('user token refused by admin API', st in (401, 403), b[:100])

st, _, b = api.req('GET', '/api/admin/users', None, {})
check('request without a token refused', st == 401)

st, _, b = u.req('GET', '/api/admin/users')
check('browser session refused by admin API', st == 401)

st, _, b = api.req('POST', '/api/oidc/token', {'grant_type': 'client_credentials', 'scope': 'some.api'}, basic('other'),
                   form=True)
st, _, b = api.req('GET', '/api/admin/whoami', None, {'Authorization': 'Bearer ' + json.loads(b)['access_token']})
check('client without an admin scope refused', st == 403 and 'insufficient_scope' in b, b[:100])

short = admin_headers('agent-short', 'authelia.admin.read')
st, _, b = api.req('GET', '/api/admin/whoami', None, short)
check('short-lived token accepted before expiry', st == 200, b[:100])

time.sleep(3)

st, _, b = api.req('GET', '/api/admin/whoami', None, short)
check('expired token refused', st == 401 and 'invalid_token' in b, b[:100])


sys.exit(summary())
