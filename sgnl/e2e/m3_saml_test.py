# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

"""M3 (C6): the SAML 2.0 identity provider, against the local service provider in samlsp/."""

import atexit
import base64
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import http.client

from lib import BASE, ISS, Client, admin_headers, check, forward_auth, login, summary

DIR = os.environ['E2E_DIR']
SPS = {name: 9100 + i for i, name in enumerate(['sp1', 'sp2', 'sp3', 'sp4', 'unknown'], start=1)}

api, A = Client(), admin_headers()

api.req('POST', '/api/admin/groups', {'name': 'staff'}, A)
api.req('POST', '/api/admin/users', {'username': 'sam', 'email': 'sam@example.com', 'groups': ['staff'],
                                     'password': 'a-long-password-5'}, A)

# Metadata.
st, h, metadata = api.req('GET', '/api/saml/metadata')
check('metadata is served as XML', st == 200 and 'EntityDescriptor' in metadata and 'xml' in h.get('Content-Type', ''), h.get('Content-Type'))
check('the entity ID is the issuer', f'entityID="{ISS}"' in metadata, metadata[:300])
check('the SSO URL is the Keycloak path (enable_keycloak_endpoints)', f'Location="{ISS}/protocol/saml"' in metadata)

st, _, descriptor = api.req('GET', '/protocol/saml/descriptor')
check('metadata is also served at Keycloak\'s path', st == 200 and f'entityID="{ISS}"' in descriptor, descriptor[:200])

conn = http.client.HTTPConnection('127.0.0.1', 9091)
conn.request('GET', '/api/saml/metadata', headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'id.example.com', 'Host': 'id.example.com'})
check('an issuer which is not a configured authelia_url gets no SAML (404)', conn.getresponse().status == 404)

with open(os.path.join(DIR, 'idp-metadata.xml'), 'w') as f:
    f.write(metadata)

procs = []

for name, port in SPS.items():
    procs.append(subprocess.Popen([os.path.join(DIR, 'samlsp'), '-listen', f'127.0.0.1:{port}',
                                   '-entity-id', f'https://{name}.example.com/saml/metadata',
                                   '-acs', f'https://{name}.example.com/saml/acs',
                                   '-idp-metadata', os.path.join(DIR, 'idp-metadata.xml'),
                                   '-key', os.path.join(DIR, 'sp.key'), '-cert', os.path.join(DIR, 'sp.crt')],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

atexit.register(lambda: [p.kill() for p in procs])
time.sleep(1)


def sp(name, method, path, form=None):
    conn = http.client.HTTPConnection('127.0.0.1', SPS[name])
    body = urllib.parse.urlencode(form) if form else None
    conn.request(method, path, body, {'Content-Type': 'application/x-www-form-urlencoded'} if form else {})

    return json.loads(conn.getresponse().read())


def idp_path(url):
    """The path of an identity provider URL below the realm, which the client prefixes again."""
    return urllib.parse.urlparse(url).path[len(BASE):] + ('?' + urllib.parse.urlparse(url).query if urllib.parse.urlparse(url).query else '')


def send_request(client, name, binding='redirect', sign=False, force=False, acs='', tamper=False, start=None, context=None):
    """Sends an authentication request of the service provider through the client and returns the HTTP answer."""
    extra = f'&class={urllib.parse.quote(context[0])}&comparison={context[1]}' if context else ''
    start = start or sp(name, 'GET', f'/start?binding={binding}&sign={int(sign)}&force={int(force)}&acs={urllib.parse.quote(acs)}{extra}')

    if tamper:
        # Changes the signed request after signing: the signature no longer covers it.
        xml = base64.b64decode(start['form']['SAMLRequest']).decode()
        start['form']['SAMLRequest'] = base64.b64encode(xml.replace('ID="id-', 'ID="id-0', 1).encode()).decode()

    if binding == 'post':
        return client.req('POST', idp_path(start['url']), start['form'], form=True)

    return client.req('GET', idp_path(start['url']))


def deliver(name, page):
    """Posts the response of an auto-submitting page to the service provider and returns its verdict."""
    form = dict(re.findall(r'name="(SAMLResponse|RelayState)" value="([^"]*)"', page))

    if 'SAMLResponse' not in form:
        return {'error': 'no response form', 'page': page[:200]}

    verdict = sp(name, 'POST', '/acs', {k: html.unescape(v) for k, v in form.items()})
    verdict['relay_state'] = html.unescape(form.get('RelayState', ''))

    return verdict


def anonymous_login(name, binding='redirect', sign=False):
    """An SP-initiated login of a new browser: the request, the portal's first factor, and the resumed response."""
    client = Client()
    st, h, _ = send_request(client, name, binding=binding, sign=sign)
    fid = flow_id(h.get('Location', ''))
    st, _, b = client.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5', 'flow': 'saml', 'flowID': fid})
    resume = json.loads(b).get('data', {}).get('redirect', '')
    st, _, page = client.req('GET', idp_path(resume))

    return client, deliver(name, page)


def flow_id(location):
    return urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('flow_id', [None])[0]


# SP-initiated login with the HTTP-Redirect binding: the anonymous user is sent to the portal and resumed after login.
user = Client()
st, h, _ = send_request(user, 'sp1')
location = h.get('Location', '')
fid = flow_id(location)
check('an anonymous user is sent to the portal with the SAML flow', st == 303 and 'flow=saml' in location and fid, location)

st, _, b = user.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5', 'flow': 'saml', 'flowID': fid})
resume = json.loads(b).get('data', {}).get('redirect', '')
check('after login the portal is told to resume the request', st == 200 and '/api/saml/sso/resume?flow_id=' in resume, b)

st, h, page = user.req('GET', idp_path(resume))
check('the response page is HTML, allowed to submit itself by the Content-Security-Policy only',
      st == 200 and h.get('Content-Type', '').startswith('text/html') and "script-src 'sha256-" in h.get('Content-Security-Policy', '') and 'unsafe-inline' not in h.get('Content-Security-Policy', ''),
      h.get('Content-Security-Policy'))
result = deliver('sp1', page)
check('the service provider accepts the response, NameID = email',
      result.get('name_id') == 'sam@example.com' and result.get('name_id_format', '').endswith('emailAddress'), result)
check('RelayState comes back unchanged', result.get('relay_state') == 'relay-1', result)
signed = base64.b64decode(html.unescape(re.search(r'name="SAMLResponse" value="([^"]*)"', page).group(1))).decode()
check('sign both: the response and the assertion are signed', signed.count('SignatureValue>') == 4, signed.count('SignatureValue>'))
check('the assertion states no client IP address', 'Address=' not in signed, re.findall(r'Address="[^"]*"', signed))
check('the configured attributes are released', result.get('attributes', {}).get('groups') == ['staff']
      and result.get('attributes', {}).get('email') == ['sam@example.com'], result)

st, _, _ = user.req('GET', idp_path(resume))
check('a resumed flow can not be used again', st == 400)

st, _, _ = user.req('GET', '/api/saml/sso/resume?flow_id=00000000-0000-0000-0000-000000000000')
check('an unknown flow is refused', st == 400)

# An expired flow: a pending request is kept for 15 minutes; this one is aged in the database.
expiring = Client()
st, h, _ = send_request(expiring, 'sp1')
fid_expired = flow_id(h.get('Location', ''))
db = sqlite3.connect(os.path.join(DIR, 'db.sqlite3'))
aged = db.execute("UPDATE saml_flows SET expires_at = datetime('now', '-1 minute') WHERE flow_id = ?", (fid_expired,)).rowcount
db.commit()
check('the pending request was aged in the database', aged == 1, aged)
db.close()
st, _, b = expiring.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5', 'flow': 'saml', 'flowID': fid_expired})
check('after login, an expired flow is not resumed', st != 200 or '/api/saml/sso/resume' not in b, b[:160])
st, _, _ = expiring.req('GET', f'/api/saml/sso/resume?flow_id={fid_expired}')
check('an expired flow is refused at the resume endpoint', st == 400)

# Requested authentication contexts (the session is one factor: PasswordProtectedTransport). Only a class stronger than
# the session's is refused; a weaker or unknown class is answered, as Keycloak does.
PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
for name, context, ok in [
    ('the session\'s own class, exact', (PPT, 'exact'), True),
    ('a weaker class, minimum', ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'minimum'), True),
    ('a weaker class, exact', ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'exact'), True),
    ('an unknown class, exact', ('urn:example:unknown-class', 'exact'), True),
    ('MFA, minimum (stronger than the session)', ('https://refeds.org/profile/mfa', 'minimum'), False),
]:
    st, _, page = send_request(user, 'sp1', context=context)
    result = deliver('sp1', page)
    if ok:
        check(f'requested context {name}: answered', result.get('name_id') == 'sam@example.com', result)
    else:
        check(f'requested context {name}: NoAuthnContext', any(c.endswith(':NoAuthnContext') for c in result.get('status_codes') or []), result)

# Bounded requests: a pending request is kept for each anonymous one.
start = sp('sp1', 'GET', '/start?binding=post')
form = dict(start['form'], RelayState='x' * 1025)
st, _, _ = Client().req('POST', idp_path(start['url']), form, form=True)
check('a RelayState longer than 1 KB is refused', st == 400, st)
form = dict(start['form'], SAMLRequest='A' * (16 * 1024 + 1))
st, _, _ = Client().req('POST', idp_path(start['url']), form, form=True)
check('a SAMLRequest longer than 16 KB is refused', st == 400, st)
form = dict(start['form'], RelayState='x' * 1024)
st, h, _ = Client().req('POST', idp_path(start['url']), form, form=True)
check('a RelayState of 1 KB is accepted', st == 303, st)

# The library also takes a request in the SAMLRedirectQuery field of a POST: its RelayState is bounded too, and nothing
# that large is stored.
redirect = sp('sp1', 'GET', '/start?binding=redirect')['url']
query = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)
inner = urllib.parse.urlencode({'SAMLRequest': query['SAMLRequest'][0], 'RelayState': 'x' * (3 * 1024 * 1024)})
st, _, _ = Client().req('POST', idp_path(redirect.split('?')[0]), {'SAMLRedirectQuery': inner}, form=True)
db = sqlite3.connect(os.path.join(DIR, 'db.sqlite3'))
largest = db.execute('SELECT COALESCE(MAX(LENGTH(form)), 0) FROM saml_flows').fetchone()[0]
db.close()
check('a 3 MB RelayState in SAMLRedirectQuery is refused and not stored', st in (400, 413) and largest < 32 * 1024, f'{st} {largest}')

# A logged in user gets the response at once, with the HTTP-POST binding and at Keycloak's path.
st, _, page = send_request(user, 'sp1', binding='post')
result = deliver('sp1', page)
check('HTTP-POST binding with a session: response at once', result.get('name_id') == 'sam@example.com', result)

# Step-up: a one-factor session against a two-factor service provider.
st, h, _ = send_request(user, 'sp2')
fid2 = flow_id(h.get('Location', ''))
check('a one-factor session is sent to the portal for a two-factor service provider', st == 303 and fid2, h.get('Location'))

st, _, b = user.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5', 'flow': 'saml', 'flowID': fid2})
check('after the first factor the portal asks for the second factor', st == 200 and 'redirect' not in b, b)

st, h, _ = user.req('GET', f'/api/saml/sso/resume?flow_id={fid2}')
check('resuming with an insufficient session is refused, not sent to the portal again (no loop)', st == 403, f'{st} {h.get("Location")}')

# Signed requests.
st, _, page = send_request(user, 'sp3', sign=False)
check('an unsigned request is refused where the service provider signs its requests', 'error' in deliver('sp3', page) or st >= 400, page[:200])

for binding in ['redirect', 'post']:
    st, _, page = send_request(user, 'sp3', binding=binding, sign=True)
    result = deliver('sp3', page)
    check(f'a signed {binding} request is answered', result.get('name_id') == 'sam@example.com', result)

st, _, page = send_request(user, 'sp3', binding='post', sign=True, tamper=True)
check('a tampered signed request gets no assertion', 'SAMLResponse' not in page or 'error' in deliver('sp3', page), f'{st} {page[:120]}')

# An assertion consumer service URL which isn't registered for the service provider.
st, _, page = send_request(user, 'sp1', acs='https://evil.example.com/saml/acs')
check('an unregistered ACS URL gets no response', 'evil.example.com' not in page and 'SAMLResponse' not in page, f'{st} {page[:160]}')

# Signed requests through the portal: the stored request is replayed as a form, so the signature of either binding
# must still be checked and accepted after login.
for binding in ['redirect', 'post']:
    _, result = anonymous_login('sp3', binding=binding, sign=True)
    check(f'a signed {binding} request is answered after login through the portal', result.get('name_id') == 'sam@example.com', result)

# Replay: the same request twice.
start = sp('sp1', 'GET', '/start?binding=post')
st, _, first = send_request(user, 'sp1', binding='post', start=start)
st, _, again = send_request(user, 'sp1', binding='post', start=start)
check('a replayed request gets no second assertion', 'SAMLResponse' in first and ('SAMLResponse' not in again or 'error' in deliver('sp1', again)), f'{st} {again[:160]}')

# Fresh user data with a live session: group membership and email are read from the user, not from the session.
api.req('POST', '/api/admin/groups', {'name': 'admins'}, A)
api.req('PUT', '/api/admin/users/sam/groups/admins', None, A)
st, _, page = send_request(user, 'sp4')
check('a member of the allowed group gets an assertion', deliver('sp4', page).get('name_id') == 'sam@example.com')
api.req('DELETE', '/api/admin/users/sam/groups/admins', None, A)
st, _, page = send_request(user, 'sp4')
check('removed from the group with a live session: RequestDenied', any(c.endswith(':RequestDenied') for c in deliver('sp4', page).get('status_codes') or []))
api.req('PATCH', '/api/admin/users/sam', {'email': 'sam.new@example.com'}, A)
st, _, page = send_request(user, 'sp1')
result = deliver('sp1', page)
check('a changed email is the NameID at once', result.get('name_id') == 'sam.new@example.com', result)

# Group restriction.
st, _, page = send_request(user, 'sp4')
result = deliver('sp4', page)
check('a user outside the allowed groups gets RequestDenied, not an assertion', 'error' in result and any(c.endswith(':RequestDenied') for c in result.get('status_codes') or []), result)

# Unknown service provider.
st, _, page = send_request(user, 'unknown')
check('an unknown service provider gets no response', st >= 400 and 'SAMLResponse' not in page, f'{st} {page[:120]}')

# ForceAuthn: the portal session ends and the user logs in again, then gets the response; the login is fresh.
forced = Client()
forced.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5'})
check('ForceAuthn setup: logged in', forward_auth(forced) == 200)
time.sleep(1.1)
st, h, _ = send_request(forced, 'sp1', force=True)
fid_forced = flow_id(h.get('Location', ''))
check('ForceAuthn sends a logged in user to the portal to log in again', st == 303 and fid_forced, f'{st} {h.get("Location")}')
check('ForceAuthn ended the portal session', forward_auth(forced) != 200)
st, _, b = forced.req('POST', '/api/firstfactor', {'username': 'sam', 'password': 'a-long-password-5', 'flow': 'saml', 'flowID': fid_forced})
resume = json.loads(b).get('data', {}).get('redirect', '')
st, _, page = forced.req('GET', idp_path(resume))
result = deliver('sp1', page)
check('after the fresh login the ForceAuthn request is answered', result.get('name_id') == 'sam.new@example.com', result)

# A disabled user with a live session gets nothing.
api.req('PATCH', '/api/admin/users/sam', {'disabled': True}, A)
st, h, page = send_request(user, 'sp1')
check('a disabled user gets no assertion', 'SAMLResponse' not in page, f'{st} {page[:120]}')

sys.exit(summary())
