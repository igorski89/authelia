// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

// M3 (C6) browser test: SAML single sign-on through the real portal at a two-factor service provider, with a password
// and a passkey, and again for a user who is already logged in when the request arrives as a cross-site HTTP-POST.
// The local service provider (samlsp, port 9102) makes the requests and checks the responses. Run by run.sh.
import { chromium, request } from 'playwright-core';
import fs from 'node:fs';

const NOTIF = process.argv[2];
const ISS = 'https://id.example.com:9091/realms/test';
const SP = 'http://127.0.0.1:9102';
const ACS = 'https://sp2.example.com/saml/acs';
const results = [];
const check = (name, ok, detail = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${!ok && detail ? '  [' + detail + ']' : ''}`); };

const api = await request.newContext({ baseURL: 'https://127.0.0.1:9091', ignoreHTTPSErrors: true,
  extraHTTPHeaders: { 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'id.example.com:9091' } });
const tok = await (await api.post('/realms/test/api/oidc/token', { form: { grant_type: 'client_credentials', scope: 'authelia.admin.read authelia.admin.write', audience: `${ISS}/api/admin` },
  headers: { Authorization: 'Basic ' + Buffer.from('agent:insecure_secret').toString('base64') } })).json();
const A = { Authorization: `Bearer ${tok.access_token}` };

// A user with a password and a passkey, set up through an invite as in invite_passkey.mjs.
await api.post('/realms/test/api/admin/users', { headers: A, data: { username: 'samuser', email: 'samuser@example.com' } });
await api.post('/realms/test/api/admin/users/samuser/invite', { headers: A });
const link = (fs.readFileSync(NOTIF, 'utf8').match(/https:\/\/id\.example\.com:9091\/realms\/test\/account-setup\?token=[A-Za-z0-9._-]+/g) || []).pop();

const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--host-resolver-rules=MAP id.example.com 127.0.0.1'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const cdp = await ctx.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

await page.goto(link);
await page.waitForSelector('#password1-textfield:not([disabled])', { timeout: 20000 });
await page.fill('#password1-textfield', 'a-saml-password-1');
await page.fill('#password2-textfield', 'a-saml-password-1');
await page.click('#reset-button');
await page.waitForURL(/settings\/two-factor-authentication/, { timeout: 20000 });
await page.click('#webauthn-credential-add', { timeout: 20000 });
await page.waitForSelector('#webauthn-credential-description', { timeout: 10000 });
await page.fill('#webauthn-credential-description', 'laptop');
await page.click('#dialog-next');
await page.waitForTimeout(3000);
const user = await (await api.get('/realms/test/api/admin/users/samuser', { headers: A })).json();
check('setup: the user has a passkey', (user.credentials || []).includes('webauthn'), JSON.stringify(user.credentials));
const credentials = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
await ctx.close();

// A fresh browser with the passkey and no session.
const c = await browser.newContext({ ignoreHTTPSErrors: true });
const p = await c.newPage();
const s = await c.newCDPSession(p);
await s.send('WebAuthn.enable');
const { authenticatorId: id } = await s.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
for (const cred of credentials) await s.send('WebAuthn.addCredential', { authenticatorId: id, credential: cred });

// The service provider's assertion consumer service is caught in the browser, and its form handed to samlsp.
let acs = null;
await c.route(ACS, async (route) => {
  acs = route.request().postData();
  await route.fulfill({ status: 200, contentType: 'text/html', body: '<p>received</p>' });
});
const violations = [];
p.on('console', (m) => { if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) violations.push(m.text()); });

async function waitForACS(timeout = 40000) {
  const end = Date.now() + timeout;
  while (!acs && Date.now() < end) {
    // Whatever the portal asks along the way: the password, or whether to remember the device.
    if (await p.locator('#password-textfield:not([disabled])').count() && !(await p.inputValue('#password-textfield'))) {
      if (await p.locator('#username-textfield:not([disabled])').count()) await p.fill('#username-textfield', 'samuser');
      await p.fill('#password-textfield', 'a-saml-password-1');
      await p.click('#sign-in-button');
    }
    const no = p.getByRole('button', { name: /^no$/i });
    if (await no.count()) await no.click().catch(() => {});
    await p.waitForTimeout(500);
  }
  const got = acs;
  acs = null;
  return got;
}

async function verdict(body) {
  const r = await fetch(`${SP}/acs`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  return r.json();
}

// 1. SP-initiated, HTTP-Redirect binding, no session: portal, password and passkey, then the response.
const start = await (await fetch(`${SP}/start?binding=redirect`)).json();
await p.goto(start.url);
const body = await waitForACS();
check('the response reaches the ACS after password and passkey in the portal', !!body, `${p.url()} ${(await p.content()).slice(0, 400)}`);
const v1 = body ? await verdict(body) : {};
check('the service provider accepts it: NameID = email', v1.name_id === 'samuser@example.com', JSON.stringify(v1));
check('RelayState comes back unchanged', new URLSearchParams(body || '').get('RelayState') === 'relay-1');
check('the response page submits itself without CSP violations', violations.length === 0, violations.join(' | '));
const state = await p.evaluate(async () => (await fetch('/realms/test/api/state')).json()).catch(() => ({}));
await p.goto(`${ISS}/`);
const level = await p.evaluate(async () => (await fetch('/realms/test/api/state')).json()).then((r) => r.data.authentication_level).catch(() => 0);
check('the session is two-factor afterwards', level === 2, JSON.stringify(state));

// 2. Logged in, HTTP-POST binding from another site: the Lax session cookie isn't sent with the POST, so the request
//    goes through the portal, which must resume it at once.
const post = await (await fetch(`${SP}/start?binding=post`)).json();
await p.goto('about:blank');
await p.setContent(`<form method="post" action="${post.url}">` +
  Object.entries(post.form).map(([k, val]) => `<input type="hidden" name="${k}" value="${val}">`).join('') +
  '</form><script>document.forms[0].submit()</script>');
const body2 = await waitForACS(20000);
const v2 = body2 ? await verdict(body2) : {};
check('a logged in user gets the response for a cross-site HTTP-POST request without logging in again',
  v2.name_id === 'samuser@example.com', `${p.url()} ${JSON.stringify(v2)} ${(await p.content()).slice(0, 300)}`);

await browser.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
