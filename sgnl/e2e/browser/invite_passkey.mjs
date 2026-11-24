// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

// M2 (C4) browser test: an invited user sets a password, registers a passkey, logs in with it, and is refused once
// disabled. Run by run.sh.
import { chromium, request } from 'playwright-core';
import fs from 'node:fs';

const NOTIF = process.argv[2];
const ISS = 'https://id.example.com:9091/realms/test';
const results = [];
const check = (name, ok, detail = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${!ok && detail ? '  [' + detail + ']' : ''}`); };

const api = await request.newContext({ baseURL: 'https://127.0.0.1:9091', ignoreHTTPSErrors: true,
  extraHTTPHeaders: { 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'id.example.com:9091' } });
const tok = await (await api.post('/realms/test/api/oidc/token', { form: { grant_type: 'client_credentials', scope: 'authelia.admin.read authelia.admin.write', audience: `${ISS}/api/admin` },
  headers: { Authorization: 'Basic ' + Buffer.from('agent:insecure_secret').toString('base64') } })).json();
const A = { Authorization: `Bearer ${tok.access_token}` };
await api.post('/realms/test/api/admin/users', { headers: A, data: { username: 'newbie', email: 'newbie@example.com', display_name: 'New Bie' } });
const before = fs.existsSync(NOTIF) ? fs.statSync(NOTIF).size : 0;
const inv = await api.post('/realms/test/api/admin/users/newbie/invite', { headers: A });
check('agent invites the user', inv.status() === 202, await inv.text());
const mail = fs.readFileSync(NOTIF, 'utf8');
const link = (mail.match(/https:\/\/id\.example\.com:9091\/realms\/test\/account-setup\?token=[A-Za-z0-9._-]+/g) || []).pop();
check('the mail carries the invite link', !!link);

const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--host-resolver-rules=MAP id.example.com 127.0.0.1'] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const cdp = await ctx.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

await page.goto(link);
await page.waitForSelector('#password1-textfield:not([disabled])', { timeout: 20000 });
check('the invite page asks for a password', true);
await page.fill('#password1-textfield', 'a-browser-password-1');
await page.fill('#password2-textfield', 'a-browser-password-1');
await page.click('#reset-button');
await page.waitForURL(/settings\/two-factor-authentication/, { timeout: 20000 }).catch(() => {});
check('the user lands on the passkey settings, logged in', /settings\/two-factor-authentication/.test(page.url()), page.url());

await page.click('#webauthn-credential-add', { timeout: 20000 });
await page.waitForSelector('#webauthn-credential-description', { timeout: 10000 });
const prompted = await page.locator('text=/one-time code|One-Time Code/i').count();
check('no extra one-time code is asked for (the session is elevated)', prompted === 0);
await page.fill('#webauthn-credential-description', 'laptop');
await page.click('#dialog-next');
await page.waitForTimeout(3000);
const creds = await (await api.get('/realms/test/api/admin/users/newbie', { headers: A })).json();
check('the passkey is registered', (creds.credentials || []).includes('webauthn'), JSON.stringify(creds.credentials));

let latest = null;

async function passkeyLogin() {
  const c = await browser.newContext({ ignoreHTTPSErrors: true });
  const p = await c.newPage();
  const s = await c.newCDPSession(p);
  await s.send('WebAuthn.enable');
  const { authenticatorId: id } = await s.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  // The credential moves between authenticators with its current sign count, so the server never sees a clone.
  const credentials = latest ?? (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  for (const cred of credentials) await s.send('WebAuthn.addCredential', { authenticatorId: id, credential: cred });
  await p.goto(`https://id.example.com:9091/realms/test/`);
  // The login page starts a conditional (autofill) passkey request by itself, which the virtual authenticator answers.
  await p.waitForTimeout(5000);
  if (await p.locator('#passkey-sign-in-button:not([disabled])').count()) {
    await p.click('#passkey-sign-in-button');
    await p.waitForTimeout(4000);
  }
  // The portal asks whether to remember the device before it completes the passkey login.
  const no = p.getByRole('button', { name: /^no$/i });
  if (await no.count()) {
    await no.click();
    await p.waitForTimeout(3000);
  }
  const state = await p.evaluate(async () => (await fetch('/realms/test/api/state')).json()).catch(() => ({}));
  latest = (await s.send('WebAuthn.getCredentials', { authenticatorId: id })).credentials;
  await c.close();
  return state?.data?.authentication_level ?? 0;
}

check('passkey login works', (await passkeyLogin()) >= 1);
await api.post('/realms/test/api/admin/users/newbie/logout', { headers: A });
await new Promise((resolve) => setTimeout(resolve, 1100));
check('passkey login works after a logout', (await passkeyLogin()) >= 1);
await api.patch('/realms/test/api/admin/users/newbie', { headers: A, data: { disabled: true } });
check('passkey login is refused for a disabled user', (await passkeyLogin()) === 0);

await browser.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
