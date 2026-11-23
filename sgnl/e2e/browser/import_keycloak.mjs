// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

// C8 browser test: after the Keycloak import, every user logs in through the portal with the password from Keycloak
// and, as the second factor, the same virtual passkey which registered in Keycloak. carol-test's passkey is a synced
// style key (resident, backup eligible and backed up), whose flags Keycloak doesn't keep: Authelia must take them from
// the first sign in, and keep them for the second. Run by import_keycloak.sh.
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';

const FIXTURES = process.argv[2];
// second-factor: the passkeys are the second factor, as in Keycloak. passkey-login: Authelia also offers passkey login,
// and upgrades credentials to passkeys, so carol-test first signs in with her passkey alone.
const MODE = process.argv[3] ?? 'second-factor';
const PORTAL = 'https://id.example.com:9095/realms/test/';
const results = [];
const check = (name, ok, detail = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${!ok && detail ? '  [' + detail + ']' : ''}`); };

const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--host-resolver-rules=MAP id.example.com 127.0.0.1'] });

// Logs a user in with the password and then the passkey, and returns the authentication level and the credential with
// its new sign count.
async function login(username, credential) {
  const c = await browser.newContext({ ignoreHTTPSErrors: true });
  const p = await c.newPage();
  const s = await c.newCDPSession(p);
  await s.send('WebAuthn.enable');
  const { authenticatorId } = await s.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: credential.isResidentCredential, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
    defaultBackupEligibility: credential.backupEligibility ?? false, defaultBackupState: credential.backupState ?? false } });
  await s.send('WebAuthn.addCredential', { authenticatorId, credential });

  await p.goto(PORTAL);
  await p.waitForSelector('#username-textfield', { timeout: 20000 });
  await p.fill('#username-textfield', username);
  await p.fill('#password-textfield', `Throwaway-${username}-pw1`);
  await p.click('#sign-in-button');

  let level = 0;
  const end = Date.now() + 25000;

  while (Date.now() < end && level < 2) {
    await p.waitForTimeout(1000);
    const no = p.getByRole('button', { name: /^no$/i });
    if (await no.count()) await no.click().catch(() => {});
    level = await p.evaluate(async () => (await fetch('/realms/test/api/state')).json()).then((r) => r.data.authentication_level).catch(() => 0);
  }

  const [after] = (await s.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  await c.close();

  return { level, credential: after ?? credential };
}

// Signs in with the passkey alone, and returns the authentication level and the credential.
async function passkeyLogin(credential) {
  const c = await browser.newContext({ ignoreHTTPSErrors: true });
  const p = await c.newPage();
  const s = await c.newCDPSession(p);
  await s.send('WebAuthn.enable');
  const { authenticatorId } = await s.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    automaticPresenceSimulation: true, defaultBackupEligibility: true, defaultBackupState: true } });
  await s.send('WebAuthn.addCredential', { authenticatorId, credential });

  await p.goto(PORTAL);
  // The login page starts a conditional (autofill) passkey request by itself, which the virtual authenticator answers.
  await p.waitForTimeout(5000);
  if (await p.locator('#passkey-sign-in-button:not([disabled])').count()) {
    await p.click('#passkey-sign-in-button');
    await p.waitForTimeout(4000);
  }
  const no = p.getByRole('button', { name: /^no$/i });
  if (await no.count()) {
    await no.click();
    await p.waitForTimeout(3000);
  }

  const level = await p.evaluate(async () => (await fetch('/realms/test/api/state')).json()).then((r) => r.data.authentication_level).catch(() => 0);
  const [after] = (await s.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  await c.close();

  return { level, credential: after ?? credential };
}

function fixture(username) {
  let credential = JSON.parse(fs.readFileSync(path.join(FIXTURES, `passkey-${username}.json`), 'utf8'));
  credential = Array.isArray(credential) ? credential[0] : credential;
  // The virtual authenticator counts on from the sign count Keycloak saw last, for the RP ID of this Authelia (see
  // import_keycloak.sh).
  credential.signCount += 1;
  credential.rpId = 'id.example.com';

  return credential;
}

const credentials = Object.fromEntries(['alice-test', 'bob-test', 'carol-test'].map((u) => [u, fixture(u)]));

if (MODE === 'passkey-login') {
  const first = await passkeyLogin(credentials['carol-test']);
  check('carol-test: the synced passkey from Keycloak signs in alone (passkey login)', first.level >= 1, `level ${first.level}`);

  const second = await passkeyLogin(first.credential);
  check('carol-test: it signs in again, with the flags kept from the first sign in', second.level >= 1, `level ${second.level}`);
}

// With passkey login, the login page signs carol-test in with her resident passkey by itself, so her password path is
// tested in the second-factor mode only.
for (const username of MODE === 'passkey-login' ? ['alice-test', 'bob-test'] : ['alice-test', 'bob-test', 'carol-test']) {
  const credential = credentials[username];

  const first = await login(username, credential);
  check(`${username}: password and the Keycloak passkey log in (two factors)`, first.level === 2, `level ${first.level}`);

  if (username === 'carol-test') {
    const second = await login(username, first.credential);
    check(`${username}: the synced passkey logs in again, with the flags kept from the first sign in`, second.level === 2, `level ${second.level}`);
  }
}

await browser.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
