const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");
const { MemoryStore } = require("express-session");

const root = path.join(__dirname, "..");
const filename = path.join(root, "server.js");
const source = fs.readFileSync(filename, "utf8");
const localRequire = createRequire(filename);
const password = "TestParkingAccess2026";
const passwordHash = bcrypt.hashSync(password, 4);

// Exercise the real Express routes, middleware, sessions, and templates without
// starting background maintenance or connecting to the application's database.
async function startApp(t, overrides = {}, database = {}, services = {}) {
  const user = {
    id: 1, username: "test-admin", password: passwordHash, role: "admin",
    is_active: 1, must_change_password: 0, last_login_at: null,
    totp_enabled: 1, totp_secret_encrypted: "legacy-enrollment",
    ...overrides
  };
  const audits = [];
  let store;
  const pool = {
    ...database,
    async query(sql, values) {
      if (database.query) { const result = await database.query(sql, values); if (result !== undefined) return result; }
      if (/FROM users\s+WHERE username/.test(sql)) return [[values[0] === user.username ? user : null].filter(Boolean)];
      if (/FROM users(?:\s+WHERE id| u)/.test(sql)) return [[user]];
      if (/UPDATE users SET last_login_at/.test(sql)) return [{ affectedRows: 1 }];
      if (/INSERT INTO security_audit_logs/.test(sql)) { audits.push(values); return [{ affectedRows: 1 }]; }
      if (/SELECT session_id, data FROM sessions/.test(sql)) return [Object.entries(store.sessions).map(([session_id, data]) => ({ session_id, data }))];
      if (/DELETE FROM sessions WHERE session_id IN/.test(sql)) {
        for (const id of values[0]) delete store.sessions[id];
        return [{ affectedRows: values[0].length }];
      }
      if (/FROM (sessions|security_audit_logs)/.test(sql)) return [[]];
      throw new Error(`Unexpected database query: ${sql}`);
    }
  };
  const context = vm.createContext({
    __dirname: root, __filename: filename, console, Buffer, URL,
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate,
    process: { env: {
      NODE_ENV: "production",
      APP_BASE_URL: "https://parking.example",
      SESSION_SECRET: "password-login-test-secret-at-least-32-characters",
      REQUIRE_ADMIN_2FA: "true"
    } },
    require(name) {
      if (services[name]) return services[name];
      if (name === "./db") return { pool };
      if (name === "dotenv") return { config() {} };
      if (name === "express-mysql-session") return () => class extends MemoryStore {
        constructor() { super(); store = this; }
      };
      return localRequire(name);
    }
  });
  assert.match(source, /\nstartServer\(\);\s*$/);
  vm.runInContext(source.replace(/\nstartServer\(\);\s*$/, "\n"), context, { filename });
  const app = vm.runInContext("app", context);
  const server = app.listen(0, "127.0.0.1");
  t.after(() => new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeAllConnections();
  }));
  await once(server, "listening");
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  async function request(route, { cookie, form, data } = {}) {
    const headers = { "x-forwarded-proto": "https", origin: "https://parking.example" };
    if (cookie) headers.cookie = cookie;
    if (data) headers["content-type"] = "application/json";
    if (form) headers["content-type"] = "application/x-www-form-urlencoded";
    return fetch(baseUrl + route, {
      method: form || data ? "POST" : "GET", headers, redirect: "manual",
      body: form ? new URLSearchParams(form) : data ? JSON.stringify(data) : undefined
    });
  }
  const signIn = (suppliedPassword = password) => request("/login", {
    form: { username: user.username, password: suppliedPassword }
  });
  return { request, signIn, store, audits, context, evaluate: code => vm.runInContext(code, context) };
}

test("bulk parking closure requires an administrator and explicit confirmation", async t => {
  const app = await startApp(t, { role: "guard" });
  const form = { confirm_disable_all: "yes" };
  assert.equal((await app.request("/admin/slots/disable-all", { form })).headers.get("location"), "/login");
  const login = await app.signIn();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  assert.equal((await app.request("/admin/slots/disable-all", { cookie, form })).status, 403);
  const admin = await startApp(t);
  const adminCookie = (await admin.signIn()).headers.get("set-cookie").split(";")[0];
  const unconfirmed = await admin.request("/admin/slots/disable-all", { cookie: adminCookie, form: {} });
  assert.match(unconfirmed.headers.get("location"), /error=Confirm/);
  assert.equal(admin.audits.some(values => values.includes("PARKING_SLOTS_DISABLED_ALL")), false);
});

for (const note of [undefined, "  School foundation day  "]) {
  test(`bulk parking closure records the administrator and ${note ? "custom" : "default"} reason`, async t => {
    const updates = [];
    const app = await startApp(t, {}, {
      query(sql, values) {
        if (/UPDATE parking_slots/.test(sql)) {
          updates.push({ sql, values: Array.from(values) });
          return [{ affectedRows: updates.length === 1 ? 4 : 0 }];
        }
      }
    });
    const cookie = (await app.signIn()).headers.get("set-cookie").split(";")[0];
    const form = { confirm_disable_all: "yes", ...(note === undefined ? {} : { approval_note: note }) };
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await app.request("/admin/slots/disable-all", { cookie, form });
      assert.equal(response.headers.get("location"), "/admin/slots?disabled_all=1");
    }
    assert.equal(updates.length, 2);
    for (const { sql, values } of updates) {
      assert.match(sql, /SET status = 'disabled', disabled_reason = \?/);
      assert.match(sql, /WHERE status = 'available'/);
      assert.doesNotMatch(sql, /current_sticker_id\s*=|current_visitor_pass_id\s*=/);
      assert.deepEqual(values, [note ? note.trim() : "School event or temporary closure"]);
    }
    const audit = app.audits.filter(values => values.includes("PARKING_SLOTS_DISABLED_ALL"));
    assert.equal(audit.length, 2);
    assert.equal(JSON.parse(audit[0].at(-1)).affected_slots, 4);
    assert.equal(JSON.parse(audit[1].at(-1)).affected_slots, 0);
  });
}

for (const note of ["x".repeat(256), { unexpected: "object" }, ["array"]]) {
  test(`bulk parking closure rejects invalid reasons: ${Array.isArray(note) ? "array" : typeof note}`, async t => {
    const app = await startApp(t);
    const cookie = (await app.signIn()).headers.get("set-cookie").split(";")[0];
    const response = await app.request("/admin/slots/disable-all", {
      cookie, data: { confirm_disable_all: "yes", approval_note: note }
    });
    assert.match(response.headers.get("location"), /error=Enter\+a\+reason/);
    assert.equal(app.audits.some(values => values.includes("PARKING_SLOTS_DISABLED_ALL")), false);
  });
}

test("bulk parking closure hides database failures and does not report success", async t => {
  const app = await startApp(t, {}, { query(sql) {
    if (/UPDATE parking_slots/.test(sql)) throw new Error("private-db-host SELECT secret");
  } });
  const cookie = (await app.signIn()).headers.get("set-cookie").split(";")[0];
  const response = await app.request("/admin/slots/disable-all", { cookie, form: { confirm_disable_all: "yes" } });
  assert.match(response.headers.get("location"), /error=Unable\+to\+disable/);
  assert.doesNotMatch(response.headers.get("location"), /private-db-host|SELECT|disabled_all=1/);
});

test("bulk parking closure rejects cross-site requests", async t => {
  const app = await startApp(t);
  const login = await app.signIn();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const response = await fetch(new URL("/admin/slots/disable-all", login.url), {
    method: "POST", redirect: "manual",
    headers: { cookie, origin: "https://untrusted.example", "x-forwarded-proto": "https", "content-type": "application/x-www-form-urlencoded" },
    body: "confirm_disable_all=yes"
  });
  assert.equal(response.status, 403);
});

for (const enrolled of [0, 1]) {
  test(`admin password sign-in reaches protected pages with legacy enrollment=${enrolled}`, async t => {
    const { request, signIn, audits } = await startApp(t, { totp_enabled: enrolled });
    const login = await signIn();
    assert.equal(login.status, 302);
    assert.equal(login.headers.get("location"), "/admin");
    const cookie = login.headers.get("set-cookie").split(";")[0];
    const users = await request("/admin/users", { cookie });
    assert.equal(users.status, 200);
    assert.doesNotMatch(await users.text(), /Reset 2FA|2FA enabled|No 2FA|reset-2fa/);
    const security = await request("/account/security", { cookie });
    assert.equal(security.status, 200);
    const html = await security.text();
    assert.match(html, /Change Password/);
    assert.match(html, /Active Sessions/);
    assert.doesNotMatch(html, /authenticator|two-factor|\/account\/2fa/i);
    assert.ok(audits.some(values => values.includes("LOGIN_SUCCEEDED")));
  });
}

test("guard password sign-in preserves administrator access restrictions", async t => {
  const { request, signIn } = await startApp(t, { role: "guard" });
  const login = await signIn();
  assert.equal(login.headers.get("location"), "/guard");
  const cookie = login.headers.get("set-cookie").split(";")[0];
  assert.equal((await request("/admin/users", { cookie })).status, 403);
});

test("wrong passwords and suspended accounts cannot establish a session", async t => {
  const app = await startApp(t);
  const wrongPassword = await app.signIn("wrong-password");
  assert.match(await wrongPassword.text(), /Invalid username or password/);
  assert.equal(wrongPassword.headers.get("set-cookie"), null);
  const suspended = await startApp(t, { is_active: 0 });
  const disabledLogin = await suspended.signIn();
  assert.match(await disabledLogin.text(), /account is suspended/);
  assert.equal(disabledLogin.headers.get("set-cookie"), null);
});

test("repeated wrong passwords remain rate limited", async t => {
  const { signIn } = await startApp(t);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await signIn("wrong-password");
    assert.equal(response.status, 200);
    await response.text();
  }
  const blocked = await signIn();
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get("retry-after")) > 0);
  assert.equal(blocked.headers.get("set-cookie"), null);
});

test("temporary passwords still require a password change", async t => {
  const { request, signIn } = await startApp(t, { must_change_password: 1 });
  const login = await signIn();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const protectedPage = await request("/admin/users", { cookie });
  assert.equal(protectedPage.headers.get("location"), "/account/security?password_required=1#password");
  assert.equal((await request("/account/security", { cookie })).status, 200);
});

test("old verification pages return pending sessions to password sign-in", async t => {
  const { request, signIn, store } = await startApp(t);
  const login = await signIn();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const sessionId = Object.keys(store.sessions)[0];
  const pending = JSON.parse(store.sessions[sessionId]);
  delete pending.user;
  pending.pending2fa = { id: 1, username: "test-admin", role: "admin", createdAt: Date.now() };
  store.sessions[sessionId] = JSON.stringify(pending);
  for (const form of [undefined, { code: "123456" }]) {
    const legacy = await request("/login/2fa", { cookie, form });
    assert.equal(legacy.headers.get("location"), "/login");
  }
  const loginPage = await request("/login", { cookie });
  assert.equal(loginPage.status, 200);
  assert.match(await loginPage.text(), /Sign In/i);
  assert.equal((await request("/admin/users", { cookie })).headers.get("location"), "/login");
  assert.equal((await signIn()).headers.get("location"), "/admin");
});


test("database connection failures return responses and leave the server available", async t => {
  for (const role of ["admin", "guard"]) {
    const app = await startApp(t, { role }, { getConnection: async () => { throw new Error("Simulated database outage"); } });
    const login = await app.signIn();
    const cookie = login.headers.get("set-cookie").split(";")[0];
    const cases = role === "admin" ? [
      ["/students", { student_number: "OUTAGE-1", full_name: "Test", program: "Bachelor of Science in Aeronautical Engineering", year_level: "1" }],
      ["/visitor-passes/1/approve", {}], ["/visitor-passes/1/reject", {}], ["/visitor-passes/1/cancel", {}]
    ] : [
      ["/api/auto-scan/pending-entries/1/confirm", { slot_id: "1" }],
      ["/api/auto-scan/pending-entries/1/cancel", {}]
    ];
    for (const [route, form] of cases) {
      const response = await app.request(route, { cookie, form });
      if (route.startsWith("/api/")) assert.equal((await response.json()).ok, false);
      else assert.match(response.headers.get("location"), /error=/);
      assert.equal((await app.request("/account/security", { cookie })).status, 200);
    }
  }
});


test("offline and metrics batch failures are handled without crashing the process", async t => {
  const app = await startApp(t, { role: "guard" }, { getConnection: async () => { throw new Error("Simulated database outage"); } });
  const login = await app.signIn();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  for (const [route, data] of [
    ["/api/sync-queue", { movements: [{ event_id: "outage", action: "ENTRY" }] }],
    ["/api/scanner-metrics/batch", { metrics: [{ event_id: "outage" }] }],
    ["/api/sync-queue", { movements: [null, null] }]
  ]) {
    const response = await app.request(route, { cookie, data });
    assert.ok(response.status >= 400);
    assert.equal((await response.json()).ok, false);
  }
  assert.equal((await app.request("/account/security", { cookie })).status, 200);
});


for (const [route, snapshot, registry] of [
  ['/api/notifications/events', 'getNotificationSummaryForUser', 'notificationSseClients'],
  ['/api/auto-scan/events', 'getAutoScanHealthSnapshot', 'autoScanSseClients']
]) {
  async function openStream(t, pending = false) {
    const app = await startApp(t, { role: 'guard' });
    let resolveSnapshot;
    app.context.testSnapshot = pending ? new Promise(resolve => { resolveSnapshot = resolve; }) : Promise.resolve({});
    app.evaluate(snapshot + ' = () => testSnapshot');
    const login = await app.signIn();
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const response = await app.request(route, { cookie });
    assert.equal(response.status, 200);
    const reader = response.body.getReader();
    assert.match(new TextDecoder().decode((await reader.read()).value), /event: connected/);
    t.after(async () => {
      await reader.cancel().catch(() => {});
      if (resolveSnapshot) resolveSnapshot({});
      app.evaluate('for (const client of ' + registry + '.values()) client.close()');
    });
    return { ...app, cookie, reader, resolveSnapshot, count: () => app.evaluate(registry + '.size') };
  }

  test(route + ' cleans up when the browser disconnects before its initial query finishes', async t => {
    const app = await openStream(t, true);
    await app.reader.cancel();
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.equal(app.count(), 0, 'disconnected response must not retain a client or heartbeat timer');
    app.resolveSnapshot({});
  });

  test(route + ' closes live connections on logout', async t => {
    const app = await openStream(t);
    assert.equal((await app.request('/logout', { cookie: app.cookie })).status, 302);
    assert.equal(app.count(), 0, 'logging out must end existing streams');
    while (!(await app.reader.read()).done) { /* Drain the initial snapshot; the socket must end. */ }
    assert.equal((await app.request(route, { cookie: app.cookie })).status, 401);
  });

  test(route + ' closes live connections when its session is revoked', async t => {
    const app = await openStream(t);
    assert.equal(await app.evaluate('revokeUserSessions(1)'), 1);
    assert.equal(app.count(), 0, 'revoking a session must end existing streams');
    while (!(await app.reader.read()).done) { /* Drain the initial snapshot; the socket must end. */ }
    assert.equal((await app.request(route, { cookie: app.cookie })).status, 401);
  });

  test(route + ' preserves the current connection when revoking other sessions', async t => {
    const app = await openStream(t);
    app.context.keptSession = Object.keys(app.store.sessions)[0];
    const otherLogin = await app.signIn();
    const otherCookie = otherLogin.headers.get('set-cookie').split(';')[0];
    const response = await app.request(route, { cookie: otherCookie });
    const reader = response.body.getReader();
    t.after(() => reader.cancel().catch(() => {}));
    await reader.read();
    assert.equal(app.count(), 2);
    assert.equal(await app.evaluate('revokeUserSessions(1, { keepSessionId: keptSession })'), 1);
    assert.equal(app.count(), 1);
    assert.equal(Object.keys(app.store.sessions)[0], app.context.keptSession);
    while (!(await reader.read()).done) { /* Only the other device should disconnect. */ }
    await app.request('/logout', { cookie: app.cookie });
    assert.equal(app.count(), 0);
  });

  test(route + ' closes revoked streams even if their database row is already gone', async t => {
    const app = await openStream(t);
    for (const id of Object.keys(app.store.sessions)) delete app.store.sessions[id];
    assert.equal(await app.evaluate('revokeUserSessions(1)'), 0);
    assert.equal(app.count(), 0);
  });

}


test('retired QR email routes cannot create or retry delivery jobs', async t => {
  const app = await startApp(t, {}, { getConnection() { throw new Error('No email job should reach the database'); } }, {
    './lib/mail-transport': { getMailConfigurationIssue: () => 'Missing email settings' }
  });
  const login = await app.signIn();
  const cookie = login.headers.get('set-cookie').split(';')[0];
  for (const route of ['/stickers/1/email', '/admin/email-deliveries/1/retry']) {
    const response = await app.request(route, { cookie, form: {} });
    assert.equal(response.status, 410);
    assert.match((await response.json()).message, /QR email delivery has been removed/);
  }
});

test('database failures do not expose internal details in movement responses', async t => {
  const detail = 'SQL connection failed for private-db-host; SELECT secret FROM users';
  const app = await startApp(t, {}, { getConnection: async () => { throw new Error(detail); } });
  const login = await app.signIn();
  const cookie = login.headers.get('set-cookie').split(';')[0];
  for (const [route, form] of [
    ['/api/force-exit', { sticker_id: '1' }],
    ['/api/auto-scan/pending-entries/1/confirm', { slot_id: '1' }],
    ['/api/auto-scan/pending-entries/1/cancel', {}]
  ]) {
    const response = await app.request(route, { cookie, form });
    assert.ok(response.status >= 400);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.doesNotMatch(body.message, /private-db-host|SELECT secret/);
    assert.ok(body.message.length > 0);
  }
});

test('session-store failures return a generic API error', async t => {
  const app = await startApp(t);
  const login = await app.signIn();
  const cookie = login.headers.get('set-cookie').split(';')[0];
  app.store.get = (_id, callback) => callback(new Error('private session database connection failed'));
  const response = await app.request('/api/notifications/summary', { cookie });
  assert.equal(response.status, 500);
  assert.doesNotMatch((await response.json()).message, /private session database/);
});

test('occupied-space validation still tells the guard what to correct', async t => {
  const app = await startApp(t, { role: 'guard' });
  app.context.occupiedSlotDb = {
    async query(sql) {
      if (sql.includes('FOR UPDATE')) return [[{ id: 2, zone: 'A', status: 'available', current_sticker_id: 99 }]];
      if (sql.includes('COUNT(*)')) return [[{ total_slots: 2, available_slots: 1 }]];
      throw new Error('An occupied slot must never be updated');
    }
  };
  const message = await app.evaluate(`assignParkingSlot(occupiedSlotDb, 1, 2)
    .then(() => 'unexpected success')
    .catch(error => getPublicErrorMessage(error, 'Failed to record movement.'))`);
  assert.equal(message, 'Selected parking slot is already occupied.');
});

test('dynamic pages and authentication redirects prevent private browser caching', async t => {
  const app = await startApp(t);
  const loginPage = await app.request('/login');
  assert.equal(loginPage.headers.get('cache-control'), 'private, no-store');
  const login = await app.signIn();
  assert.equal(login.headers.get('cache-control'), 'private, no-store');
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const account = await app.request('/account/security', { cookie });
  assert.equal(account.status, 200);
  assert.equal(account.headers.get('cache-control'), 'private, no-store');
  await app.request('/logout', { cookie });
  const signedOut = await app.request('/account/security', { cookie });
  assert.equal(signedOut.status, 302);
  assert.equal(signedOut.headers.get('cache-control'), 'private, no-store');
  const stylesheet = await app.request('/design-system.css');
  assert.equal(stylesheet.status, 200);
  assert.doesNotMatch(stylesheet.headers.get('cache-control'), /no-store/);
});

test('retired QR email routes remain restricted to administrators', async t => {
  const app = await startApp(t, { role: 'guard' });
  const login = await app.signIn();
  const cookie = login.headers.get('set-cookie').split(';')[0];
  for (const route of ['/stickers/1/email', '/admin/email-deliveries/1/retry']) {
    assert.equal((await app.request(route, { cookie, form: {} })).status, 403);
    assert.equal((await app.request(route, { form: {} })).status, 302);
  }
});

// Gate APIs share the application's actual session authentication and role rules.
for (const role of ['admin', 'guard']) {
  test('gate logging permissions for ' + role, async t => {
    const app = await startApp(t, { role }, { query(sql) {
      if (/FROM gates/.test(sql)) return [[{ id: 4, name: 'Gate 4', type: 'exit' }]];
    } });
    for (const route of ['/api/gates', '/api/logs', '/api/vehicle-sessions', '/api/vehicles/1/latest-session']) {
      assert.equal((await app.request(route)).status, 401);
    }
    assert.equal((await app.request('/api/scans', { data: { qr_data: 'test', gate_id: 4 } })).status, 401);
    const cookie = (await app.signIn()).headers.get('set-cookie').split(';')[0];
    const gates = await app.request('/api/gates', { cookie });
    assert.equal(gates.status, 200);
    assert.equal((await gates.json()).gates[0].type, 'exit');
    assert.equal((await app.request('/api/logs?limit=101', { cookie })).status, 400);
    assert.equal((await app.request('/api/vehicle-sessions?date_from=bad', { cookie })).status, 400);
    if (role === 'admin') {
      assert.equal((await app.request('/api/scans', { cookie, data: { qr_data: 'test', gate_id: 4 } })).status, 403);
      assert.equal((await app.request('/api/gates/4', { cookie, data: { type: 'invalid' } })).status, 400);
    } else {
      assert.equal((await app.request('/api/gates/4', { cookie, data: { type: 'both' } })).status, 403);
      assert.equal((await app.request('/api/scans', { cookie, data: { qr_data: {}, gate_id: 4 } })).status, 400);
    }
  });
}

test('gate history uses the existing scan log retention period', async t => {
  const queries = [];
  const app = await startApp(t, {}, { query(sql, values) {
    if (/^\s*(DELETE FROM|UPDATE scan_logs|UPDATE auto_scan_queue)/.test(sql)) {
      queries.push({ sql, values });
      return [{ affectedRows: 0 }];
    }
  } });
  await app.evaluate('runDataRetentionCleanup()');
  const cleanup = queries.find(query => /DELETE FROM vehicle_logs/.test(query.sql));
  assert.ok(cleanup);
  assert.match(cleanup.sql, /INTERVAL \? DAY/);
  assert.equal(cleanup.values[0], app.evaluate('SCAN_LOG_RETENTION_DAYS'));
});
