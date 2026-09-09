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
async function startApp(t, overrides = {}) {
  const user = {
    id: 1, username: "test-admin", password: passwordHash, role: "admin",
    is_active: 1, must_change_password: 0, last_login_at: null,
    totp_enabled: 1, totp_secret_encrypted: "legacy-enrollment",
    ...overrides
  };
  const audits = [];
  let store;
  const pool = {
    async query(sql, values) {
      if (/FROM users\s+WHERE username/.test(sql)) return [[values[0] === user.username ? user : null].filter(Boolean)];
      if (/FROM users(?:\s+WHERE id| u)/.test(sql)) return [[user]];
      if (/UPDATE users SET last_login_at/.test(sql)) return [{ affectedRows: 1 }];
      if (/INSERT INTO security_audit_logs/.test(sql)) { audits.push(values); return [{ affectedRows: 1 }]; }
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
  async function request(route, { cookie, form } = {}) {
    const headers = { "x-forwarded-proto": "https", origin: "https://parking.example" };
    if (cookie) headers.cookie = cookie;
    if (form) headers["content-type"] = "application/x-www-form-urlencoded";
    return fetch(baseUrl + route, {
      method: form ? "POST" : "GET", headers, redirect: "manual",
      body: form ? new URLSearchParams(form) : undefined
    });
  }
  const signIn = (suppliedPassword = password) => request("/login", {
    form: { username: user.username, password: suppliedPassword }
  });
  return { request, signIn, store, audits };
}

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
