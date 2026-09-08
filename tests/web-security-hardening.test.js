const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.join(__dirname, "..");
const read = (...segments) => fs.readFileSync(path.join(projectRoot, ...segments), "utf8");

function listFiles(directory, extension) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return listFiles(fullPath, extension);
    return entry.name.endsWith(extension) ? [fullPath] : [];
  });
}

test("dynamic pages nonce inline scripts and avoid inline event handlers", () => {
  const viewFiles = listFiles(path.join(projectRoot, "views"), ".ejs");
  for (const filename of viewFiles) {
    const source = fs.readFileSync(filename, "utf8");
    const normalizedSource = source.replace(/<%[\s\S]*?%>/g, "EJS_VALUE");
    const inlineScripts = normalizedSource.match(/<script\b(?![^>]*\bsrc=)[^>]*>/gi) || [];
    for (const scriptTag of inlineScripts) {
      assert.match(scriptTag, /\bnonce="EJS_VALUE"/, `${filename} has an inline script without a CSP nonce`);
    }
    assert.doesNotMatch(normalizedSource, /<[^>]*\son[a-z]+\s*=/i, `${filename} uses a CSP-blocked inline event handler`);
  }
});

test("response headers use a strict nonce-based content security policy", () => {
  const server = read("server.js");
  assert.match(server, /crypto\.randomBytes\(18\)\.toString\("base64"\)/);
  assert.match(server, /Content-Security-Policy/);
  assert.match(server, /script-src 'self' 'nonce-\$\{cspNonce\}'/);
  assert.match(server, /script-src-attr 'none'/);
  assert.match(server, /object-src 'none'/);
  assert.match(server, /frame-ancestors 'none'/);
});

test("reverse proxy and mutation-source validation cannot trust arbitrary forwarding headers", () => {
  const server = read("server.js");
  assert.doesNotMatch(server, /app\.set\("trust proxy",\s*true\)/);
  assert.match(server, /TRUST_PROXY_HOPS/);
  assert.match(server, /const expectedOrigin = IS_PRODUCTION \? APP_ORIGIN/);
  assert.match(server, /fetchSite === "cross-site"/);
  assert.match(server, /if \(fetchSite === "same-origin"\) return next\(\)/);
  assert.match(server, /Request origin is required/);
});

test("login and QR email actions have independent abuse controls", () => {
  const server = read("server.js");
  assert.match(server, /loginAccountRateLimiter/);
  assert.match(server, /loginAccountRateLimiter\.recordFailure\(accountRateKey\)/);
  assert.match(server, /qrEmailRateLimiter\.check\(emailRateKey\)/);
  assert.match(server, /STICKER_QR_EMAIL_RATE_LIMITED/);
});

test("production seed credentials must be explicitly configured", () => {
  const database = read("db.js");
  assert.match(database, /isProduction && \(!configuredAdminPassword \|\| !configuredGuardPassword\)/);
  assert.match(database, /ADMIN_PASSWORD and GUARD_PASSWORD are required in production/);
});

test("known live-data HTML renderers escape stored values", () => {
  const scanner = read("views", "scanner.ejs");
  const dashboard = read("views", "dashboard.ejs");
  const updates = read("views", "admin_updates.ejs");
  const slots = read("views", "admin_slots.ejs");

  assert.match(scanner, /escapeHtml\(item\.full_name \|\| "-"\)/);
  assert.match(scanner, /escapeHtml\(item\.qr_token\)/);
  assert.match(dashboard, /escapeHtml\(item\.full_name \|\| "Unknown"\)/);
  assert.match(updates, /escapeHtml\(scan\.full_name \|\| "Unknown Student"\)/);
  assert.match(slots, /escapeHtml\(slot\.occupied_by_name \|\| "-"\)/);
});
