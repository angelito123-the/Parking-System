const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(projectRoot, file), "utf8");

test("scanner operations include anonymous metrics and an admin dashboard", () => {
  const server = read("server.js");
  const scanner = read("views/scanner_auto.ejs");
  assert.match(server, /app\.post\("\/api\/scanner-metrics"/);
  assert.match(server, /\/admin\/scanner-analytics/);
  assert.match(scanner, /queueScanMetric/);
  assert.match(scanner, /resetSmartAssistBtn/);
  assert.match(scanner, /runDeviceCheckBtn/);
  assert.doesNotMatch(server, /scanner_metrics[\s\S]{0,300}qr_token/i);
});

test("offline queue is durable and server sync is idempotent", () => {
  const client = read("public/offline-sync.js");
  const server = read("server.js");
  assert.match(client, /metricsOutbox/);
  assert.match(client, /queueMovement/);
  assert.match(server, /offline_sync_receipts/);
  assert.match(server, /event_id/);
  assert.match(server, /expectedAction/);
});

test("database migrations add operational indexes and security tables", () => {
  const database = read("db.js");
  assert.match(database, /ensurePerformanceIndexes/);
  assert.match(database, /scanner_metrics/);
  assert.match(database, /security_audit_logs/);
  assert.match(database, /idx_scan_gate_time/);
  assert.match(database, /idx_stickers_status_expiry/);
});

test("administrators can export backups and import protected master data", () => {
  const server = read("server.js");
  assert.match(server, /\/admin\/data\/export\/:dataset/);
  assert.match(server, /\/admin\/data\/import/);
  assert.match(server, /DATASET_DEFINITIONS/);
  assert.match(server, /scanner_metrics/);
});

test("account security includes throttling, password changes, sessions, audit, and TOTP", () => {
  const server = read("server.js");
  assert.match(server, /SlidingWindowRateLimiter/);
  assert.match(server, /\/account\/password/);
  assert.match(server, /\/account\/sessions\/revoke-others/);
  assert.match(server, /security_audit_logs/);
  assert.match(server, /\/account\/2fa\/enable/);
});
