const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const server = read("server.js");
const database = read("db.js");

test("QR email controls and sending are removed while stored history is retained", () => {
  assert.match(database, /CREATE TABLE IF NOT EXISTS email_delivery_jobs/);
  assert.match(database, /CREATE TABLE IF NOT EXISTS email_delivery_attempts/);
  assert.doesNotMatch(server, /processEmailDeliveryJobs|sendStudentQrEmail|qrEmailRateLimiter/);
  assert.doesNotMatch(read("views/stickers.ejs"), /data-email-preview|emailPreviewModal|QR Email Delivery|Email QR/);
});

test("sticker management remains available when optional history data is unavailable", () => {
  assert.match(server, /async function loadOptionalStickerRows/);
  assert.match(server, /Sticker dashboard \$\{label\} unavailable/);
  assert.doesNotMatch(server, /latestEmailJobs|emailHistory/);
  assert.match(read("views/stickers.ejs"), /Print card/);
});

test("administrator and guard account controls enforce practical security", () => {
  assert.match(server, /mustChangePassword/);
  assert.match(server, /\/admin\/users\/:id\/status/);
  assert.match(server, /GUARD_INACTIVITY_SUSPENDED/);
  assert.match(read("views/admin_users.ejs"), /Suspend account/);
});

test("encrypted backups require preview and explicit confirmation before restore", () => {
  assert.match(database, /CREATE TABLE IF NOT EXISTS backup_archives/);
  assert.match(database, /CREATE TABLE IF NOT EXISTS backup_restore_previews/);
  assert.match(server, /\/admin\/data\/restore-preview/);
  assert.match(server, /verifyRestorePreviewToken/);
  assert.match(server, /\/admin\/data\/restore-confirm/);
  assert.match(read("views/admin_data.ejs"), /Nothing is changed until you review the contents and confirm/);
});

test("QR replacement, parking-space configuration, and retention are implemented", () => {
  assert.match(database, /CREATE TABLE IF NOT EXISTS sticker_qr_history/);
  assert.match(server, /STICKER_QR_ROTATED/);
  assert.match(database, /parking_zone_settings/);
  assert.match(server, /warning_threshold_percent/);
  assert.match(read("views/admin_slots.ejs"), /Accessibility/);
  assert.match(read("views/admin_slots.ejs"), /Maintenance reason/);
  assert.match(server, /async function runDataRetentionCleanup/);
});

test("the delivered scope remains admin and guard only", () => {
  assert.doesNotMatch(server, /USER_ROLES\.STUDENT/);
  assert.doesNotMatch(server, /\/student\/dashboard/);
  assert.doesNotMatch(read("views/partials/header.ejs"), /system-health/i);
});
