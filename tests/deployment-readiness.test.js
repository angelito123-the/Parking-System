const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.join(__dirname, "..");

test("free Render deployment uses production health and TLS settings", () => {
  const blueprint = fs.readFileSync(path.join(projectRoot, "render.yaml"), "utf8");
  assert.match(blueprint, /plan:\s*free/);
  assert.match(blueprint, /healthCheckPath:\s*\/healthz/);
  assert.match(blueprint, /key:\s*DB_SSL[\s\S]*?value:\s*["']true["']/);
  assert.match(blueprint, /key:\s*SESSION_SECRET[\s\S]*?generateValue:\s*true/);
});

test("production state is persisted outside the web service filesystem", () => {
  const serverSource = fs.readFileSync(path.join(projectRoot, "server.js"), "utf8");
  const databaseSource = fs.readFileSync(path.join(projectRoot, "db.js"), "utf8");
  assert.match(serverSource, /new MySQLStore\(/);
  assert.match(serverSource, /secure:\s*IS_PRODUCTION/);
  assert.match(serverSource, /INSERT INTO scan_snapshots/);
  assert.match(databaseSource, /CREATE TABLE IF NOT EXISTS scan_snapshots/);
  assert.match(databaseSource, /rejectUnauthorized:\s*true/);
});

test("Render's assigned URL is used for generated QR links", () => {
  const serverSource = fs.readFileSync(path.join(projectRoot, "server.js"), "utf8");
  assert.match(serverSource, /process\.env\.RENDER_EXTERNAL_URL/);
});
