const assert = require('node:assert/strict');
const { chromium, request } = require('@playwright/test');
require('dotenv').config();
const baseURL = process.env.REVIEW_BASE_URL || 'http://127.0.0.1:3018';
if (process.env.REVIEW_ALLOW_WRITES !== '1' || !['localhost', '127.0.0.1'].includes(new URL(baseURL).hostname) || !process.env.DB_NAME?.endsWith('_review')) {
  throw new Error('Run only against a local isolated *_review database with REVIEW_ALLOW_WRITES=1. This check creates and restores test records.');
}
const { pool } = require('../db');
const { PNG } = require('pngjs');
const snapshot = 'data:image/png;base64,' + PNG.sync.write(new PNG({ width: 32, height: 32 })).toString('base64');
const checks = [];
const contexts = [];
let browser;
const pass = name => { checks.push(name); console.log('PASS ' + name); };
async function login(role, username, password) {
  const api = await request.newContext({ baseURL, extraHTTPHeaders: { origin: baseURL } });
  contexts.push(api);
  const response = await api.post('/login', { form: { username: username || process.env[role.toUpperCase() + '_USERNAME'], password: password || process.env[role.toUpperCase() + '_PASSWORD'] }, maxRedirects: 0 });
  assert.equal(response.headers().location, '/' + role, await response.text());
  return api;
}
async function json(api, url, data) {
  const response = await api.post(url, { data, maxRedirects: 0 });
  return response.json();
}
async function redirect(api, url, form, expected) {
  const response = await api.post(url, { form, maxRedirects: 0 });
  assert.equal(response.status(), 302, await response.text());
  assert.match(response.headers().location, expected);
  return response;
}
(async () => {
  const [[clock]] = await pool.query('SELECT NOW() AS now, @@session.time_zone AS zone');
  assert.equal(clock.zone, '+00:00');
  assert.ok(Math.abs(Date.now() - clock.now.getTime()) < 3000);
  pass('SQL timestamps match UTC application time');
  const admin = await login('admin');
  const guard = await login('guard');
  assert.equal((await guard.get('/admin/users')).status(), 403);
  pass('password login and administrator access restriction');
  const run = 'REV' + Date.now();
  const program = 'Bachelor of Science in Aeronautical Engineering';
  await redirect(admin, '/students', { student_number: run, full_name: 'System Review Student', program, year_level: '1', email: 'review@example.invalid', plate_number: run, model: 'Test car', color: 'Blue' }, /success=1/);
  const [[vehicle]] = await pool.query('SELECT id FROM vehicles WHERE plate_number = ?', [run]);
  await redirect(admin, '/stickers', { vehicle_id: String(vehicle.id), expires_at: '2027-12-31' }, /success=1/);
  let [[sticker]] = await pool.query('SELECT * FROM stickers WHERE vehicle_id = ?', [vehicle.id]);
  const slots = async () => (await pool.query("SELECT id FROM parking_slots WHERE status = 'available' AND current_sticker_id IS NULL AND current_visitor_pass_id IS NULL ORDER BY id"))[0];
  const move = (action, slot_id) => json(guard, '/api/manual-movement', { token: sticker.qr_token, action, slot_id, gate: 'Review Gate' });
  const firstSlot = (await slots())[0].id;
  assert.equal((await move('ENTRY', firstSlot)).movement_saved, true);
  assert.equal((await move('ENTRY', firstSlot)).movement_saved, false);
  assert.equal((await move('EXIT')).movement_saved, true);
  pass('registration, QR issuance, entry, duplicate prevention, exit');
  const oldToken = sticker.qr_token;
  await redirect(admin, `/stickers/${sticker.id}/rotate`, { reason: 'Isolated review' }, /rotate=success/);
  [[sticker]] = await pool.query('SELECT * FROM stickers WHERE id = ?', [sticker.id]);
  assert.notEqual(sticker.qr_token, oldToken);
  assert.equal((await json(guard, '/api/manual-movement', { token: oldToken, action: 'ENTRY', slot_id: firstSlot })).movement_saved, false);
  assert.equal((await admin.get(`/stickers/${sticker.id}/qr`)).headers()['content-type'], 'image/png');
  pass('QR replacement invalidates the previous token and image download works');
  await new Promise(resolve => setTimeout(resolve, 11000)); // Respect the scanner duplicate cooldown.
  let detected = await json(guard, '/api/auto-scan/detect', { token: sticker.qr_token, defer_entry_confirmation: true, device_id: run, snapshot_data_url: snapshot, gate: 'Review Gate' });
  assert.ok(detected.pending_entry_id, JSON.stringify(detected));
  assert.equal((await json(guard, `/api/auto-scan/pending-entries/${detected.pending_entry_id}/confirm`, { slot_id: firstSlot })).movement_saved, true);
  assert.equal((await move('EXIT')).movement_saved, true);
  pass('remote phone scan queues an entry and guard confirmation assigns the slot');
  const sync = async movement => json(guard, '/api/sync-queue', { movements: [movement] });
  const movement = { event_id: run + '-offline-entry', token: sticker.qr_token, action: 'ENTRY', offline_timestamp: Date.now(), gate: 'Review Gate' };
  const result = await sync(movement);
  assert.equal(result.results[0].action, 'ENTRY', JSON.stringify(result));
  assert.equal((await sync(movement)).results[0].status, 'duplicate');
  const conflict = await sync({ ...movement, event_id: run + '-conflict' });
  assert.equal(conflict.results[0].status, 'rejected');
  const [[last]] = await pool.query("SELECT action FROM scan_logs WHERE sticker_id = ? AND result = 'VALID' ORDER BY scanned_at DESC,id DESC LIMIT 1", [sticker.id]);
  assert.equal(last.action, 'ENTRY');
  assert.equal((await move('EXIT')).movement_saved, true);
  const stale = await sync({ ...movement, event_id: run + '-stale', offline_timestamp: Date.now() - 3600000 });
  assert.equal(stale.results[0].status, 'rejected');
  pass('offline retries are idempotent; conflicting or stale movements cannot change the current state');
  const username = run.toLowerCase();
  await redirect(admin, '/admin/users', { username, password: 'ReviewTemporary2026', role: 'admin' }, /success=1/);
  const secondary = await login('admin', username, 'ReviewTemporary2026');
  await redirect(secondary, '/account/password', { current_password: 'ReviewTemporary2026', new_password: 'ReviewPrivateAccess2026', confirm_password: 'ReviewPrivateAccess2026' }, /saved=1/);
  const [[user]] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
  await redirect(admin, `/admin/users/${user.id}/edit`, { username, role: 'guard', password: '' }, /updated=1/);
  assert.match((await secondary.get('/admin/users', { maxRedirects: 0 })).headers().location, /login/);
  const deleted = await login('guard', username, 'ReviewPrivateAccess2026');
  await redirect(admin, `/admin/users/${user.id}/delete`, {}, /deleted=1/);
  assert.match((await deleted.get('/guard', { maxRedirects: 0 })).headers().location, /login/);
  pass('role changes and account deletion revoke existing login sessions');
  const from = new Date(Date.now() - 60000).toISOString();
  const until = new Date(Date.now() + 3600000).toISOString();
  await redirect(guard, '/visitor-passes/register', { visitor_name: run, visitor_type: 'guest', plate_number: run + 'V', vehicle_type: 'car', purpose: 'Isolated review', valid_from: from, valid_until: until }, /success=1/);
  const [[visitor]] = await pool.query('SELECT * FROM visitor_passes WHERE visitor_name = ?', [run]);
  await redirect(admin, `/visitor-passes/${visitor.id}/approve`, {}, /approved=1/);
  const [[visitorSlot]] = await pool.query("SELECT id FROM parking_slots WHERE zone = 'Visitor Zone' AND status = 'available' AND current_sticker_id IS NULL AND current_visitor_pass_id IS NULL LIMIT 1");
  const visitorMove = action => json(guard, '/api/manual-movement', { token: visitor.qr_token, entity_type: 'visitor', action, slot_id: visitorSlot.id, gate: 'Review Gate' });
  assert.equal((await visitorMove('ENTRY')).movement_saved, true);
  assert.equal((await visitorMove('EXIT')).movement_saved, true);
  pass('visitor registration, approval, entry and exit');
  const csv = `student_number,full_name,program,year_level,email\n${run}CSV,CSV Review,${program},1,review@example.invalid`;
  const preview = await json(admin, '/students/import/preview', { csv_data: csv });
  assert.equal(preview.canImport, true, JSON.stringify(preview));
  await redirect(admin, '/students/import', { csv_data: csv, preview_token: preview.previewToken }, /imported=1/);
  await redirect(admin, '/students/import', { csv_data: csv + 'tampered', preview_token: preview.previewToken }, /import_error=/);
  pass('CSV preview/import works and altered content is rejected');
  const phrase = 'ReviewBackupPassphrase2026';
  const backup = await admin.post('/admin/data/backup', { form: { backup_passphrase: phrase, backup_passphrase_confirmation: phrase } });
  assert.equal(backup.status(), 200);
  const archive = await backup.body();
  const restored = await admin.post('/admin/data/restore-preview', { multipart: { backup_file: { name: 'review.naapbackup', mimeType: 'application/json', buffer: archive }, backup_passphrase: phrase } });
  const previewHtml = await restored.text();
  const previewId = previewHtml.match(/name="preview_id" value="([^"]+)"/)[1];
  const previewToken = previewHtml.match(/name="preview_token" value="([^"]+)"/)[1];
  await redirect(admin, '/admin/data/restore-confirm', { preview_id: previewId, preview_token: previewToken, backup_passphrase: phrase }, /restored=\d+/);
  await redirect(admin, '/admin/data/restore-confirm', { preview_id: previewId, preview_token: previewToken, backup_passphrase: phrase }, /error=/);
  pass('encrypted backup preview/restore succeeds and consumed confirmation cannot be replayed');
  browser = await chromium.launch({ args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] });
  for (const [api, paths] of [[admin, ['/admin','/students','/stickers','/admin/users','/admin/slots','/admin/updates','/admin/records','/admin/alerts','/admin/scanner-analytics','/admin/data','/reports','/visitor-passes','/account/security']], [guard, ['/guard','/scanner','/scanner/auto?mode=remote','/scanner/auto','/visitor-passes','/account/security']]]) {
    const context = await browser.newContext({ storageState: await api.storageState(), serviceWorkers: 'block' });
    await context.route('https://**', route => route.abort());
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    for (const route of paths) { assert.equal((await page.goto(baseURL + route)).status(), 200, route); await page.waitForTimeout(150); }
    if (api === admin) {
      await page.goto(baseURL + '/reports');
      assert.equal(await page.evaluate(() => typeof window.Chart), 'function');
      assert.ok(await page.evaluate(() => Object.keys(Chart.instances).length) > 0);
      await context.route('**/vendor/chartjs/**', route => route.abort());
      await page.reload();
      await page.getByText('Chart unavailable.', { exact: false }).first().waitFor();
    }
    assert.deepEqual(errors, []);
    await context.close();
  }
  pass('19 administrator/guard pages load without uncaught JavaScript errors with external resources blocked');
  const context = await browser.newContext({ storageState: await admin.storageState() });
  const page = await context.newPage();
  await page.goto(baseURL + '/admin');
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.reload();
  const qrPath = `/stickers/${sticker.id}/qr`;
  assert.equal(await page.evaluate(async url => (await fetch(url)).status, qrPath), 200);
  assert.equal(await page.evaluate(async url => Boolean(await caches.match(url)), qrPath), false);
  await context.request.get(baseURL + '/logout');
  const afterLogout = await page.evaluate(async url => { const response = await fetch(url); return response.headers.get('content-type'); }, qrPath);
  assert.match(afterLogout, /text\/html/);
  await context.close();
  pass('service worker never caches private QR images; logout removes access');
  console.log(`System review: ${checks.length} workflow groups passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  await Promise.all(contexts.map(context => context.dispose()));
  await pool.end();
});
