const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '..');

test('private images and downloads bypass the service worker cache', () => {
  const events = {};
  vm.runInNewContext(fs.readFileSync(path.join(root, 'public/sw.js'), 'utf8'), {
    URL, self: { location: { origin: 'https://parking.example' }, addEventListener: (name, handler) => { events[name] = handler; } }
  });
  for (const pathname of ['/stickers/1/qr','/visitor-passes/1/qr','/snapshots/private.png','/admin/data/backups/1','/api/sync-roster']) {
    let intercepted = false;
    events.fetch({ request: { method: 'GET', mode: 'cors', url: 'https://parking.example' + pathname }, respondWith: () => { intercepted = true; } });
    assert.equal(intercepted, false, pathname);
  }
});

test('offline roster verification expires cached stickers at Philippine midnight', async () => {
  class ReviewDate extends Date { static now() { return Date.parse('2026-09-09T16:00:00Z'); } }
  let cached = { qr_token: 'review', expires_at: '2026-09-09T00:00:00.000Z' };
  const context = vm.createContext({ window: {}, navigator: { onLine: false }, Date: ReviewDate });
  vm.runInContext(fs.readFileSync(path.join(root, 'public/offline-sync.js'), 'utf8'), context);
  context.readCached = async () => cached;
  vm.runInContext('dbTransaction = readCached', context);
  const manager = context.window.OfflineManager;
  assert.equal((await manager.verifyOfflineToken('review')).result, 'EXPIRED');
  cached = { ...cached, expires_at: '2026-09-10T00:00:00.000Z' };
  assert.equal((await manager.verifyOfflineToken('review')).ok, true);
  cached = { ...cached, expires_at: null };
  assert.equal((await manager.verifyOfflineToken('review')).ok, true);
});
