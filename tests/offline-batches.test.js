const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(movementCount, metricCount, respond) {
  const records = (prefix, count) => Array.from({ length: count }, (_, id) => ({ id, event_id: `${prefix}-${id}`, token: `token-${id}`, action: 'ENTRY' }));
  const stores = { outbox: records('movement', movementCount), metricsOutbox: records('metric', metricCount) };
  const calls = [];
  const context = vm.createContext({ window: {}, navigator: { onLine: true }, console, async fetch(url, options) {
    const items = Object.values(JSON.parse(options.body))[0];
    calls.push({ url, count: items.length });
    if (respond) {
      const response = respond(calls.length, items);
      if (response) return response;
    }
    return { ok: true, json: async () => ({ ok: true, accepted_event_ids: items.slice(0, 100).map(item => item.event_id), results: [] }) };
  } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/offline-sync.js'), 'utf8'), context);
  context.readRecords = async store => stores[store].slice();
  vm.runInContext('dbTransaction = readRecords', context);
  const manager = context.window.OfflineManager;
  manager.notifyQueueStatus = async () => {};
  manager.deleteQueuedItems = async (store, items) => {
    const ids = new Set(items.map(item => item.event_id));
    stores[store] = stores[store].filter(item => !ids.has(item.event_id));
  };
  return { manager, stores, calls };
}

test('offline synchronization drains queues beyond the 100-record server limit', async () => {
  const { manager, stores, calls } = setup(240, 130);
  await manager.performQueueSync();
  assert.deepEqual(calls.map(call => call.count), [100, 100, 40, 100, 30]);
  assert.equal(stores.outbox.length, 0);
  assert.equal(stores.metricsOutbox.length, 0);
});

test('a failed later batch preserves unsent records and retry drains them', async () => {
  const { manager, stores } = setup(240, 0, call => call === 2 ? { ok: false, status: 503 } : null);
  await assert.rejects(manager.performQueueSync(), /503/);
  assert.equal(stores.outbox.length, 140);
  assert.equal(stores.outbox[0].event_id, 'movement-100');
  await manager.performQueueSync();
  assert.equal(stores.outbox.length, 0);
});

test('a success response without acknowledgements cannot erase queued records', async () => {
  const { manager, stores } = setup(2, 0, () => ({ ok: true, json: async () => ({ ok: true }) }));
  await assert.rejects(manager.performQueueSync(), /acknowledge/);
  assert.equal(stores.outbox.length, 2);
});

test('partial acknowledgements delete only the explicitly accepted records', async () => {
  const { manager, stores } = setup(3, 0, () => ({ ok: true, json: async () => ({ ok: true, accepted_event_ids: ['movement-1', 'unrelated'], results: [] }) }));
  await manager.performQueueSync();
  assert.deepEqual(stores.outbox.map(item => item.event_id), ['movement-0', 'movement-2']);
});
