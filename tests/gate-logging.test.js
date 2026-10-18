const test = require('node:test');
const assert = require('node:assert/strict');
const gates = require('../lib/parking/gate-logging');

test('gate direction comes from configuration, including an exit-only Gate 4', () => {
  for (const action of ['ENTRY', 'EXIT']) gates.assertGateDirection({ name: 'Gate 1', type: 'both' }, action);
  gates.assertGateDirection({ name: 'Gate 4', type: 'exit' }, 'EXIT');
  assert.throws(() => gates.assertGateDirection({ name: 'Gate 4', type: 'exit' }, 'ENTRY'), error => error.code === 'GATE_DIRECTION_MISMATCH' && error.status === 409);
  gates.assertGateDirection({ name: 'Gate 4', type: 'entry' }, 'ENTRY');
  assert.throws(() => gates.assertGateDirection({ name: 'Gate 1', type: 'both' }, 'VERIFY'));
});

test('gate IDs and legacy names are bound as parameters; unconfigured gates fail', async () => {
  const calls = [];
  const db = { async query(sql, values) { calls.push([sql, values]); return [[{ id: 1, name: 'Gate 1', type: 'both' }]]; } };
  await gates.resolveGate(db, 'Main Gate');
  assert.deepEqual(calls[0][1], ['Gate 1']);
  await gates.resolveGate(db, 1);
  assert.match(calls[1][0], /id = \?/);
  assert.deepEqual(calls[1][1], [1]);
  for (const value of [null, {}, [], '', '9'.repeat(30)]) await assert.rejects(gates.resolveGate(db, value));
  await assert.rejects(gates.resolveGate({ query: async () => [[]] }, 'Unconfigured'), /not configured/);
});

test('log filters validate dates, pagination and scalar inputs and bind search values', () => {
  const f = gates.filters({ page: '2', limit: '10', gate_id: '4', vehicle: "ABC%_'", scan_type: 'exit', date_from: '2026-10-18', date_to: '2026-10-18' });
  assert.equal(f.offset, 10);
  assert.deepEqual(f.params.slice(0, 2), [4, "ABC\\%\\_'%"]);
  assert.equal(f.params[2].toISOString(), '2026-10-17T16:00:00.000Z');
  assert.equal(f.params[3].toISOString(), '2026-10-18T16:00:00.000Z');
  assert.doesNotMatch(f.where, /ABC/);
  for (const query of [{ page: '0' }, { limit: '101' }, { gate_id: ['1'] }, { vehicle_id: {} }, { scan_type: 'drop' }, { date_from: '2026-02-30' }, { date_from: '2026-10-20', date_to: '2026-10-18' }]) assert.throws(() => gates.filters(query));
  const sessions = gates.filters({ gate_id: '4' }, true);
  assert.match(sessions.where, /e.gate_id = \? OR x.gate_id = \?/);
  assert.deepEqual(sessions.params, [4, 4]);
});

function movementDb(previous, type = 'both') {
  const queries = [];
  return { queries, async query(sql) {
    queries.push(sql);
    if (/FROM vehicles v/.test(sql)) return [[{ id: 8, plate_number: 'TEST' }]];
    if (/FROM gates/.test(sql)) return [[{ id: 4, name: 'Gate 4', type }]];
    if (/FROM vehicle_logs/.test(sql)) return [previous ? [previous] : []];
    throw new Error('Unexpected query');
  } };
}

test('movement validation locks the vehicle and rejects duplicates and conflicting state', async () => {
  const now = new Date('2026-10-18T08:00:00Z');
  const options = { stickerId: 2, action: 'ENTRY', gate: 4, cooldownSeconds: 10, scannedAt: now };
  const first = movementDb(null);
  await gates.validateMovement(first, options);
  assert.match(first.queries[0], /FOR UPDATE/);
  await assert.rejects(gates.validateMovement(movementDb({ scan_type: 'entry', scanned_at: now }), { ...options, action: 'EXIT' }), e => e.code === 'DUPLICATE_SCAN');
  const prior = { scan_type: 'entry', scanned_at: new Date(now - 11000) };
  await gates.validateMovement(movementDb(prior, 'exit'), { ...options, action: 'EXIT' });
  await assert.rejects(gates.validateMovement(movementDb(prior), options), e => e.code === 'MOVEMENT_CONFLICT');
  await assert.rejects(gates.validateMovement(movementDb(null, 'exit'), options), e => e.code === 'GATE_DIRECTION_MISMATCH');
  await assert.rejects(gates.validateMovement(movementDb(prior), { ...options, scannedAt: new Date(now - 20000) }), e => e.code === 'DUPLICATE_SCAN');
});

test('administrative force exit does not invent a physical gate', async () => {
  const result = await gates.validateMovement(movementDb(null), { stickerId: 2, administrativeOverride: true });
  assert.equal(result.gate, null);
});
