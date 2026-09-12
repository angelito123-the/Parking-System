const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter, once } = require('node:events');
const { openEventStream } = require('../lib/event-stream');

function setup(t, { session, get, keepaliveMs = 10000, write } = {}) {
  session = session || { user: { id: 7, role: 'guard' }, cookie: { expires: new Date(Date.now() + 60000) } };
  const req = Object.assign(new EventEmitter(), { authUser: { id: 7, role: 'guard' }, sessionID: 'session-a', session });
  const chunks = [];
  const res = Object.assign(new EventEmitter(), {
    writableEnded: false, destroyed: false,
    setHeader() {}, flushHeaders() {},
    write: write || (chunk => { chunks.push(chunk); return true; }),
    end() { this.writableEnded = true; this.emit('finish'); },
    destroy() { this.destroyed = true; this.emit('close'); }
  });
  const clients = new Map();
  const client = openEventStream({ req, res, clients, keepaliveMs,
    sessionStore: { get: get || ((_id, callback) => callback(null, session)) } });
  t.after(() => client.close());
  return { req, res, clients, client, chunks };
}

test('valid streams deliver events and release listeners on repeated disconnects', async t => {
  const { req, res, clients, client, chunks } = setup(t);
  assert.equal(await client.authorize(), true);
  assert.equal(client.send('queue-health', { online_devices: 2 }), true);
  assert.match(chunks[0], /event: queue-health\ndata: {"online_devices":2}\n\n/);
  res.emit('close');
  req.emit('aborted');
  assert.equal(clients.size, 0);
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
  assert.equal(res.listenerCount('error'), 0);
  assert.equal(client.send('late', {}), false);
});

for (const [name, session] of [
  ['deleted', null],
  ['different user', { user: { id: 8, role: 'guard' } }],
  ['changed role', { user: { id: 7, role: 'admin' } }],
  ['password change required', { user: { id: 7, role: 'guard', mustChangePassword: true } }],
  ['expired', { user: { id: 7, role: 'guard' }, cookie: { expires: new Date(0) } }]
]) {
  test(name + ' sessions lose their existing stream', async t => {
    const { client, res, clients } = setup(t, { get: (_id, callback) => callback(null, session) });
    assert.equal(await client.authorize(), false);
    assert.equal(clients.size, 0);
    assert.equal(res.writableEnded, true);
    assert.equal(client.send('private-data', { token: 'must-not-send' }), false);
  });
}

test('heartbeat notices session deletion by another server', { timeout: 2000 }, async t => {
  const { res, clients } = setup(t, { keepaliveMs: 20, get: (_id, callback) => callback(null, null) });
  await once(res, 'finish');
  assert.equal(clients.size, 0);
});

test('cookie expiry ends an idle stream without waiting for the heartbeat', { timeout: 2000 }, async t => {
  const { res, clients } = setup(t, { session: {
    user: { id: 7, role: 'guard' }, cookie: { expires: new Date(Date.now() + 30) }
  } });
  await once(res, 'finish');
  assert.equal(clients.size, 0);
});

for (const [name, get] of [
  ['callback failure', (_id, callback) => callback(new Error('database offline'))],
  ['thrown failure', () => { throw new Error('database offline'); }],
  ['unresponsive database', () => {}]
]) {
  test(name + ' closes the stream safely', { timeout: 2000 }, async t => {
    const { client, clients } = setup(t, { get, keepaliveMs: 20 });
    assert.equal(await client.authorize(), false);
    assert.equal(clients.size, 0);
  });
}

test('disconnect resolves pending authorization and ignores a late database result', async t => {
  let callback;
  const { client, clients, res } = setup(t, { get: (_id, done) => { callback = done; } });
  const pending = client.authorize();
  res.emit('close');
  assert.equal(await pending, false);
  callback(null, { user: { id: 7, role: 'guard' } });
  assert.equal(clients.size, 0);
});

for (const [name, write] of [
  ['stalled reader', () => false],
  ['broken socket', () => { throw new Error('socket closed'); }]
]) {
  test(name + ' is removed from the registry without throwing', t => {
    const { client, res, clients } = setup(t, { write });
    assert.equal(client.send('ping', {}), false);
    assert.equal(res.destroyed, true);
    assert.equal(clients.size, 0);
  });
}
