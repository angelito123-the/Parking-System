const { randomUUID } = require('node:crypto');

// One lifecycle for notification and scanner streams. Register cleanup before
// any asynchronous snapshot work, and tie each connection to its login session.
function openEventStream({ req, res, clients, sessionStore, keepaliveMs }) {
  const id = randomUUID();
  const userId = Number(req.authUser.id);
  const role = req.authUser.role;
  const sessionId = req.sessionID;
  let closed = false;
  let heartbeatTimer;
  let expiryTimer;
  let expiresAt = Infinity;
  let validation;

  function close(destroy = false) {
    if (closed) return;
    closed = true;
    clearInterval(heartbeatTimer);
    clearTimeout(expiryTimer);
    if (validation) validation.finish(false);
    clients.delete(id);
    req.off('aborted', onDisconnect);
    res.off('close', onDisconnect);
    res.off('error', onDisconnect);
    if (destroy) res.destroy();
    else if (!res.writableEnded && !res.destroyed) res.end();
  }

  function onDisconnect() { close(true); }

  function setExpiry(session) {
    clearTimeout(expiryTimer);
    expiresAt = session.cookie?.expires ? new Date(session.cookie.expires).getTime() : Infinity;
    if (Number.isNaN(expiresAt) || expiresAt <= Date.now()) { close(); return false; }
    if (Number.isFinite(expiresAt)) expiryTimer = setTimeout(close, Math.min(expiresAt - Date.now(), 2147483647));
    return true;
  }

  function send(event, payload = {}) {
    if (closed) return false;
    if (res.destroyed || res.writableEnded || Date.now() >= expiresAt) { close(); return false; }
    try {
      // Disconnect a stalled reader instead of buffering events indefinitely.
      if (!res.write('event: ' + event + '\ndata: ' + JSON.stringify(payload) + '\n\n')) {
        close(true);
        return false;
      }
      return true;
    } catch (_error) {
      close(true);
      return false;
    }
  }

  function authorize() {
    if (closed) return Promise.resolve(false);
    if (validation) return validation.promise;
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    const pending = { promise, finish(valid) {
      if (validation !== pending) return;
      clearTimeout(pending.timer);
      validation = undefined;
      resolve(valid);
    } };
    validation = pending;
    // A database outage must not leave an unchecked stream open indefinitely.
    pending.timer = setTimeout(() => close(), Math.min(keepaliveMs, 10000));
    try {
      sessionStore.get(sessionId, (error, session) => {
        if (closed || validation !== pending) return;
        if (error || !session?.user || Number(session.user.id) !== userId ||
            session.user.role !== role || session.user.mustChangePassword || !setExpiry(session)) {
          close();
          return;
        }
        pending.finish(true);
      });
    } catch (_error) { close(); }
    return promise;
  }

  const client = { id, userId, role, sessionId, send, close, authorize };
  clients.set(id, client);
  req.once('aborted', onDisconnect);
  res.once('close', onDisconnect);
  res.once('error', onDisconnect);
  if (req.aborted || res.destroyed || !setExpiry(req.session)) { close(); return client; }
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  heartbeatTimer = setInterval(async () => {
    if (await authorize()) send('ping', { ts: new Date().toISOString() });
  }, keepaliveMs);
  return client;
}

module.exports = { openEventStream };
