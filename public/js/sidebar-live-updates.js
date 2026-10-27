/* Browser-local unseen movements from the existing stream; never an alert count. */
(() => {
  const sidebar = document.getElementById('mobileSidebar');
  const badge = sidebar?.querySelector('[data-sidebar-live]');
  if (!badge || !sidebar.dataset.sidebarUser) return;
  const link = badge.closest('a');
  const key = `naap-sidebar-live-v1:${document.body.dataset.role}:${sidebar.dataset.sidebarUser}`;
  const empty = () => ({ count: 0, seenAt: 0, recent: [] });
  let state = empty();
  let memoryOnly = false;
  let displayed = -1;
  let queue = Promise.resolve();
  const read = () => {
    if (memoryOnly) return state;
    try {
      const saved = JSON.parse(localStorage.getItem(key));
      if (saved && Number.isSafeInteger(saved.count) && saved.count >= 0 && Number.isFinite(saved.seenAt) && Array.isArray(saved.recent)) {
        state = { count: saved.count, seenAt: saved.seenAt, recent: saved.recent.filter(id => /^[a-f0-9]{64}$/.test(id)).slice(-512) };
      }
    } catch (_) { memoryOnly = true; }
    return state;
  };
  const save = () => {
    if (memoryOnly) return;
    try { localStorage.setItem(key, JSON.stringify(state)); } catch (_) { memoryOnly = true; }
  };
  const viewing = () => location.pathname === '/admin/updates' && !document.hidden;
  const paint = () => {
    if (displayed === state.count) return;
    displayed = state.count;
    badge.hidden = !displayed;
    badge.textContent = displayed > 99 ? '99+' : String(displayed);
    const description = displayed ? `${displayed} new update${displayed === 1 ? '' : 's'}` : 'No new updates';
    link.setAttribute('aria-label', `Live Updates, ${description}`);
    link.setAttribute('aria-description', description);
    // No recurring pulse or DOM replacement on summary polls.
  };
  const markViewed = () => {
    if (!viewing()) return;
    read();
    state.count = 0;
    state.seenAt = Date.now();
    save(); paint();
  };
  const movementCount = event => {
    if (event.reason === 'pending-entry-confirmed') return 1;
    if (['movement-recorded', 'visitor-movement-recorded'].includes(event.reason) && ['ENTRY', 'EXIT'].includes(event.movement_action)) return 1;
    if (event.reason === 'offline-queue-synced' && Number.isSafeInteger(event.synced_count) && event.synced_count > 0) return event.synced_count;
    return 0;
  };
  window.addEventListener('naap:notifications-updated', event => {
    let update;
    try { update = typeof event.detail === 'string' ? JSON.parse(event.detail) : event.detail; } catch (_) { return; }
    if (!update || !Number.isFinite(Date.parse(update.server_time))) return;
    const count = movementCount(update);
    if (!count) return;
    const receivedAt = Date.now();
    // Hash identifying fields so QR tokens and vehicle identifiers never enter storage.
    const identity = JSON.stringify([update.reason, update.server_time, update.movement_action, update.gate_id, update.sticker_id, update.pending_entry_id, update.visitor_pass_id, update.qr_value, update.synced_count]);
    queue = queue.then(async () => {
      if (!crypto.subtle) return; // Secure contexts provide this; do not invent a count otherwise.
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
      const id = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
      read();
      if (state.recent.includes(id)) return;
      state.recent = [...state.recent, id].slice(-512);
      if (viewing()) { state.count = 0; state.seenAt = Date.now(); }
      else if (receivedAt > state.seenAt) state.count += count;
      save(); paint();
    }).catch(() => { /* A malformed or unsupported event must not affect navigation. */ });
  });
  window.addEventListener('storage', event => {
    if (event.key !== key && event.key !== null) return;
    if (!event.newValue) state = empty();
    read();
    if (viewing() && state.count) markViewed(); else paint();
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) markViewed(); });
  window.addEventListener('pageshow', () => { read(); if (viewing()) markViewed(); else paint(); });
  read();
  if (viewing()) markViewed(); else paint();
})();
