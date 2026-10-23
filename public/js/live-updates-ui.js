/* Presentation only: the page retains its existing fetch and 20-second refresh. */
(function () {
  'use strict';
  const list = document.getElementById('updatesList');
  if (!list) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const lite = Boolean(navigator.connection?.saveData || (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2));
  const canAnimate = () => !reduced.matches && !lite && !document.hidden && document.readyState !== 'loading';
  const animations = new Set();
  const cache = new Map();
  const metricValues = new Map();
  const dayFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Manila', year: 'numeric', month: '2-digit', day: '2-digit' });
  const dateFormatter = new Intl.DateTimeFormat('en-PH', { timeZone: 'Asia/Manila', year: 'numeric', month: 'short', day: 'numeric' });
  const exactFormatter = new Intl.DateTimeFormat('en-PH', { timeZone: 'Asia/Manila', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' });
  const lastUpdated = document.getElementById('updatesLastUpdated');
  const refresh = document.getElementById('updatesRefreshBtn');
  const live = document.getElementById('updatesLiveStatus');
  let records = [];
  let filter = 'all';
  let renderer;
  let rendered = false;
  let pending = 0;
  let failed = false;
  let lastSuccess = null;
  let lastPulse = Date.now();
  let refreshTimer;
  const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const timestamp = value => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).getTime() : null;
  const dayKey = value => {
    if (value === null) return 'unknown';
    const parts = Object.fromEntries(dayFormatter.formatToParts(new Date(value)).map(part => [part.type, part.value]));
    return `${parts.year}-${parts.month}-${parts.day}`;
  };
  const unknown = row => !String(row.full_name || '').trim() || /^unknown student$/i.test(String(row.full_name).trim());
  const action = row => ['ENTRY', 'EXIT', 'VERIFY'].includes(String(row.action).toUpperCase()) ? String(row.action).toUpperCase() : 'VERIFY';
  const exact = value => value === null ? 'Time not recorded' : `${exactFormatter.format(new Date(value))} (Philippine time)`;
  function dayLabel(key, now = Date.now()) {
    if (key === 'unknown') return 'Date not recorded';
    if (key === dayKey(now)) return 'Today';
    if (key === dayKey(now - 86400000)) return 'Yesterday';
    return dateFormatter.format(new Date(`${key}T12:00:00+08:00`));
  }
  function relative(value, now, calendar = true) {
    if (value === null) return 'Time not recorded';
    if (value > now + 5000) return 'Time is ahead of this device';
    if (calendar && dayKey(value) === dayKey(now - 86400000)) return 'Yesterday';
    const seconds = Math.max(0, Math.floor((now - value) / 1000));
    if (seconds < 5) return 'Just now';
    const [amount, unit] = seconds < 60 ? [seconds, 'second'] : seconds < 3600 ? [Math.floor(seconds / 60), 'minute'] : seconds < 86400 ? [Math.floor(seconds / 3600), 'hour'] : [Math.floor(seconds / 86400), 'day'];
    return `${amount} ${unit}${amount === 1 ? '' : 's'} ago`;
  }
  function motion(node, frames, options = {}, done) {
    if (!node?.animate || !canAnimate()) { done?.(); return; }
    const animation = node.animate(frames, { duration: 280, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards', ...options });
    animations.add(animation);
    animation.finished.catch(() => {}).finally(() => { animations.delete(animation); done?.(); });
  }
  function finishMotion() { animations.forEach(animation => animation.finish()); }
  reduced.addEventListener('change', finishMotion);
  document.addEventListener('visibilitychange', () => { if (document.hidden) finishMotion(); else tick(); });

  function sourceChip(row) {
    const source = String(row.scan_source || row.source || '').trim();
    const methods = {
      manual: ['ph-keyboard', 'Manual'], scanner: ['ph-qr-code', 'Scanned: QR scanner'],
      camera_phone: ['ph-qr-code', 'Scanned: Phone camera'], offline_sync: ['ph-cloud-arrow-up', 'Offline sync']
    };
    const method = methods[source.toLowerCase()];
    if (method) return `<span class="live-meta-chip live-method"><i class="ph ${method[0]}" aria-hidden="true"></i>${escape(method[1])}</span>`;
    return `${source ? `<span class="live-meta-chip">Source <strong>${escape(source.replace(/_/g, ' '))}</strong></span>` : ''}<span class="live-meta-chip live-method"><i class="ph ph-question" aria-hidden="true"></i>Method unavailable</span>`;
  }
  function renderRow(row) {
    const direction = action(row);
    const icon = { ENTRY: 'ph-sign-in', EXIT: 'ph-sign-out', VERIFY: 'ph-scan' }[direction];
    const at = timestamp(row.scanned_at);
    const gate = String(row.gate_name || row.gate || '').trim();
    const gateLabel = /^admin console$/i.test(gate) ? 'Source ' : /\bgate\b/i.test(gate) ? '' : 'Gate ';
    const result = String(row.result || 'INVALID').toUpperCase();
    return `<article class="live-event event-${direction.toLowerCase()}${unknown(row) ? ' is-unknown' : ''}">
      <span class="live-event-icon" aria-hidden="true"><i class="ph ${icon}"></i></span>
      <div class="live-event-body"><div class="live-event-heading"><strong class="live-event-name">${escape(String(row.full_name || '').trim() || 'Unknown Student')}</strong><span class="live-direction"><i class="ph ${icon}" aria-hidden="true"></i>${direction}</span></div>
        ${unknown(row) ? '<p class="live-unknown-note"><i class="ph ph-warning" aria-hidden="true"></i>Student identity unavailable</p>' : ''}
        <div class="live-event-meta"><span class="live-meta-chip"><i class="ph ph-door" aria-hidden="true"></i>${gateLabel}<strong>${escape(gate || 'Not recorded')}</strong></span>${sourceChip(row)}${result !== 'VALID' ? `<span class="live-meta-chip live-result">Result <strong>${escape(result)}</strong></span>` : ''}</div>
      </div>
      <time class="live-event-time" ${at === null ? '' : `datetime="${new Date(at).toISOString()}" data-event-time="${at}"`} title="${escape(exact(at))}" aria-label="${escape(exact(at))}">${escape(relative(at, Date.now()))}</time>
    </article>`;
  }

  // Reuse nodes and preserve the visible row when new records arrive above a scrolled feed.
  function reconcile(parent, desired) {
    let cursor = parent.firstChild;
    for (const node of desired) {
      if (node === cursor) cursor = cursor.nextSibling;
      else parent.insertBefore(node, cursor);
    }
    while (cursor) { const next = cursor.nextSibling; cursor.remove(); cursor = next; }
  }
  function paint(changedFilter = false) {
    const oldCards = [...list.querySelectorAll('.live-event')];
    const positions = new Map(oldCards.map(node => [node, node.getBoundingClientRect().top]));
    const top = list.getBoundingClientRect().top;
    const anchor = !changedFilter && list.scrollTop > 1 ? oldCards.find(node => node.getBoundingClientRect().bottom > top + 44) : null;
    const previousTop = anchor?.getBoundingClientRect().top;
    const matching = records.filter(({ row }) => filter === 'all' || (filter === 'unknown' ? unknown(row) : action(row).toLowerCase() === filter));
    const visible = matching.slice(0, 14);
    const groups = new Map();
    const oldGroups = new Map([...list.querySelectorAll('.updates-day')].map(group => [group.dataset.day, group]));
    const nextNodes = [];
    for (const item of visible) {
      const key = dayKey(timestamp(item.row.scanned_at));
      if (!groups.has(key)) {
        const group = oldGroups.get(key) || document.createElement('section');
        group.className = 'updates-day';
        group.dataset.day = key;
        if (!group.firstElementChild) group.innerHTML = '<h3 class="updates-day-title"></h3><div class="updates-day-events"></div>';
        group.firstElementChild.textContent = dayLabel(key);
        groups.set(key, { group, nodes: [] });
      }
      const signature = JSON.stringify(item.row);
      let cached = cache.get(item.key);
      if (!cached) {
        const template = document.createElement('template');
        template.innerHTML = renderer(item.row);
        cached = { node: template.content.firstElementChild, signature };
        cached.node.dataset.eventKey = item.key;
        cache.set(item.key, cached);
      } else if (cached.signature !== signature) {
        // Relative time is refreshed in place; other changed fields retain the row itself.
        const template = document.createElement('template');
        template.innerHTML = renderer(item.row);
        cached.node.className = template.content.firstElementChild.className;
        cached.node.replaceChildren(...template.content.firstElementChild.childNodes);
        cached.signature = signature;
      }
      groups.get(key).nodes.push(cached.node);
      nextNodes.push(cached.node);
    }
    for (const { group, nodes } of groups.values()) reconcile(group.lastElementChild, nodes);
    reconcile(list, [...groups.values()].map(value => value.group));
    if (!visible.length) {
      list.innerHTML = `<div class="updates-friendly-empty"><i class="ph ph-check-circle" aria-hidden="true"></i><strong>${filter === 'all' ? 'No activity yet' : 'No matching events'}</strong><p>${filter === 'all' ? 'New gate events will appear here.' : 'Try another filter to see more recent activity.'}</p></div>`;
    }
    if (changedFilter) list.scrollTop = 0;
    else if (anchor?.isConnected) list.scrollTop += anchor.getBoundingClientRect().top - previousTop;
    let animated = 0;
    for (const node of nextNodes) {
      const rect = node.getBoundingClientRect();
      if (rect.bottom < top || rect.top > Math.min(innerHeight, list.getBoundingClientRect().bottom) || animated >= 6) continue;
      const previous = positions.get(node);
      if (previous === undefined || changedFilter) {
        motion(node, [{ opacity: 0, transform: 'translateY(-7px)' }, { opacity: 1, transform: 'none' }], { delay: animated * 20 });
        if (rendered && !changedFilter && previous === undefined && canAnimate()) {
          const wash = document.createElement('span');
          wash.className = 'live-event-highlight';
          wash.setAttribute('aria-hidden', 'true');
          node.append(wash);
          motion(wash, [{ opacity: .35 }, { opacity: 0 }], { duration: 350, delay: 1600 }, () => wash.remove());
        }
      } else if (Math.abs(previous - rect.top) > 1) {
        motion(node, [{ transform: `translateY(${previous - rect.top}px)` }, { transform: 'none' }]);
      }
      animated++;
    }
    document.getElementById('updatesFilterCount').textContent = `Showing ${visible.length} of ${matching.length} matching recent events`;
    rendered = true;
  }
  function render(logs, makeRow) {
    renderer = makeRow;
    const occurrences = new Map();
    records = logs.map(row => {
      // The current API omits log IDs, so identical records use occurrence positions.
      const base = row.id != null ? `id:${row.id}` : JSON.stringify([row.scanned_at, row.action, row.result, row.gate_name || row.gate, row.student_number, row.sticker_code, row.plate_number, row.full_name]);
      const occurrence = occurrences.get(base) || 0;
      occurrences.set(base, occurrence + 1);
      return { row, key: `${base}#${occurrence}` };
    });
    const keys = new Set(records.map(item => item.key));
    for (const key of cache.keys()) if (!keys.has(key)) cache.delete(key);
    paint();
  }
  function metric(element, value) {
    if (!element) return;
    const previous = metricValues.get(element.id);
    metricValues.set(element.id, String(value));
    element.textContent = String(value);
    const card = element.closest('.hero-card');
    if (element.id === 'updatesMetricOverstay') card.classList.toggle('has-overstay', Number(value) > 0);
    if (previous !== undefined && previous !== String(value)) {
      motion(card.querySelector('.updates-stat-glow'), [{ opacity: .45 }, { opacity: 0 }], { duration: 400 });
      if (element.id === 'updatesMetricOverstay' && Number(value) > 0) pulse(card.querySelector('i'));
    }
  }
  function pulse(node) { motion(node, [{ opacity: 1, transform: 'scale(1)' }, { opacity: .6, transform: 'scale(.92)' }, { opacity: 1, transform: 'scale(1)' }], { duration: 400 }); }
  function tick() {
    if (document.hidden) return;
    const now = Date.now();
    const text = lastSuccess === null ? 'Waiting for the first update' : `Last updated: ${relative(lastSuccess, now, false)}`;
    if (lastUpdated.textContent !== text) lastUpdated.textContent = text;
    lastUpdated.title = lastSuccess === null ? '' : `Last displayed snapshot: ${exact(lastSuccess)}`;
    const status = !navigator.onLine ? 'Offline' : failed ? 'Update failed' : pending ? 'Refreshing' : lastSuccess !== null && now - lastSuccess > 45000 ? 'Waiting for update' : 'Live';
    live.querySelector('.updates-live-label').textContent = status;
    live.dataset.state = status === 'Live' ? 'live' : status === 'Refreshing' ? 'refreshing' : 'stale';
    // Short pulses with a long quiet interval avoid perpetual work on guard devices.
    if (now - lastPulse >= 8000) {
      lastPulse = now;
      const indicators = [status === 'Live' ? live.querySelector('.updates-live-dot') : null, document.querySelector('.updates-stats-grid .has-overstay i')];
      indicators.forEach(node => {
        if (node && node.getBoundingClientRect().bottom > 0 && node.getBoundingClientRect().top < innerHeight) pulse(node);
      });
    }
    list.querySelectorAll('[data-event-time]').forEach(node => {
      const copy = relative(Number(node.dataset.eventTime), now);
      if (node.textContent !== copy) node.textContent = copy;
    });
    list.querySelectorAll('.updates-day').forEach(group => {
      const copy = dayLabel(group.dataset.day, now);
      if (group.firstElementChild.textContent !== copy) group.firstElementChild.textContent = copy;
    });
  }
  function start() {
    pending++;
    clearTimeout(refreshTimer);
    refresh.disabled = true;
    refresh.setAttribute('aria-busy', 'true');
    refresh.classList.remove('is-refreshed');
    refresh.querySelector('i').className = 'ph ph-arrow-clockwise';
    refresh.querySelector('span').textContent = 'Refreshing';
    document.getElementById('updatesLoading').hidden = false;
    list.setAttribute('aria-busy', 'true');
    tick();
  }
  function success() {
    lastSuccess = Date.now();
    failed = false;
    document.getElementById('updatesRefreshError').hidden = true;
    tick();
    pulse(live.querySelector('.updates-live-dot'));
  }
  function failure() {
    failed = true;
    document.getElementById('updatesRefreshError').hidden = false;
    tick();
  }
  function end(ok) {
    pending = Math.max(0, pending - 1);
    if (pending) return;
    refresh.disabled = false;
    refresh.setAttribute('aria-busy', 'false');
    list.setAttribute('aria-busy', 'false');
    document.getElementById('updatesLoading').hidden = true;
    refresh.classList.toggle('is-refreshed', ok);
    refresh.querySelector('i').className = `ph ${ok ? 'ph-check' : 'ph-arrow-clockwise'}`;
    refresh.querySelector('span').textContent = ok ? 'Updated' : 'Refresh';
    if (ok) {
      motion(refresh.querySelector('i'), [{ opacity: 0, transform: 'scale(.8)' }, { opacity: 1, transform: 'none' }]);
      refreshTimer = setTimeout(() => { refresh.classList.remove('is-refreshed'); refresh.querySelector('i').className = 'ph ph-arrow-clockwise'; refresh.querySelector('span').textContent = 'Refresh'; }, 1500);
    }
    tick();
  }
  function init(logs, makeRow, at) {
    lastSuccess = timestamp(at);
    document.querySelectorAll('.updates-stats-grid .hero-card p').forEach(element => metric(element, element.textContent.trim()));
    render(logs, makeRow);
    tick();
  }
  document.getElementById('updatesFilters').addEventListener('click', event => {
    const button = event.target instanceof Element ? event.target.closest('[data-update-filter]') : null;
    if (!button || filter === button.dataset.updateFilter) return;
    filter = button.dataset.updateFilter;
    document.querySelectorAll('[data-update-filter]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    paint(true);
  });
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.updates-stats-grid .hero-card p').forEach(element => window.NaapMotion?.countUp(element));
    list.querySelectorAll('.live-event').forEach((node, index) => { if (index < 6 && node.getBoundingClientRect().top < innerHeight) window.NaapMotion?.animate(node, 'enter', index * 20); });
    pulse(live.querySelector('.updates-live-dot'));
    pulse(document.querySelector('.updates-stats-grid .has-overstay i'));
  }, { once: true });
  window.addEventListener('online', tick);
  window.addEventListener('offline', tick);
  setInterval(tick, 1000);
  window.NaapUpdatesUi = { init, render, renderRow, metric, start, success, failure, end };
}());
