/* Presentation only: notification requests and mutations remain in the header. */
(function () {
  'use strict';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const lite = Boolean(navigator.connection?.saveData || (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2));
  const canAnimate = () => !reduced.matches && !lite && !document.hidden;
  const running = new Set();
  const activeMotion = new WeakMap();
  function motion(node, frames, options = {}, done) {
    activeMotion.get(node)?.cancel();
    if (!node?.animate || !canAnimate()) { done?.(); return; }
    const animation = node.animate(frames, { duration: 240, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards', ...options });
    activeMotion.set(node, animation);
    running.add(animation);
    animation.finished.catch(() => {}).finally(() => {
      running.delete(animation);
      if (activeMotion.get(node) === animation) { activeMotion.delete(node); done?.(); }
    });
  }
  const finishMotion = () => running.forEach(animation => animation.finish());
  reduced.addEventListener('change', finishMotion);
  document.addEventListener('visibilitychange', () => { if (document.hidden) finishMotion(); });

  // A measured transform supports tabs of different widths without stretching them.
  function slidingIndicator(group, selected, underline = false) {
    if (!group) return;
    const marker = document.createElement('span');
    marker.className = `header-slide-marker${underline ? ' is-underline' : ''}`;
    marker.setAttribute('aria-hidden', 'true');
    group.prepend(marker);
    const update = () => {
      const button = group.querySelector(selected);
      if (!button || !button.offsetWidth) return;
      marker.style.transform = `translateX(${button.offsetLeft}px) scaleX(${button.offsetWidth / 100})`;
      group.classList.add('indicator-ready');
    };
    new MutationObserver(update).observe(group, { subtree: true, attributes: true, attributeFilter: ['aria-selected', 'aria-pressed'] });
    new ResizeObserver(update).observe(group);
    document.fonts?.ready.then(update);
    update();
  }
  slidingIndicator(document.querySelector('.student-tabs-bar .flow-tabs'), '[aria-selected="true"]', true);
  slidingIndicator(document.querySelector('.notification-filter-row'), '[aria-pressed="true"]');

  const panel = document.getElementById('notificationPanel');
  if (!panel) return;
  const bell = document.getElementById('notificationBell');
  const backdrop = document.getElementById('notificationBackdrop');
  const list = document.getElementById('notificationPanelList');
  const meta = document.getElementById('notificationPanelMeta');
  const caughtUp = document.getElementById('notificationCaughtUp');
  const toast = document.getElementById('notificationFeedback');
  const formatter = new Intl.DateTimeFormat('en-PH', { timeZone: 'Asia/Manila', dateStyle: 'medium', timeStyle: 'medium' });
  const dayFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Manila', dateStyle: 'short' });
  let summary = null;
  let rows = [];
  let listHealthy = false;
  let closePanel;
  let toastTimer;
  let previousStates = new Map();
  const isResolved = row => String(row.status || '').toLowerCase() === 'resolved';
  const timestamp = value => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).getTime() : null;
  function relative(value) {
    if (value === null) return 'Time unavailable';
    const now = Date.now();
    if (value > now + 5000) return 'Time is ahead of this device';
    if (dayFormatter.format(value) === dayFormatter.format(now - 86400000)) return 'Yesterday';
    const seconds = Math.max(0, Math.floor((now - value) / 1000));
    if (seconds < 5) return 'Just now';
    const [amount, unit] = seconds < 60 ? [seconds, 'second'] : seconds < 3600 ? [Math.floor(seconds / 60), 'minute'] : seconds < 86400 ? [Math.floor(seconds / 3600), 'hour'] : [Math.floor(seconds / 86400), 'day'];
    return `${amount} ${unit}${amount === 1 ? '' : 's'} ago`;
  }
  function renderRow(row, severityClass, escape) {
    const resolved = isResolved(row);
    const unread = !row.is_read;
    const severity = severityClass === 'sev-high' ? 'High' : severityClass === 'sev-medium' ? 'Medium' : 'Low';
    const icon = resolved ? 'ph-check-circle' : { High: 'ph-warning', Medium: 'ph-warning-circle', Low: 'ph-info' }[severity];
    const created = timestamp(row.created_at);
    const exact = created === null ? 'Creation time unavailable' : `Created ${formatter.format(created)} (Philippine time)`;
    const id = Number.isInteger(Number(row.id)) ? Number(row.id) : 0;
    return `<article class="notification-row ${resolved ? 'is-resolved' : unread ? 'is-unread' : 'is-read'}" data-notification-id="${id}">
      <div class="notification-row-main">
        <p class="notification-row-title"><span class="notification-state-icon ${resolved ? 'state-resolved' : severityClass}" role="img" aria-label="${resolved ? 'Resolved' : severity + ' risk'}" title="${resolved ? 'Resolved' : severity + ' risk'}"><i class="ph ${icon}" aria-hidden="true"></i></span><span>${escape(row.title || 'Alert')}</span></p>
        <p class="notification-row-message">${escape(row.message || '-')}</p>
        <p class="notification-row-meta"><span class="notification-chip ${resolved ? 'state-resolved' : 'state-active'}">${resolved ? 'Resolved' : unread ? 'Unread' : 'Read'}</span><span class="notification-category">${escape(String(row.type || 'Alert').toLowerCase().replace(/_/g, ' '))}</span></p>
      </div>
      <div class="notification-row-footer"><time class="notification-row-time" ${created === null ? '' : `datetime="${new Date(created).toISOString()}" data-notify-time="${created}"`} title="${escape(exact)}" aria-label="${escape(exact)}">${relative(created)}</time>
        <div class="notification-row-actions">${unread ? `<button type="button" class="btn-sm btn-reset notification-read-btn" data-alert-id="${id}">Mark read</button>` : ''}${!resolved ? `<button type="button" class="btn-sm btn-reset notification-resolve-btn" data-alert-id="${id}">Resolve</button>` : ''}</div>
      </div></article>`;
  }
  function summaryChanged(value) {
    if (value) summary = value;
    const active = Number(summary?.active_total);
    const loadedActive = rows.some(row => !isResolved(row));
    const mismatch = summary && active === 0 && loadedActive;
    if (summary) meta.textContent = mismatch ? 'Alert status is updating…' : `${active} active alert(s)`;
    caughtUp.hidden = !(listHealthy && summary && active === 0 && !loadedActive);
    if (!caughtUp.hidden) {
      const unread = Number(summary.unread_total || 0);
      caughtUp.querySelector('small').textContent = unread > 0 ? `No active alerts. ${unread} unread in history.` : 'No active alerts need attention.';
    }
  }
  function restoreListFocus(focused) {
    if (!focused || !panel.classList.contains('open')) return;
    const matching = [...list.querySelectorAll('button[data-alert-id]')].find(button => button.dataset.alertId === focused.dataset.alertId && button.className === focused.className && button.getClientRects().length);
    (matching || list.querySelector('.notification-resolved[open] summary') || panel.querySelector('[data-notify-filter][aria-pressed="true"]'))?.focus({ preventScroll: true });
  }
  function render(newRows, renderer) {
    const focused = list.contains(document.activeElement) ? document.activeElement : null;
    const historyOpen = Boolean(list.querySelector('.notification-resolved[open]'));
    const scroll = list.scrollTop;
    rows = newRows;
    listHealthy = true;
    const active = rows.filter(row => !isResolved(row));
    const resolved = rows.filter(isResolved);
    const unreadHistory = resolved.filter(row => !row.is_read).length;
    list.innerHTML = active.map(renderer).join('') + (resolved.length ? `<details class="notification-resolved" ${historyOpen ? 'open' : ''}><summary><i class="ph ph-check-circle" aria-hidden="true"></i> Resolved <span>${resolved.length}${unreadHistory ? ` · ${unreadHistory} unread` : ''}</span><i class="ph ph-caret-down" aria-hidden="true"></i></summary><div class="notification-resolved-items">${resolved.map(renderer).join('')}</div></details>` : '');
    if (!rows.length) list.innerHTML = window.NaapUiState.render('empty', { title: 'No matching alerts', message: 'Try another filter or check back later.', compact: true });
    const disclosure = list.querySelector('.notification-resolved');
    disclosure?.addEventListener('toggle', () => { if (disclosure.open) motion(disclosure.lastElementChild, [{ opacity: 0, transform: 'translateY(-4px)' }, { opacity: 1, transform: 'none' }]); });
    list.scrollTop = scroll;
    const currentStates = new Map(rows.map(row => [String(row.id), { read: Boolean(row.is_read), resolved: isResolved(row) }]));
    let index = 0;
    list.querySelectorAll('.notification-row').forEach(node => {
      if (!node.getClientRects().length || index >= 5) return;
      const prior = previousStates.get(node.dataset.notificationId);
      const current = currentStates.get(node.dataset.notificationId);
      const settled = prior && current && ((!prior.read && current.read) || (!prior.resolved && current.resolved));
      motion(node, settled ? [{ opacity: .55, transform: 'translateY(-2px)' }, { opacity: 1, transform: 'none' }] : [{ opacity: 0, transform: 'translateY(5px)' }, { opacity: 1, transform: 'none' }], { delay: index++ * 20 });
    });
    previousStates = currentStates;
    motion(list, [{ opacity: .65 }, { opacity: 1 }], { duration: 180 });
    summaryChanged();
    restoreListFocus(focused);
  }
  function position() {
    if (!panel.classList.contains('open')) return;
    const bellRect = bell.getBoundingClientRect();
    if (innerWidth > 600) panel.style.top = `${Math.min(bellRect.bottom + 12, innerHeight - 180)}px`;
    else panel.style.removeProperty('top');
    const panelRect = panel.getBoundingClientRect();
    panel.style.transformOrigin = innerWidth <= 600 ? 'center bottom' : `${Math.max(20, Math.min(panelRect.width - 20, bellRect.left + bellRect.width / 2 - panelRect.left))}px top`;
  }
  function open(close) {
    closePanel = close;
    panel.classList.remove('is-closing');
    backdrop.classList.remove('is-closing');
    document.body.classList.add('notifications-open');
    backdrop.classList.add('open');
    position();
    motion(panel, [{ opacity: 0, transform: 'scale(.97)' }, { opacity: 1, transform: 'none' }]);
    motion(backdrop, [{ opacity: 0 }, { opacity: 1 }]);
  }
  function close() {
    if (!document.body.classList.contains('notifications-open')) return;
    document.body.classList.remove('notifications-open');
    backdrop.classList.remove('open');
    panel.classList.add('is-closing');
    backdrop.classList.add('is-closing');
    motion(panel, [{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'scale(.97)' }], {}, () => panel.classList.remove('is-closing'));
    motion(backdrop, [{ opacity: 1 }, { opacity: 0 }], {}, () => backdrop.classList.remove('is-closing'));
  }
  function feedback(success) {
    clearTimeout(toastTimer);
    toast.hidden = false;
    toast.classList.toggle('is-error', !success);
    toast.querySelector('i').className = `ph ${success ? 'ph-check-circle' : 'ph-warning-circle'}`;
    toast.querySelector('p').textContent = success ? 'All notifications marked as read.' : 'Couldn’t mark notifications as read. Please try again.';
    motion(toast, [{ opacity: 0, transform: 'translateY(5px)' }, { opacity: 1, transform: 'none' }]);
    if (success) toastTimer = setTimeout(() => { if (!toast.contains(document.activeElement)) toast.hidden = true; }, 6000);
  }
  function listFailed() { listHealthy = false; summaryChanged(); }
  function afterLoad() {
    if (panel.classList.contains('open') && !panel.contains(document.activeElement)) document.getElementById('notificationCloseBtn')?.focus({ preventScroll: true });
  }
  toast.querySelector('button').addEventListener('click', () => { clearTimeout(toastTimer); toast.hidden = true; document.getElementById('notificationMarkAllBtn')?.focus(); });
  // Dismiss from the header before focus moves; Tab and programmatic focus stay in the panel.
  document.addEventListener('pointerdown', event => {
    if (panel.classList.contains('open') && event.target instanceof Element && event.target.closest('.top-nav') && !event.target.closest('#notificationBell')) closePanel?.({ restoreFocus: false });
  }, true);
  document.addEventListener('focusin', event => {
    if (panel.classList.contains('open') && !panel.contains(event.target)) document.getElementById('notificationCloseBtn')?.focus({ preventScroll: true });
  });
  panel.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const controls = [...panel.querySelectorAll('a[href],button:not([disabled]),summary,[tabindex="0"]')].filter(node => node.getClientRects().length);
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  window.addEventListener('resize', position);
  const tick = () => {
    if (document.hidden || !panel.classList.contains('open')) return;
    list.querySelectorAll('[data-notify-time]').forEach(node => { const text = relative(Number(node.dataset.notifyTime)); if (node.textContent !== text) node.textContent = text; });
  };
  setInterval(tick, 1000);
  window.NaapHeaderUi = { renderRow, render, summaryChanged, open, close, feedback, listFailed, afterLoad, filterChanged: () => motion(list, [{ opacity: 1 }, { opacity: .55 }], { duration: 150 }) };
}());
