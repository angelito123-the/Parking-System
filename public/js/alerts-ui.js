/* Presentation helpers only. The page retains ownership of all existing requests. */
(function () {
  'use strict';
  const list = document.getElementById('alertsList');
  if (!list) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const activeAnimations = new Set();
  let previousIds = new Set();
  let hasRendered = false;
  let pendingFocus = null;
  const lite = Boolean(navigator.connection?.saveData || (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2));
  const canAnimate = () => document.readyState !== 'loading' && !reduced.matches && !document.hidden && !lite;
  function animate(node, frames, done, delay = 0) {
    if (!node?.animate || !canAnimate()) { done?.(); return; }
    const animation = node.animate(frames, { duration: 240, delay: Math.min(delay, 120), easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards' });
    activeAnimations.add(animation);
    animation.finished.catch(() => {}).finally(() => { activeAnimations.delete(animation); done?.(); });
  }
  function finishAnimations() { activeAnimations.forEach(animation => animation.finish()); }
  reduced.addEventListener('change', finishAnimations);
  document.addEventListener('visibilitychange', () => { if (document.hidden) finishAnimations(); });
  const inView = rect => rect.bottom > 0 && rect.top < innerHeight;

  function summary(rows) {
    const values = {
      alertsCountUnread: rows.filter(row => !row.is_read && String(row.status).toLowerCase() !== 'resolved').length,
      alertsCountHigh: rows.filter(row => ['high', 'critical'].includes(String(row.severity).toLowerCase())).length,
      alertsCountResolved: rows.filter(row => String(row.status).toLowerCase() === 'resolved').length
    };
    for (const [id, value] of Object.entries(values)) {
      const node = document.getElementById(id);
      if (node) {
        const changed = node.dataset.count !== String(value);
        node.textContent = String(value);
        node.dataset.count = String(value);
        if (changed && canAnimate() && inView(node.getBoundingClientRect())) window.NaapMotion?.countUp(node);
      }
    }
    document.getElementById('alertsCountScope').textContent = `${rows.length} displayed alerts`;
  }

  function render(rows, markup) {
    const oldCards = new Map([...list.querySelectorAll('.alerts-log-row:not(.alert-exiting)')].map(card => [card.dataset.alertKey, { card, rect: card.getBoundingClientRect(), unread: card.classList.contains('is-unread') }]));
    // Disabling a focused action moves focus to body in some browsers.
    const focus = document.activeElement === document.body ? pendingFocus : document.activeElement;
    const focusCard = focus?.closest('[data-alert-key]');
    const focusId = focusCard?.dataset.alertKey;
    const focusSelector = focus?.matches('.alerts-read-btn') ? '.alerts-read-btn' : focus?.matches('.alerts-resolve-btn') ? '.alerts-resolve-btn' : focus?.matches('.alert-qr-copy') ? '.alert-qr-copy' : '.alerts-log-title';
    const listTop = list.getBoundingClientRect().top;
    const nextIds = new Set(rows.map(row => String(Number(row.id))));
    list.innerHTML = markup;
    const cards = [...list.querySelectorAll('.alerts-log-row')];
    let animated = 0;
    for (const card of cards) {
      const id = card.dataset.alertKey;
      const previous = oldCards.get(id);
      const rect = card.getBoundingClientRect();
      if (!canAnimate() || !inView(rect) || animated >= 6) continue;
      if (!previousIds.has(id)) {
        card.classList.add('is-arriving');
        animate(card, [{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'none' }], null, animated * 20);
        animated++;
      } else if (previous && previous.unread && !card.classList.contains('is-unread')) {
        // Cross-fade a tint overlay instead of animating background color or layout.
        const wash = document.createElement('span');
        wash.className = 'alert-transition-wash';
        wash.setAttribute('aria-hidden', 'true');
        card.append(wash);
        animate(wash, [{ opacity: .9 }, { opacity: 0 }], () => wash.remove());
        animated++;
      } else if (previous && Math.abs(previous.rect.top - rect.top) > 1) {
        animate(card, [{ transform: `translateY(${previous.rect.top - rect.top}px)` }, { transform: 'none' }]);
        animated++;
      }
    }
    // A removed unread card briefly fades over its old position; it cannot receive input.
    if (hasRendered && canAnimate()) {
      let exiting = 0;
      for (const [id, previous] of oldCards) {
        if (nextIds.has(id) || !previous.unread || !inView(previous.rect) || exiting >= 3) continue;
        const card = previous.card;
        card.classList.add('alert-exiting');
        card.inert = true;
        card.setAttribute('aria-hidden', 'true');
        card.style.top = `${previous.rect.top - listTop}px`;
        card.style.left = '0';
        card.style.width = `${previous.rect.width}px`;
        list.append(card);
        animate(card, [{ opacity: 1, transform: 'scaleY(1)' }, { opacity: 0, transform: 'translateY(-6px) scaleY(.97)' }], () => card.remove());
        exiting++;
      }
    }
    if (focusId) {
      const replacement = cards.find(card => card.dataset.alertKey === focusId);
      const target = replacement?.querySelector(focusSelector) || replacement?.querySelector('.alerts-log-title') || document.getElementById('alertsLogTitle');
      target?.focus({ preventScroll: true });
    }
    pendingFocus = null;
    previousIds = nextIds;
    hasRendered = true;
    summary(rows);
  }

  function loading(busy) {
    document.getElementById('alertsLoading').hidden = !busy;
    list.setAttribute('aria-busy', String(busy));
  }
  function busy(button, value) {
    if (!button) return;
    if (value && button === document.activeElement && list.contains(button)) pendingFocus = button;
    if (!value && pendingFocus === button) pendingFocus = null;
    button.disabled = value;
    button.classList.toggle('is-loading', value);
    button.setAttribute('aria-busy', String(value));
  }
  function failed() {
    document.getElementById('alertsCountScope').textContent = 'Last loaded alerts · update failed';
    if (pendingFocus && document.activeElement === document.body) document.getElementById('alertsLogTitle').focus({ preventScroll: true });
    pendingFocus = null;
  }
  async function feedback(response, message) {
    const data = await response.json().catch(() => ({ ok: false }));
    window.NaapFeedback?.show(response.ok && data.ok ? message : 'The alert could not be updated. Please try again.', { tone: response.ok && data.ok ? 'success' : 'error' });
  }

  // Chips describe the successful request, not unsaved selections in the form.
  function filters(applied, remove) {
    const container = document.getElementById('alertsFilterChips');
    container.replaceChildren();
    if (!applied) {
      const note = document.createElement('span');
      note.className = 'helper-text';
      note.textContent = 'Initial snapshot: all statuses. Apply filters to use the selections above.';
      container.append(note);
      return;
    }
    const names = { status: 'Status', type: 'Type', severity: 'Severity', read_state: 'Read state', from: 'From', to: 'To', q: 'Search' };
    for (const [key, label] of Object.entries(names)) {
      const value = applied[key];
      if (!value || value === 'all') continue;
      const field = document.getElementById('alertsFilterForm').elements.namedItem(key);
      const text = field?.tagName === 'SELECT' ? [...field.options].find(option => option.value === value)?.textContent || value : value;
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.removeFilter = key;
      button.setAttribute('aria-label', `Remove ${label.toLowerCase()} filter: ${text}`);
      const copy = document.createElement('span');
      copy.textContent = `${label}: ${text}`;
      const icon = document.createElement('i');
      icon.className = 'ph ph-x';
      icon.setAttribute('aria-hidden', 'true');
      button.append(copy, icon);
      button.addEventListener('click', () => {
        remove(key);
        // The response removes this chip; return to a stable keyboard target first.
        document.getElementById('alertsFilterToggle')?.focus({ preventScroll: true });
      });
      container.append(button);
    }
    if (!container.childElementCount) {
      const note = document.createElement('span');
      note.className = 'helper-text';
      note.textContent = 'All alerts · no filters applied';
      container.append(note);
    }
  }
  window.NaapAlertsUi = { render, loading, busy, failed, feedback, filters };
  document.addEventListener('DOMContentLoaded', () => {
    ['alertsCountUnread', 'alertsCountHigh', 'alertsCountResolved'].forEach(id => window.NaapMotion?.countUp(document.getElementById(id)));
    list.querySelectorAll('.alerts-log-row').forEach((card, index) => {
      if (canAnimate() && index < 6 && inView(card.getBoundingClientRect())) {
        card.classList.add('is-arriving');
        window.NaapMotion?.animate(card, 'enter', index * 20);
      }
    });
  }, { once: true });
  const toggle = document.getElementById('alertsFilterToggle');
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(open));
    if (window.NaapPages) window.NaapPages.reveal(document.getElementById('alertsFilterForm'), open);
    else document.getElementById('alertsFilterForm').hidden = !open;
  });
  list.addEventListener('click', async event => {
    const button = event.target instanceof Element ? event.target.closest('.alert-qr-copy') : null;
    if (!button) return;
    const value = button.dataset.copyQr;
    try {
      await navigator.clipboard.writeText(value);
      button.classList.add('is-copied');
      button.querySelector('i').className = 'ph ph-check';
      button.setAttribute('aria-label', 'QR identifier copied');
      window.NaapFeedback?.show('QR identifier copied.', { tone: 'success' });
      clearTimeout(button._copyTimer);
      button._copyTimer = setTimeout(() => {
        button.classList.remove('is-copied');
        button.querySelector('i').className = 'ph ph-copy';
        button.setAttribute('aria-label', 'Copy full QR identifier');
      }, 1800);
    } catch (_error) {
      window.prompt('Copy the full QR identifier:', value);
    }
  });
  list.addEventListener('keydown', event => {
    if (event.key === 'Escape') event.target.closest('.alert-qr-chip')?.classList.add('tooltip-dismissed');
  });
  list.addEventListener('focusin', event => event.target.closest('.alert-qr-chip')?.classList.remove('tooltip-dismissed'));
  list.addEventListener('pointerout', event => {
    const chip = event.target.closest('.alert-qr-chip');
    if (chip && !chip.contains(event.relatedTarget)) chip.classList.remove('tooltip-dismissed');
  });
}());
