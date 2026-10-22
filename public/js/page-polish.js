/* Small presentation helpers for server-rendered pages. No data requests here. */
(function () {
  'use strict';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const running = new Set();
  const reveals = new WeakMap();
  const canAnimate = () => !reduced.matches && !document.hidden && !document.body.classList.contains('motion-lite');
  function motion(node, frames, done) {
    if (!node?.animate || !canAnimate()) { done?.(); return; }
    const animation = node.animate(frames, { duration: 240, easing: 'cubic-bezier(.2,.8,.2,1)' });
    running.add(animation);
    animation.finished.catch(() => {}).finally(() => { running.delete(animation); done?.(); });
    return animation;
  }
  function finishMotion() { running.forEach(animation => animation.finish()); }
  reduced.addEventListener('change', finishMotion);
  document.addEventListener('visibilitychange', () => { if (document.hidden) finishMotion(); });

  // Closing content becomes inert immediately; rapid toggles cancel the old close.
  function reveal(node, open, options = {}) {
    if (!node) return;
    const startHeight = node.hidden ? 0 : node.getBoundingClientRect().height;
    const startOpacity = node.hidden ? 0 : Number(getComputedStyle(node).opacity);
    const overflow = reveals.get(node)?.overflow ?? node.style.overflow;
    reveals.get(node)?.cancel();
    const state = { overflow };
    reveals.set(node, state);
    node.inert = !open;
    if (open) node.hidden = false;
    // Height mode is opt-in for directory disclosures; other pages keep their motion.
    const frames = options.height ? [
      { height: `${startHeight}px`, opacity: startOpacity },
      { height: `${open ? node.getBoundingClientRect().height : 0}px`, opacity: open ? 1 : 0 }
    ] : open
      ? [{ opacity: 0, transform: 'translateY(-6px)' }, { opacity: 1, transform: 'none' }]
      : [{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'translateY(-6px)' }];
    if (options.height) node.style.overflow = 'hidden';
    const animation = motion(node, frames, () => {
      if (reveals.get(node) !== state) return;
      node.hidden = !open;
      node.inert = false;
      if (options.height) node.style.overflow = overflow;
      reveals.delete(node);
    });
    state.cancel = () => animation?.cancel();
  }

  let selectedCode;
  let ringCode;
  const previousStates = new Map();
  let chipsEntered = false;
  function parkingRendered() {
    const map = document.getElementById('parkingSlotsList');
    if (!map) return;
    map.querySelectorAll('[data-slot-code]').forEach(tile => {
      const code = tile.dataset.slotCode;
      if (tile.getAttribute('aria-pressed') === 'true' && ringCode !== code) {
        ringCode = code;
        if (canAnimate()) tile.classList.add('selection-arrive');
      }
      const state = tile.dataset.parkingVisualState || tile.dataset.parkingState;
      const previous = previousStates.get(code);
      previousStates.set(code, state);
      if (previous && previous !== state && canAnimate()) {
        const overlay = document.createElement('span');
        overlay.className = 'parking-state-change';
        overlay.dataset.previousState = previous;
        overlay.setAttribute('aria-hidden', 'true');
        tile.append(overlay);
        motion(overlay, [{ opacity: .9, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(1.025)' }], () => overlay.remove());
      }
    });
    if (!chipsEntered) {
      document.querySelectorAll('#availableSlotsStrip button').forEach((chip, index) => {
        if (index < 6) window.NaapMotion?.animate(chip, 'enter', index * 20);
      });
      chipsEntered = true;
    }
  }
  function inspectorUpdated(code) {
    if (selectedCode === code) return;
    selectedCode = code;
    window.NaapMotion?.animate(document.getElementById('slotInspectorTitle'));
    document.querySelectorAll('#slotInspectorDetails > div').forEach((row, index) => window.NaapMotion?.animate(row, 'enter', index * 20));
  }
  function viewChanged(node) {
    window.NaapMotion?.animate(node, 'fade');
    if (node?.id === 'directoryPanel') {
      node.querySelectorAll('.student-card').forEach((row, index) => { if (index < 6) window.NaapMotion?.animate(row, 'enter', index * 20); });
    }
  }
  let viewTransition;
  function switchView(update, getPanel) {
    viewTransition?.skipTransition();
    if (!canAnimate() || !document.startViewTransition) {
      update();
      viewChanged(getPanel());
      return;
    }
    // Browser snapshots cross-fade without copying forms or changing their values.
    const transition = document.startViewTransition(update);
    viewTransition = transition;
    transition.finished.catch(() => {}).finally(() => {
      if (viewTransition === transition) viewTransition = null;
    });
  }
  reduced.addEventListener('change', () => viewTransition?.skipTransition());
  window.NaapPages = { reveal, parkingRendered, inspectorUpdated, viewChanged, switchView };
  parkingRendered();
  inspectorUpdated(document.getElementById('slotInspectorTitle')?.textContent.trim());
  if (document.getElementById('directoryPanel')?.getClientRects().length) viewChanged(document.getElementById('directoryPanel'));

  // Native navigation remains in charge; skeletons only appear after a real submit.
  const directory = document.getElementById('studentDirectory');
  let skeleton;
  if (directory) {
    skeleton = document.createElement('div');
    skeleton.className = 'directory-loading';
    skeleton.hidden = true;
    skeleton.setAttribute('aria-hidden', 'true');
    skeleton.innerHTML = '<span></span><span></span><span></span>';
    directory.before(skeleton);
    document.addEventListener('submit', event => {
      if (event.defaultPrevented || !event.target.matches('.directory-filter-form, .directory-page-size-form')) return;
      directory.hidden = true;
      skeleton.hidden = false;
      directory.setAttribute('aria-busy', 'true');
    });
    window.addEventListener('pageshow', () => { directory.hidden = false; skeleton.hidden = true; directory.removeAttribute('aria-busy'); });

    // Normalize only user edits; existing stored plate values are not rewritten.
    directory.querySelectorAll('input[name="plate_number"]').forEach(field => {
      const uppercase = event => {
        if (event.isComposing) return;
        const value = field.value;
        const normalized = value.toUpperCase();
        if (value === normalized) return;
        const start = field.selectionStart;
        const end = field.selectionEnd;
        const direction = field.selectionDirection;
        field.value = normalized;
        if (start !== null) field.setSelectionRange(value.slice(0, start).toUpperCase().length, value.slice(0, end).toUpperCase().length, direction);
      };
      field.addEventListener('input', uppercase);
      field.addEventListener('compositionend', uppercase);
    });

    // Present the browser's existing validity errors without adding validation rules.
    directory.querySelectorAll('.vehicle-edit-form form').forEach(form => {
      form.querySelectorAll('input').forEach(field => {
        const note = document.createElement('small');
        note.id = field.id + '-error';
        note.className = 'form-field-error vehicle-field-error';
        note.hidden = true;
        note.setAttribute('aria-live', 'polite');
        (field.closest('.vehicle-input-wrap') || field).after(note);
        const descriptions = (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
        field.setAttribute('aria-describedby', [...new Set([...descriptions, note.id])].join(' '));
        let touched = false;
        const update = () => {
          const invalid = touched && !field.validity.valid;
          note.hidden = !invalid;
          note.textContent = invalid ? field.validationMessage : '';
          if (invalid) field.setAttribute('aria-invalid', 'true');
          else field.removeAttribute('aria-invalid');
        };
        field.addEventListener('blur', () => { touched = true; update(); });
        field.addEventListener('input', update);
        field.addEventListener('invalid', event => {
          event.preventDefault();
          touched = true;
          update();
          if (field === form.querySelector('input:invalid')) field.focus();
        });
        form.addEventListener('reset', () => { touched = false; setTimeout(update, 0); });
      });
    });
  }

  // Only confirm fields the user has touched; do not change validation rules.
  document.querySelectorAll('#regForm input, #regForm select').forEach(field => {
    let touched = false;
    const note = document.createElement('small');
    note.className = 'form-field-success';
    note.textContent = '✓ Looks good';
    note.hidden = true;
    field.parentElement.append(note);
    const update = () => {
      const valid = touched && !field.disabled && Boolean(field.value.trim()) && field.validity.valid && field.getAttribute('aria-invalid') !== 'true';
      note.hidden = !valid;
      field.dataset.fieldValid = String(valid);
    };
    field.addEventListener('blur', () => { touched = true; update(); });
    field.addEventListener('input', update);
    field.addEventListener('change', update);
    field.form?.addEventListener('reset', () => { touched = false; setTimeout(update, 0); });
  });

  // Escape and arrow keys complement the existing click-driven action menus.
  document.addEventListener('keydown', event => {
    const menu = event.target instanceof Element ? event.target.closest('.action-menu.is-open') : null;
    if (!menu) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      menu.classList.remove('is-open');
      const trigger = menu.querySelector('[data-action-menu-trigger]');
      trigger?.setAttribute('aria-expanded', 'false');
      trigger?.focus();
    } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      const items = [...menu.querySelectorAll('[role="menuitem"]')].filter(item => item.getClientRects().length && !item.disabled);
      if (!items.length) return;
      event.preventDefault();
      const current = items.indexOf(document.activeElement);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowUp' ? -1 : 1) + items.length) % items.length;
      items[next].focus();
    }
  });

  // A native dialog supplies focus trapping and Escape without replacing QR URLs.
  const qrLinks = document.querySelectorAll('[data-qr-preview]');
  if (!qrLinks.length || typeof HTMLDialogElement === 'undefined') return;
  const dialog = document.createElement('dialog');
  dialog.className = 'qr-preview-dialog';
  dialog.setAttribute('aria-labelledby', 'qrPreviewTitle');
  dialog.innerHTML = '<div class="qr-preview-heading"><h2 id="qrPreviewTitle">Vehicle QR code</h2><button type="button" class="btn-ghost" aria-label="Close QR preview">×</button></div><p class="helper-text" id="qrPreviewCode"></p><p role="status" id="qrPreviewStatus">Loading QR code…</p><img class="qr-preview-image" alt="Vehicle verification QR code" hidden><a class="link-btn btn-secondary" target="_blank" rel="noopener">Open original QR</a>';
  document.body.append(dialog);
  const image = dialog.querySelector('img');
  const status = dialog.querySelector('[role="status"]');
  let opener;
  let request = 0;
  qrLinks.forEach(link => link.addEventListener('click', event => {
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button) return;
    event.preventDefault();
    opener = link;
    const current = ++request;
    image.hidden = true;
    status.hidden = false;
    status.textContent = 'Loading QR code…';
    dialog.querySelector('#qrPreviewCode').textContent = link.dataset.qrCode || '';
    dialog.querySelector('a').href = link.href;
    // Replace the image node so a late event from a previous QR cannot reveal it.
    const preview = image.cloneNode(false);
    preview.removeAttribute('src');
    const previous = dialog.querySelector('img');
    previous.replaceWith(preview);
    preview.onload = () => { if (current !== request) return; preview.hidden = false; status.hidden = true; };
    preview.onerror = () => { if (current !== request) return; status.textContent = 'Unable to load the QR preview. Close and try again, or open the original QR.'; };
    preview.src = link.href;
    dialog.showModal();
  }));
  dialog.querySelector('button').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', event => {
    const rect = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
  });
  dialog.addEventListener('close', () => { request++; opener?.focus({ preventScroll: true }); });
}());
