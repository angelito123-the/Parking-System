(() => {
  const dialog = document.getElementById('confirmDialog');
  if (!dialog) return;
  const card = dialog.querySelector('.confirm-dialog-card');
  const title = document.getElementById('confirmDialogTitle');
  const message = document.getElementById('confirmDialogMessage');
  const confirmButton = document.getElementById('confirmDialogSubmit');
  const cancelButton = card.querySelector('[data-confirm-close]');
  const noteField = document.getElementById('confirmDialogNoteField');
  const noteInput = document.getElementById('confirmDialogNote');
  const appShell = document.querySelector('.app-shell');
  const approvedForms = new WeakSet();
  let pending = null;
  let wasInert = false;

  function close(restoreFocus = true) {
    const previous = pending;
    pending = null;
    dialog.hidden = true;
    document.body.classList.remove('confirm-dialog-open');
    if (appShell) appShell.inert = wasInert;
    if (restoreFocus) previous?.returnFocus?.focus({ preventScroll: true });
  }

  function open(form, trigger, data, submitter = null) {
    if (!(form instanceof HTMLFormElement) || pending) return;
    const menu = trigger?.closest('.action-menu');
    const returnFocus = menu?.querySelector('[data-action-menu-trigger]') || trigger;
    document.querySelectorAll('.action-menu.is-open').forEach(menu => {
      menu.classList.remove('is-open');
      menu.querySelector('[data-action-menu-trigger]')?.setAttribute('aria-expanded', 'false');
    });
    pending = { form, submitter, returnFocus };
    title.textContent = data.confirmTitle || 'Confirm action?';
    message.textContent = data.confirmMessage || 'This action cannot be undone.';
    confirmButton.textContent = data.confirmLabel || 'Confirm';
    const primary = data.confirmTone === 'primary';
    confirmButton.className = primary ? 'btn-save-sm' : 'btn-confirm-danger';
    dialog.dataset.tone = primary ? 'primary' : 'danger';
    noteField.hidden = !data.confirmNote;
    noteInput.value = form.elements.namedItem('approval_note')?.value || '';
    dialog.hidden = false;
    document.body.classList.add('confirm-dialog-open');
    wasInert = Boolean(appShell?.inert);
    cancelButton.focus({ preventScroll: true });
    if (appShell) appShell.inert = true;
  }

  document.addEventListener('click', event => {
    const trigger = event.target instanceof Element ? event.target.closest('[data-destructive-trigger]') : null;
    if (!trigger) return;
    event.preventDefault();
    open(document.getElementById(trigger.dataset.formId || ''), trigger, trigger.dataset);
  });

  // Capture before the shared navigation loader. A cancelled confirmation must
  // neither submit the form nor leave the screen in a loading state.
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute('data-confirm-form') || approvedForms.has(form)) return;
    event.preventDefault();
    open(form, event.submitter || form.querySelector('button'), form.dataset, event.submitter);
  }, true);

  dialog.querySelectorAll('[data-confirm-close]').forEach(control => control.addEventListener('click', () => close()));
  confirmButton.addEventListener('click', () => {
    if (!pending) return;
    const { form, submitter } = pending;
    if (!noteField.hidden) {
      const input = form.elements.namedItem('approval_note');
      if (input) input.value = noteInput.value.trim();
    }
    close(false);
    approvedForms.add(form);
    try { form.requestSubmit(submitter || undefined); }
    finally { approvedForms.delete(form); }
  });

  document.addEventListener('keydown', event => {
    if (dialog.hidden) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    if (event.key !== 'Tab') return;
    const controls = [...card.querySelectorAll('button:not([disabled]), textarea:not([disabled])')].filter(control => control.getClientRects().length);
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
})();
