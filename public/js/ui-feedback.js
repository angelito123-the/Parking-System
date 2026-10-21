/* Optional feedback complements inline messages without changing form submissions. */
(function () {
  'use strict';
  let stack;

  function show(message, options = {}) {
    if (!String(message || '').trim()) return;
    const tone = ['success', 'error', 'info'].includes(options.tone) ? options.tone : 'info';
    if (!stack) {
      stack = document.createElement('div');
      stack.className = 'ui-toast-stack';
      stack.setAttribute('aria-label', 'Status messages');
      stack.setAttribute('role', 'region');
      document.body.append(stack);
    }
    const returnFocus = document.activeElement;
    const toast = document.createElement('div');
    toast.className = `ui-toast ui-toast-${tone}`;
    const copy = document.createElement('p');
    copy.setAttribute('role', tone === 'error' ? 'alert' : 'status');
    const label = document.createElement('strong');
    label.textContent = { success: 'Success', error: 'Unable to update', info: 'Notice' }[tone];
    const detail = document.createElement('span');
    detail.textContent = String(message);
    copy.append(label, detail);
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'ui-toast-close';
    close.setAttribute('aria-label', 'Dismiss message');
    close.textContent = '×';
    let timer;
    function dismiss() {
      clearTimeout(timer);
      if (toast.contains(document.activeElement) && returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
      toast.remove();
    }
    function schedule() {
      clearTimeout(timer);
      if (tone !== 'error' && !toast.matches(':hover') && !toast.contains(document.activeElement)) timer = setTimeout(dismiss, 6000);
    }
    close.addEventListener('click', dismiss);
    toast.addEventListener('mouseenter', () => clearTimeout(timer));
    toast.addEventListener('focusin', () => clearTimeout(timer));
    toast.addEventListener('mouseleave', schedule);
    toast.addEventListener('focusout', () => setTimeout(schedule, 0));
    toast.append(copy, close);
    stack.append(toast);
    // Keep repeated refreshes from covering the screen; inline feedback remains available.
    if (stack.children.length > 3) {
      const oldest = [...stack.children].find(item => item !== toast && !item.contains(document.activeElement));
      oldest?.remove();
    }
    schedule();
  }

  window.NaapFeedback = { show };
  document.querySelectorAll('.flash-success:not([id]), .flash-error:not([id])').forEach(flash => {
    if (flash.getClientRects().length) show(flash.textContent.trim(), { tone: flash.classList.contains('flash-error') ? 'error' : 'success' });
  });
  // Keyboard users can scroll wide tables independently of the rest of the page.
  document.querySelectorAll('.table-wrap').forEach(wrapper => {
    if (!wrapper.hasAttribute('tabindex')) wrapper.tabIndex = 0;
    if (!wrapper.hasAttribute('role')) wrapper.setAttribute('role', 'region');
    if (!wrapper.hasAttribute('aria-label') && !wrapper.hasAttribute('aria-labelledby')) {
      const title = wrapper.closest('section, .panel')?.querySelector('h2, h3')?.textContent.trim();
      wrapper.setAttribute('aria-label', title ? `${title} table` : 'Scrollable records table');
    }
  });
}());
