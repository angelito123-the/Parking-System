/* Navigation presentation: no requests, route interception, or account-state changes. */
(() => {
  const sidebar = document.getElementById('mobileSidebar');
  if (!sidebar) return;
  const root = document.documentElement;
  const nav = sidebar.querySelector('.side-nav');
  const content = sidebar.querySelector('.sidebar-nav-content');
  const scroll = sidebar.querySelector('.sidebar-scroll');
  const highlight = document.getElementById('sidebarActiveHighlight');
  const active = nav.querySelector('[aria-current="page"]');
  const links = [...nav.querySelectorAll('a[href]')];
  const pin = document.getElementById('sidebarPin');
  const userButton = document.getElementById('sidebarUserButton');
  const userMenu = document.getElementById('sidebarUserMenu');
  const tooltip = document.getElementById('sidebarTooltip');
  const mobile = matchMedia('(max-width: 1080px), (hover: none), (pointer: coarse)');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const role = document.body.dataset.role;
  const key = `naap-sidebar-${role}`;
  const running = new Map();
  const read = (storage, name, fallback) => {
    try { return JSON.parse(window[storage].getItem(name)) ?? fallback; } catch (_) { return fallback; }
  };
  const write = (storage, name, value) => {
    try { window[storage].setItem(name, JSON.stringify(value)); } catch (_) { /* Storage is optional. */ }
  };
  const canAnimate = () => !reduced.matches && !document.hidden && !document.body.classList.contains('motion-lite');
  const isRail = () => !mobile.matches && root.classList.contains('sidebar-rail');

  // Cancel superseded effects so rapid toggles never hide a reopened menu or section.
  const motion = (node, frames, options = {}) => {
    running.get(node)?.cancel();
    if (!canAnimate() || !node.animate) return Promise.resolve();
    const animation = node.animate(frames, { duration: 240, easing: 'cubic-bezier(.2,.8,.2,1)', ...options });
    running.set(node, animation);
    return animation.finished.catch(() => {}).finally(() => { if (running.get(node) === animation) running.delete(node); });
  };
  const stopMotion = () => { if (!canAnimate()) running.forEach(animation => animation.finish()); };
  reduced.addEventListener('change', stopMotion);
  document.addEventListener('visibilitychange', stopMotion);

  const updateEdges = () => {
    scroll.classList.toggle('can-scroll-up', nav.scrollTop > 2);
    scroll.classList.toggle('can-scroll-down', nav.scrollHeight - nav.clientHeight - nav.scrollTop > 2);
  };
  const layoutTop = (node) => {
    let y = 0;
    for (let item = node; item && item !== content; item = item.offsetParent) y += item.offsetTop;
    return y;
  };
  const positionHighlight = (from) => {
    const visible = active && !active.closest('[hidden], [inert]');
    highlight.hidden = !visible;
    sidebar.classList.toggle('has-highlight', Boolean(visible));
    if (!visible) return;
    // Layout coordinates stay stable while links and sections are animating.
    const y = layoutTop(active);
    highlight.style.height = `${active.offsetHeight}px`;
    highlight.style.transform = `translateY(${y}px)`;
    if (from && from !== active && from.getClientRects().length) {
      const oldY = layoutTop(from);
      motion(highlight, [{ transform: `translateY(${oldY}px)`, opacity: .75 }, { transform: `translateY(${y}px)`, opacity: 1 }]);
    }
  };
  const revealActive = () => {
    if (!active || active.closest('[hidden]')) return;
    const box = active.getBoundingClientRect();
    const viewport = nav.getBoundingClientRect();
    if (box.top < viewport.top + 6) nav.scrollTop += box.top - viewport.top - 6;
    else if (box.bottom > viewport.bottom - 10) nav.scrollTop += box.bottom - viewport.bottom + 10;
    updateEdges();
  };
  const savedSections = read('localStorage', `${key}-sections`, {});
  const sectionPreferences = savedSections && typeof savedSections === 'object' && !Array.isArray(savedSections) ? savedSections : {};
  const sections = [...sidebar.querySelectorAll('.side-nav-group-label')].map(button => ({ button, panel: document.getElementById(button.getAttribute('aria-controls')) }));
  const setSection = ({ button, panel }, open, animate = false) => {
    button.setAttribute('aria-expanded', String(open));
    panel.inert = !open;
    if (open) {
      panel.hidden = false;
      if (animate) motion(panel, [{ opacity: 0, transform: 'translateY(-4px)' }, { opacity: 1, transform: 'translateY(0)' }]);
      else running.get(panel)?.cancel();
      positionHighlight();
      updateEdges();
    } else {
      const finish = () => {
        if (button.getAttribute('aria-expanded') === 'false') panel.hidden = true;
        positionHighlight();
        updateEdges();
      };
      if (animate) motion(panel, [{ opacity: 1, transform: 'translateY(0)' }, { opacity: 0, transform: 'translateY(-4px)' }], { duration: 180 }).then(finish);
      else { running.get(panel)?.cancel(); finish(); }
    }
  };
  sections.forEach(section => {
    // Always reveal the current page after navigation, even if its section was collapsed.
    if (section.panel.contains(active)) sectionPreferences[section.panel.id] = true;
    section.button.addEventListener('click', () => {
      const open = section.button.getAttribute('aria-expanded') !== 'true';
      sectionPreferences[section.panel.id] = open;
      write('localStorage', `${key}-sections`, sectionPreferences);
      setSection(section, open, true);
    });
  });

  let tooltipOwner;
  let tooltipTimer;
  const hideTooltip = () => {
    clearTimeout(tooltipTimer);
    tooltip.hidden = true;
    if (tooltipOwner) tooltipOwner.removeAttribute('aria-describedby');
    tooltipOwner = null;
  };
  const showTooltip = (node) => {
    if (!isRail()) return;
    hideTooltip();
    tooltipOwner = node;
    tooltip.textContent = node.dataset.sidebarLabel;
    tooltip.hidden = false;
    const box = node.getBoundingClientRect();
    tooltip.style.left = `${sidebar.getBoundingClientRect().right + 10}px`;
    tooltip.style.top = `${Math.max(8, Math.min(innerHeight - tooltip.offsetHeight - 8, box.top + (box.height - tooltip.offsetHeight) / 2))}px`;
    node.setAttribute('aria-describedby', tooltip.id);
  };
  sidebar.querySelectorAll('[data-sidebar-label]').forEach(node => {
    node.addEventListener('pointerenter', event => { if (event.pointerType !== 'touch') showTooltip(node); });
    node.addEventListener('pointerleave', () => { tooltipTimer = setTimeout(hideTooltip, 160); });
    node.addEventListener('focus', () => showTooltip(node));
    node.addEventListener('blur', hideTooltip);
  });
  tooltip.addEventListener('pointerenter', () => clearTimeout(tooltipTimer));
  tooltip.addEventListener('pointerleave', hideTooltip);

  let userOpen = false;
  const setUserMenu = (open, restoreFocus = false) => {
    userOpen = open;
    userButton.setAttribute('aria-expanded', String(open));
    userMenu.inert = !open;
    if (open) {
      hideTooltip();
      userMenu.hidden = false;
      motion(userMenu, [{ opacity: 0, transform: 'translateY(-3px) scale(.98)' }, { opacity: 1, transform: 'translateY(0) scale(1)' }]);
      userMenu.querySelector('a').focus({ preventScroll: true });
    } else {
      if (restoreFocus) userButton.focus({ preventScroll: true });
      if (!userMenu.hidden) motion(userMenu, [{ opacity: 1, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(.98)' }], { duration: 180 }).then(() => { if (!userOpen) userMenu.hidden = true; });
    }
  };
  userButton.addEventListener('click', () => setUserMenu(!userOpen));
  document.addEventListener('click', event => { if (userOpen && !event.target.closest('.sidebar-account')) setUserMenu(false); });
  document.addEventListener('focusin', event => { if (userOpen && !event.target.closest('.sidebar-account')) setUserMenu(false); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      hideTooltip();
      if (userOpen) { event.preventDefault(); event.stopPropagation(); setUserMenu(false, true); }
    }
    if (userOpen && userMenu.contains(event.target) && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      const items = [...userMenu.querySelectorAll('a')];
      const index = items.indexOf(document.activeElement);
      items[event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
    }
  }, true);

  let pinned = root.classList.contains('sidebar-pinned');
  let pointerInside = false;
  let openTimer;
  let closeTimer;
  const expand = () => {
    clearTimeout(openTimer);
    clearTimeout(closeTimer);
    if (mobile.matches) return;
    root.classList.remove('sidebar-rail');
    hideTooltip();
  };
  const scheduleCollapse = () => {
    clearTimeout(openTimer);
    clearTimeout(closeTimer);
    if (mobile.matches || pinned || pointerInside || sidebar.contains(document.activeElement)) return;
    closeTimer = setTimeout(() => {
      if (pinned || pointerInside || sidebar.contains(document.activeElement)) return;
      root.classList.add('sidebar-rail');
      hideTooltip();
    }, reduced.matches ? 0 : 200);
  };
  const updatePin = () => {
    root.classList.toggle('sidebar-pinned', pinned);
    pin.setAttribute('aria-pressed', String(pinned));
    pin.setAttribute('aria-label', pinned ? 'Unpin navigation' : 'Pin navigation open');
    pin.dataset.sidebarLabel = pin.getAttribute('aria-label');
    pin.querySelector('span').textContent = pinned ? 'Unpin navigation' : 'Pin navigation';
    pin.querySelector('i').className = `ph ${pinned ? 'ph-push-pin-slash' : 'ph-push-pin'}`;
  };
  pin.addEventListener('click', () => {
    pinned = !pinned;
    write('localStorage', 'naap-sidebar-pinned', pinned);
    updatePin();
    expand(); // Keyboard focus stays on the pin until the user leaves navigation.
    scheduleCollapse();
  });
  sidebar.addEventListener('pointerenter', event => {
    if (mobile.matches || event.pointerType === 'touch') return;
    pointerInside = true;
    clearTimeout(closeTimer);
    openTimer = setTimeout(expand, reduced.matches ? 0 : 80);
  });
  sidebar.addEventListener('pointerleave', event => {
    if (event.pointerType === 'touch') return;
    pointerInside = false;
    scheduleCollapse();
  });
  sidebar.addEventListener('focusin', expand);
  sidebar.addEventListener('focusout', () => queueMicrotask(scheduleCollapse));
  mobile.addEventListener('change', () => {
    clearTimeout(openTimer); clearTimeout(closeTimer);
    pointerInside = false;
    root.classList.toggle('sidebar-rail', !pinned && !sidebar.contains(document.activeElement));
    setUserMenu(false);
    hideTooltip();
  });
  window.addEventListener('storage', event => {
    if (event.key !== 'naap-sidebar-pinned') return;
    pinned = read('localStorage', 'naap-sidebar-pinned', false) === true;
    updatePin();
    if (pinned) expand(); else scheduleCollapse();
  });
  nav.addEventListener('scroll', () => { updateEdges(); hideTooltip(); }, { passive: true });
  new ResizeObserver(() => { positionHighlight(); updateEdges(); hideTooltip(); }).observe(content);
  new ResizeObserver(() => { positionHighlight(); updateEdges(); hideTooltip(); }).observe(nav);
  document.fonts?.ready.then(() => { positionHighlight(); revealActive(); });

  const previous = read('sessionStorage', `${key}-location`, null);
  updatePin();
  sections.forEach(section => setSection(section, sectionPreferences[section.panel.id] !== false));
  if (Number.isFinite(previous?.scroll)) nav.scrollTop = previous.scroll;
  revealActive();
  positionHighlight(!mobile.matches ? links.find(link => link.pathname === previous?.path) : null);
  const saveLocation = () => write('sessionStorage', `${key}-location`, { path: active?.pathname, scroll: nav.scrollTop });
  links.forEach(link => link.addEventListener('click', saveLocation));
  window.addEventListener('pagehide', saveLocation);

  let entranceShown = read('sessionStorage', `${key}-introduced`, false);
  const entrance = () => {
    if (entranceShown) return;
    entranceShown = true;
    write('sessionStorage', `${key}-introduced`, true);
    const viewport = nav.getBoundingClientRect();
    links.filter(link => !link.closest('[hidden]') && link.getBoundingClientRect().top < viewport.bottom).slice(0, 8).forEach((link, index) => {
      motion(link, [{ opacity: 0, transform: 'translateY(5px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 200, delay: index * 12, fill: 'backwards' });
    });
  };
  if (!mobile.matches) entrance();
  const connection = () => {
    sidebar.classList.toggle('is-offline', !navigator.onLine);
    document.getElementById('sidebarConnection').textContent = navigator.onLine ? 'Online' : 'Offline';
    userButton.setAttribute('aria-description', navigator.onLine ? 'Connection online' : 'Connection offline');
  };
  connection();
  window.addEventListener('online', connection);
  window.addEventListener('offline', connection);

  let unreadCount = 0;
  window.NaapSidebarUi = {
    drawerChanged(open) {
      setUserMenu(false);
      hideTooltip();
      if (open) { revealActive(); entrance(); }
    },
    summaryChanged(summary) {
      const count = Number(summary?.unread_total);
      const unread = Number.isFinite(count) ? Math.max(0, Math.floor(count)) : 0;
      if (unread === unreadCount) return;
      sidebar.querySelectorAll('[data-sidebar-unread]').forEach(badge => {
        badge.hidden = unread === 0;
        badge.textContent = unread > 99 ? '99+' : String(unread);
        // Only Alerts shares the bell's count. Live Updates tracks received movements separately.
        badge.parentElement.setAttribute('aria-description', unread ? `${unread} unread notifications` : 'No unread notifications');
        if (unread > 0 && unread !== unreadCount) motion(badge, [{ transform: 'scale(1)', opacity: 1 }, { transform: 'scale(1.12)', opacity: .8 }, { transform: 'scale(1)', opacity: 1 }], { duration: 280 });
      });
      unreadCount = unread;
    }
  };
})();
