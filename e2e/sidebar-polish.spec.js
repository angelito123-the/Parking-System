const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const adminLinks = ['/admin', '/students', '/stickers', '/visitor-passes', '/admin/slots', '/admin/updates', '/admin/alerts', '/admin/records', '/reports', '/admin/scanner-analytics', '/admin/data', '/admin/users'];
const guardLinks = ['/guard', '/scanner/auto', '/scanner', '/visitor-passes'];
const sidebar = page => page.locator('#mobileSidebar');
const settle = page => page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 3000).map(a => a.finished)));
test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    window.sidebarAnimations = [];
    window.EventSource = class extends EventTarget { constructor() { super(); window.notificationStream = this; } close() {} };
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (frames, options) {
      if (this.closest('#mobileSidebar')) window.sidebarAnimations.push({ frames, duration: options.duration });
      return animate.call(this, frames, options);
    };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
});
async function setup(page, role = 'admin') {
  const model = { unread: 3, requests: [] };
  await page.route('**/api/notifications**', route => {
    const url = new URL(route.request().url());
    model.requests.push(url.pathname);
    if (url.pathname.endsWith('/read-all')) { model.unread = 0; return route.fulfill({ json: { ok: true } }); }
    return route.fulfill({ json: url.pathname.endsWith('/summary') ? { ok: true, summary: { unread_total: model.unread, active_total: 0 } } : { ok: true, rows: [] } });
  });
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', { headers: { origin: base }, maxRedirects: 0, form: { username: process.env[role.toUpperCase() + '_USERNAME'], password: process.env[role.toUpperCase() + '_PASSWORD'] } });
  expect(response.headers().location).toBe('/' + role);
  await page.goto('/' + role);
  await expect(page.locator('#notificationPanelMeta')).toHaveText('0 active alert(s)');
  return model;
}
async function drawer(page) {
  if (await page.evaluate(() => matchMedia('(max-width: 1080px), (hover: none), (pointer: coarse)').matches)) {
    await page.locator('#mobileNavTrigger').click();
    await expect(page.locator('#mobileNavClose')).toBeFocused();
  } else await page.locator('.sidebar-brand').focus();
}
async function audit(page) {
  await settle(page);
  const result = await new AxeBuilder({ page }).include('#mobileSidebar').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
}

test('admin links, alert badges, pinned identity and lower navigation remain usable', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const model = await setup(page);
  await drawer(page);
  const nav = sidebar(page).locator('.side-nav');
  expect(await nav.locator('a').evaluateAll(nodes => nodes.map(n => n.getAttribute('href')))).toEqual(adminLinks);
  await expect(nav.locator('[aria-current="page"]')).toHaveAttribute('href', '/admin');
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveText(['3']);
  await expect(sidebar(page).locator('[data-sidebar-live]')).toBeHidden();
  await expect(nav.locator('a[href="/admin/updates"]')).toHaveAttribute('aria-description', 'No new updates');
  await audit(page);
  const identityTop = await sidebar(page).locator('.sidebar-identity').evaluate(n => n.getBoundingClientRect().top);
  await nav.evaluate(n => { n.scrollTop = n.scrollHeight; });
  await expect(nav.locator('a[href="/admin/users"]')).toBeInViewport();
  await expect(sidebar(page).locator('.sidebar-footer')).toBeInViewport();
  expect(await sidebar(page).locator('.sidebar-identity').evaluate(n => n.getBoundingClientRect().top)).toBe(identityTop);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({ path: info.outputPath('sidebar.png') });
  const administration = sidebar(page).getByRole('button', { name: 'Administration', exact: true });
  await administration.click();
  await expect(page.locator('#sidebarSection2')).toBeHidden();
  await administration.click();
  await expect(page.locator('#sidebarSection2')).toBeVisible();
  // Rapid toggles must settle on the last requested state.
  await administration.evaluate(n => { n.click(); n.click(); n.click(); n.click(); });
  await settle(page);
  await expect(page.locator('#sidebarSection2')).toBeVisible();
  if (await page.locator('body').evaluate(n => n.classList.contains('mobile-nav-open'))) await page.keyboard.press('Escape');
  await page.locator('#notificationBell').click();
  await page.locator('#notificationMarkAllBtn').click();
  await expect(sidebar(page).locator('[data-sidebar-unread]').first()).toBeHidden();
  expect(new Set(model.requests)).toEqual(new Set(['/api/notifications/summary', '/api/notifications', '/api/notifications/read-all']));
  expect(errors).toEqual([]);
});

test('guard account menu and mobile drawer preserve keyboard, touch and role access', async ({ page }, info) => {
  await setup(page, 'guard');
  await drawer(page);
  expect(await sidebar(page).locator('.side-nav a').evaluateAll(nodes => nodes.map(n => n.getAttribute('href')))).toEqual(guardLinks);
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveCount(0);
  await page.locator('#sidebarUserButton').click();
  const menu = page.locator('#sidebarUserMenu');
  await expect(menu.getByRole('menuitem', { name: 'Account security' })).toBeFocused();
  await expect(menu.locator('a').first()).toHaveAttribute('href', '/account/security');
  await page.keyboard.press('ArrowDown');
  await expect(menu.getByRole('menuitem', { name: 'Sign out' })).toBeFocused();
  await audit(page);
  await page.keyboard.press('Escape');
  await expect(page.locator('#sidebarUserButton')).toBeFocused();
  await expect(menu).toBeHidden();
  if (await page.locator('body').evaluate(n => n.classList.contains('mobile-nav-open'))) {
    await expect(sidebar(page)).toBeVisible();
    await page.locator('#mobileNavClose').focus();
    await page.keyboard.press('Shift+Tab');
    await expect(sidebar(page).locator('.sidebar-footer a')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#mobileNavClose')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.locator('#mobileNavTrigger')).toBeFocused();
    await expect(sidebar(page)).toHaveAttribute('inert', '');
    await drawer(page);
    // The drawer must survive viewport height changes caused by the phone browser chrome.
    await page.setViewportSize({ ...page.viewportSize(), height: page.viewportSize().height - 40 });
    await expect(sidebar(page)).toBeVisible();
    await page.locator('#mobileNavBackdrop').click({ position: { x: page.viewportSize().width - 5, y: 300 } });
    await expect(sidebar(page)).toBeHidden();
    await drawer(page);
    const swipe = async (endX, endY) => sidebar(page).evaluate((node, point) => {
      const start = new Touch({ identifier: 1, target: node, clientX: 220, clientY: 300 });
      node.dispatchEvent(new TouchEvent('touchstart', { touches: [start], bubbles: true }));
      const end = new Touch({ identifier: 1, target: node, clientX: point.x, clientY: point.y });
      node.dispatchEvent(new TouchEvent('touchend', { changedTouches: [end], bubbles: true, cancelable: true }));
    }, { x: endX, y: endY });
    await swipe(210, 100);
    await expect(sidebar(page)).toBeVisible();
    await swipe(90, 290);
    await expect(sidebar(page)).toBeHidden();
    await expect(page.locator('#mobileNavTrigger')).toBeFocused();
  }
  const animations = await page.evaluate(() => window.sidebarAnimations);
  if (info.project.use.reducedMotion === 'reduce') expect(animations).toEqual([]);
  for (const animation of animations) {
    expect(animation.duration).toBeGreaterThanOrEqual(150);
    expect(animation.duration).toBeLessThanOrEqual(300);
    animation.frames.forEach(frame => expect(Object.keys(frame).every(key => ['transform', 'opacity'].includes(key))).toBe(true));
  }
});

test('hover rail overlays content, pin persists, keyboard focus expands and icons stay aligned', async ({ page }, info) => {
  await page.setViewportSize({ width: 1280, height: 850 });
  test.skip(await page.evaluate(() => matchMedia('(hover: none), (pointer: coarse)').matches), 'Touch devices use the drawer at every width.');
  await setup(page);
  await page.mouse.move(900, 400);
  await expect(sidebar(page)).toHaveCSS('width', '72px');
  const contentBox = await page.locator('.content-area').boundingBox();
  const iconBox = await page.locator('.side-nav a.active .nav-link-icon').boundingBox();
  await sidebar(page).dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await sidebar(page).dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await page.waitForTimeout(120);
  await expect(sidebar(page)).toHaveCSS('width', '72px');
  await page.locator('.sidebar-brand').hover();
  await expect(sidebar(page)).toHaveCSS('width', '280px');
  expect(await page.locator('.content-area').boundingBox()).toEqual(contentBox);
  const expandedIcon = await page.locator('.side-nav a.active .nav-link-icon').boundingBox();
  expect(expandedIcon.x).toBe(iconBox.x);
  expect(expandedIcon.y).toBeCloseTo(iconBox.y, 0);
  await page.mouse.move(900, 400);
  await expect(sidebar(page)).toHaveCSS('width', '72px');
  const labelCount = await sidebar(page).locator('[data-sidebar-label]').count();
  expect(labelCount).toBeGreaterThan(adminLinks.length);
  const students = sidebar(page).locator('a[href="/students"]');
  await students.focus();
  await expect(sidebar(page)).toHaveCSS('width', '280px');
  await expect(students).toBeFocused();
  await page.mouse.move(900, 500);
  await page.waitForTimeout(260);
  await expect(students).toBeFocused();
  await expect(sidebar(page)).toHaveCSS('width', '280px');
  await audit(page);
  await page.locator('#sidebarUserButton').click();
  await expect(page.locator('#sidebarUserMenu')).toBeInViewport();
  await audit(page);
  await page.keyboard.press('Escape');
  await page.locator('#sidebarPin').click();
  await expect(page.locator('#sidebarPin')).toHaveAttribute('aria-pressed', 'true');
  expect((await page.locator('.content-area').boundingBox()).x).toBe(280);
  await page.mouse.move(900, 500);
  await page.reload();
  await expect(sidebar(page)).toHaveCSS('width', '280px');
  await expect(page.locator('#sidebarPin')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#sidebarPin').click();
  await expect(page.locator('#sidebarPin')).toBeFocused();
  await page.locator('#notificationBell').focus();
  await page.mouse.move(900, 500);
  await expect(sidebar(page)).toHaveCSS('width', '72px');
  expect((await page.locator('.content-area').boundingBox()).x).toBe(72);
  await students.focus();
  await students.click();
  await expect(page).toHaveURL(/\/students$/);
  await page.mouse.move(900, 500);
  await expect(sidebar(page)).toHaveCSS('width', '72px');
  await expect(sidebar(page).locator('[aria-current="page"]')).toHaveAttribute('href', '/students');
  await settle(page);
  expect(await page.evaluate(() => {
    const marker = document.getElementById('sidebarActiveHighlight').getBoundingClientRect();
    const link = document.querySelector('.side-nav [aria-current="page"]').getBoundingClientRect();
    return Math.abs(marker.top - link.top) < 2 && Math.abs(marker.height - link.height) < 2;
  })).toBe(true);
  await page.screenshot({ path: info.outputPath('rail.png') });
  await page.locator('.sidebar-brand').focus();
  await expect(sidebar(page)).toHaveCSS('width', '280px');
  await expect(page.locator('#sidebarSection1')).toBeVisible();
  await page.setViewportSize({ width: 768, height: 760 });
  await drawer(page);
  await expect(sidebar(page).locator('.nav-link-label').first()).toBeVisible();
  await expect(sidebar(page).locator('.sidebar-footer')).toBeInViewport();
});

test('Live Updates counts only new movements, survives reload and clears on viewing', async ({ page }) => {
  const model = await setup(page);
  const liveBadge = sidebar(page).locator('[data-sidebar-live]');
  const liveLink = sidebar(page).locator('a[href="/admin/updates"]');
  await expect(liveBadge).toBeHidden();
  const event = { reason: 'movement-recorded', movement_action: 'ENTRY', gate_id: 'Gate 1', server_time: new Date().toISOString(), qr_value: 'PRIVATE-QR-NOT-FOR-STORAGE' };
  const send = update => page.evaluate(data => window.notificationStream.dispatchEvent(new MessageEvent('notifications-updated', { data: JSON.stringify(data) })), update);
  await send(event);
  await expect(liveBadge).toHaveText('1');
  await expect(liveLink).toHaveAttribute('aria-label', 'Live Updates, 1 new update');
  await send(event);
  await send({ ...event, reason: 'notification-read' });
  await send({ ...event, reason: 'notification-resolved' });
  await send({ ...event, reason: 'pending-entry-created' });
  await send({ ...event, reason: 'offline-queue-synced', synced_count: 0 });
  await send({ ...event, reason: 'offline-queue-synced', synced_count: 2 });
  await expect(liveBadge).toHaveText('3');
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveText('3');
  const before = await page.evaluate(() => {
    window.liveBadgeMutations = 0;
    new MutationObserver(records => { window.liveBadgeMutations += records.length; }).observe(document.querySelector('[data-sidebar-live]'), { attributes: true, childList: true, subtree: true });
    return Object.keys(localStorage).filter(k => k.startsWith('naap-sidebar-live')).map(k => localStorage.getItem(k)).join('');
  });
  expect(before).not.toContain(event.qr_value);
  await page.evaluate(() => { for (let i = 0; i < 5; i++) window.NaapSidebarUi.summaryChanged({ unread_total: 3, active_total: 0 }); });
  expect(await page.evaluate(() => window.liveBadgeMutations)).toBe(0);
  await page.reload();
  await expect(liveBadge).toHaveText('3');
  await drawer(page);
  await expect(liveBadge).toBeVisible();
  await expect(liveLink).toHaveAccessibleName('Live Updates, 3 new updates');
  await audit(page);
  await liveLink.click();
  await expect(page).toHaveURL(/\/admin\/updates$/);
  await expect(liveBadge).toBeHidden();
  await expect(liveLink).toHaveAttribute('aria-label', 'Live Updates, No new updates');
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveText('3');
  await expect.poll(() => page.evaluate(() => Boolean(window.notificationStream))).toBe(true);
  await send(event); // Replayed events remain seen after opening Live Updates.
  await page.goto('/admin');
  await expect(liveBadge).toBeHidden();
  await expect.poll(() => page.evaluate(() => Boolean(window.notificationStream))).toBe(true);
  await send({ ...event, server_time: new Date().toISOString(), movement_action: 'EXIT' });
  await expect(liveBadge).toHaveText('1');
  if (!await page.evaluate(() => matchMedia('(max-width: 1080px), (hover: none), (pointer: coarse)').matches)) {
    await page.mouse.move(900, 500);
    await expect(sidebar(page)).toHaveCSS('width', '72px');
    const dot = await liveBadge.boundingBox();
    const icon = await liveLink.locator('.nav-link-icon').boundingBox();
    expect(dot.x).toBeGreaterThan(icon.x);
    expect(dot.x + dot.width).toBeLessThanOrEqual(icon.x + icon.width + 5);
    expect(dot.width).toBe(10);
  }
  expect(model.requests.every(url => url.startsWith('/api/notifications'))).toBe(true);
});

test('opening Live Updates in another tab clears the same account count without changing alerts', async ({ page }) => {
  await setup(page);
  const send = update => page.evaluate(data => window.notificationStream.dispatchEvent(new MessageEvent('notifications-updated', { data: JSON.stringify(data) })), update);
  await send({ reason: 'pending-entry-confirmed', pending_entry_id: 1001, server_time: new Date().toISOString() });
  await expect(sidebar(page).locator('[data-sidebar-live]')).toHaveText('1');
  const other = await page.context().newPage();
  await other.addInitScript(() => { window.EventSource = class extends EventTarget { close() {} }; });
  await other.route('https://**', route => route.abort());
  await other.goto('/admin/updates');
  await expect(sidebar(other).locator('[data-sidebar-live]')).toBeHidden();
  await expect(sidebar(page).locator('[data-sidebar-live]')).toHaveAttribute('hidden', '');
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveText('3');
  await other.close();
  await page.bringToFront();
  await send({ reason: 'visitor-movement-recorded', movement_action: 'EXIT', visitor_pass_id: 2001, server_time: new Date().toISOString() });
  await expect(sidebar(page).locator('[data-sidebar-live]')).toHaveText('1');
});

test('touch devices use the drawer even at desktop widths', async ({ page }, info) => {
  test.skip(!info.project.use.isMobile && !info.project.use.hasTouch, 'Touch-only scenario.');
  await page.setViewportSize({ width: 1280, height: 900 });
  await setup(page);
  await expect(page.locator('#mobileNavTrigger')).toBeVisible();
  await expect(sidebar(page)).toHaveAttribute('inert', '');
  expect((await page.locator('.content-area').boundingBox()).x).toBe(0);
  await drawer(page);
  await audit(page);
  await expect(page.locator('#sidebarPin')).toBeHidden();
  await page.keyboard.press('Escape');
  await expect(sidebar(page)).toBeHidden();
  await expect(page.locator('#mobileNavTrigger')).toBeFocused();
});

test('movement count continues in memory when storage becomes read-only', async ({ page }) => {
  await setup(page);
  await page.evaluate(() => {
    const key = `naap-sidebar-live-v1:admin:${document.getElementById('mobileSidebar').dataset.sidebarUser}`;
    localStorage.setItem(key, JSON.stringify({ count: 0, seenAt: 0, recent: [] }));
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = function (name, value) { if (name === key) throw new Error('Quota exceeded'); return set.call(this, name, value); };
  });
  for (let id = 1; id <= 2; id++) {
    await page.evaluate(pendingId => window.notificationStream.dispatchEvent(new MessageEvent('notifications-updated', { data: JSON.stringify({ reason: 'pending-entry-confirmed', pending_entry_id: pendingId, server_time: new Date().toISOString() }) })), id);
    await expect(sidebar(page).locator('[data-sidebar-live]')).toHaveText(String(id));
  }
});

test('low-power and storage-restricted browsers retain all navigation controls', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 2 });
    const get = Storage.prototype.getItem;
    const set = Storage.prototype.setItem;
    Storage.prototype.getItem = function (key) { if (key.startsWith('naap-sidebar')) throw new Error('Storage blocked'); return get.call(this, key); };
    Storage.prototype.setItem = function (key, value) { if (key.startsWith('naap-sidebar')) throw new Error('Storage blocked'); return set.call(this, key, value); };
  });
  await page.setViewportSize({ width: 320, height: 568 });
  await setup(page);
  await drawer(page);
  await expect(sidebar(page).locator('.sidebar-footer')).toBeInViewport();
  const nav = sidebar(page).locator('.side-nav');
  await nav.evaluate(n => { n.scrollTop = n.scrollHeight; });
  await expect(nav.locator('a[href="/admin/users"]')).toBeInViewport();
  await audit(page);
  expect(await page.evaluate(() => window.sidebarAnimations)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});
