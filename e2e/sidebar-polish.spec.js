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
  if (page.viewportSize().width <= 1080) {
    await page.locator('#mobileNavTrigger').click();
    await expect(page.locator('#mobileNavClose')).toBeFocused();
  }
}
async function audit(page) {
  await settle(page);
  const result = await new AxeBuilder({ page }).include('#mobileSidebar').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
}

test('admin links, shared badges, pinned identity and lower navigation remain usable', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const model = await setup(page);
  await drawer(page);
  const nav = sidebar(page).locator('.side-nav');
  expect(await nav.locator('a').evaluateAll(nodes => nodes.map(n => n.getAttribute('href')))).toEqual(adminLinks);
  await expect(nav.locator('[aria-current="page"]')).toHaveAttribute('href', '/admin');
  await expect(sidebar(page).locator('[data-sidebar-unread]')).toHaveText(['3', '3']);
  await expect(nav.locator('a[href="/admin/updates"]')).toHaveAttribute('aria-description', '3 unread notifications');
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
  if (page.viewportSize().width <= 1080) await page.keyboard.press('Escape');
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
  if (page.viewportSize().width <= 1080) {
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

test('desktop rail persists, tooltips work and sections never hide rail destinations', async ({ page }, info) => {
  await page.setViewportSize({ width: 1280, height: 650 });
  await setup(page);
  const daily = sidebar(page).getByRole('button', { name: 'Daily operations' });
  await daily.click();
  await expect(page.locator('#sidebarSection1')).toBeHidden();
  await page.locator('#sidebarCollapse').click();
  await expect(sidebar(page)).toHaveCSS('width', '88px');
  await expect(page.locator('#sidebarSection1')).toBeVisible();
  const students = sidebar(page).locator('a[href="/students"]');
  await students.focus();
  await expect(page.locator('#sidebarTooltip')).toHaveText('Students');
  await expect(page.locator('#sidebarTooltip')).toBeVisible();
  if (!info.project.use.isMobile) {
    await students.hover();
    await page.locator('#sidebarTooltip').hover();
    await expect(page.locator('#sidebarTooltip')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#sidebarTooltip')).toBeHidden();
  }
  await audit(page);
  await page.locator('#sidebarUserButton').click();
  await expect(page.locator('#sidebarUserMenu')).toBeInViewport();
  await audit(page);
  await page.keyboard.press('Escape');
  await students.click();
  await expect(page).toHaveURL(/\/students$/);
  await expect(sidebar(page)).toHaveCSS('width', '88px');
  await expect(sidebar(page).locator('[aria-current="page"]')).toHaveAttribute('href', '/students');
  await settle(page);
  expect(await page.evaluate(() => {
    const marker = document.getElementById('sidebarActiveHighlight').getBoundingClientRect();
    const link = document.querySelector('.side-nav [aria-current="page"]').getBoundingClientRect();
    return Math.abs(marker.top - link.top) < 2 && Math.abs(marker.height - link.height) < 2;
  })).toBe(true);
  await page.screenshot({ path: info.outputPath('rail.png') });
  await page.locator('#sidebarCollapse').click();
  await expect(sidebar(page)).toHaveCSS('width', '272px');
  await expect(page.locator('#sidebarSection1')).toBeVisible();
  await page.setViewportSize({ width: 768, height: 760 });
  await drawer(page);
  await expect(sidebar(page).locator('.nav-link-label').first()).toBeVisible();
  await expect(sidebar(page).locator('.sidebar-footer')).toBeInViewport();
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
