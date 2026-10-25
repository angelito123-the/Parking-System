const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const now = Date.parse('2026-10-25T06:00:00Z');
const rows = () => [
  { id: 7101, title: 'Entry verification required', message: 'Please verify the vehicle at Gate 1.', severity: 'high', status: 'active', is_read: false, type: 'SUSPICIOUS_SCAN_BEHAVIOR', created_at: new Date(now - 7200000).toISOString() },
  { id: 7102, title: 'Review gate activity', message: 'The recorded scan needs review.', severity: 'medium', status: 'active', is_read: true, type: 'PENDING_ENTRY_APPROVAL', created_at: new Date(now - 86400000).toISOString() },
  { id: 7103, title: 'Spaces available again', message: 'Parking capacity has recovered.', severity: 'high', status: 'resolved', is_read: false, type: 'FULL_PARKING_ZONE', created_at: new Date(now - 172800000).toISOString() },
  { id: 7104, title: 'Capacity checked', message: '<img src=x onerror="window.unsafeText=true">', severity: 'low', status: 'resolved', is_read: true, type: 'LOW_SLOT_WARNING', created_at: new Date(now - 172800000).toISOString() }
];
const card = (page, id) => page.locator(`[data-notification-id="${id}"]`);
test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    window.headerAnimations = [];
    window.EventSource = class extends EventTarget { constructor() { super(); window.notificationStream = this; } close() {} };
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (frames, options) {
      if (this.id === 'notificationBackdrop' || this.closest('#notificationPanel')) window.headerAnimations.push({ frames, duration: options.duration });
      return animate.call(this, frames, options);
    };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
});
async function setup(page, role = 'admin', routePath = '/' + role) {
  const model = { rows: rows(), requests: [], failWrite: false, failRead: false, holdWrite: false, pending: null };
  await page.route('**/api/notifications**', route => {
    const request = route.request();
    const url = new URL(request.url());
    model.requests.push({ path: url.pathname, query: url.search, method: request.method(), body: request.postData(), contentType: request.headers()['content-type'] });
    if (request.method() === 'POST') {
      const respond = () => {
        if (model.failWrite) return route.fulfill({ status: 500, json: { ok: false } });
        if (url.pathname.endsWith('/read-all')) model.rows.forEach(row => { row.is_read = true; });
        else {
          const row = model.rows.find(row => url.pathname.includes('/' + row.id + '/'));
          if (url.pathname.endsWith('/read')) row.is_read = true;
          if (url.pathname.endsWith('/resolve')) row.status = 'resolved';
        }
        return route.fulfill({ json: { ok: true } });
      };
      if (model.holdWrite) model.pending = respond;
      else return respond();
      return;
    }
    if (url.pathname.endsWith('/summary')) return route.fulfill({ json: { ok: true, summary: { active_total: model.rows.filter(row => row.status === 'active').length, unread_total: model.rows.filter(row => !row.is_read).length } } });
    if (model.failRead) return route.fulfill({ status: 503, json: { ok: false } });
    let filtered = model.rows;
    if (url.searchParams.has('severity')) filtered = filtered.filter(row => row.severity === url.searchParams.get('severity'));
    if (url.searchParams.has('read_state')) filtered = filtered.filter(row => !row.is_read);
    return route.fulfill({ json: { ok: true, rows: filtered } });
  });
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', { headers: { origin: base }, maxRedirects: 0, form: { username: process.env[role.toUpperCase() + '_USERNAME'], password: process.env[role.toUpperCase() + '_PASSWORD'] } });
  expect(response.headers().location).toBe('/' + role);
  await page.goto(routePath);
  await page.clock.setFixedTime(new Date(now));
  await expect(page.locator('#notificationPanelMeta')).toHaveText('2 active alert(s)');
  return model;
}
async function open(page) {
  await page.locator('#notificationBell').click();
  await expect(page.locator('#notificationPanel')).toBeVisible();
  await expect(page.locator('#notificationCloseBtn')).toBeFocused();
  await expect(page.locator('#notificationPanel .notification-row')).toHaveCount(4);
}
async function settle(page) { await page.evaluate(() => Promise.allSettled(document.getAnimations().filter(animation => animation.effect.getComputedTiming().endTime < 3000).map(animation => animation.finished))); }
async function emit(page) { await page.evaluate(() => window.notificationStream.dispatchEvent(new MessageEvent('notifications-updated', { data: '{}' }))); }

test('low-power narrow screens keep focus after refresh errors and skip expensive effects', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 2 }));
  await page.setViewportSize({ width: 320, height: 740 });
  const model = await setup(page);
  await page.evaluate(() => window.scrollTo(0, 500));
  await open(page);
  await expect(page.locator('.top-nav')).toHaveCSS('position', 'sticky');
  await expect(page.locator('#notificationBackdrop')).toHaveCSS('backdrop-filter', 'none');
  await card(page, 7101).getByRole('button', { name: 'Mark read', exact: true }).focus();
  model.failRead = true;
  await emit(page);
  await expect(page.locator('#notificationPanelList')).toContainText('Notifications unavailable');
  await expect(page.locator('#notificationCloseBtn')).toBeFocused();
  await expect(page.locator('#notificationCaughtUp')).toBeHidden();
  expect(await page.evaluate(() => window.headerAnimations)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  model.failRead = false;
  model.rows.forEach(row => { row.status = 'resolved'; });
  await emit(page);
  await expect(page.locator('#notificationCaughtUp')).toBeVisible();
  await expect(page.locator('.notification-resolved')).not.toHaveAttribute('open', '');
});

test('notifications distinguish states, trap focus and remain readable across screen sizes', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await setup(page);
  await open(page);
  const panel = page.locator('#notificationPanel');
  await expect(page.locator('#notificationBackdrop')).toBeVisible();
  await expect(card(page, 7101)).toHaveClass(/is-unread/);
  await expect(card(page, 7101).getByRole('img', { name: 'High risk' })).toBeVisible();
  await expect(card(page, 7102)).toHaveClass(/is-read/);
  await expect(card(page, 7102).getByRole('img', { name: 'Medium risk' })).toBeVisible();
  await expect(card(page, 7101).locator('time')).toHaveText('2 hours ago');
  await expect(card(page, 7101).locator('time')).toHaveAttribute('title', /Created.*Oct 25, 2026.*Philippine/);
  await expect(card(page, 7102).locator('time')).toHaveText('Yesterday');
  await expect(card(page, 7103)).toBeHidden();
  await panel.locator('.notification-resolved summary').click();
  await expect(card(page, 7103)).toHaveClass(/is-resolved/);
  await expect(card(page, 7103).getByRole('img', { name: 'Resolved', exact: true })).toBeVisible();
  await expect(card(page, 7103).locator('.sev-high, .sev-medium, .notify-severity-dot')).toHaveCount(0);
  await expect(card(page, 7103).getByRole('button', { name: 'Mark read', exact: true })).toBeVisible();
  await expect(card(page, 7104).locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => window.unsafeText)).toBeUndefined();
  await page.locator('#notificationCloseBtn').focus();
  await page.keyboard.press('Shift+Tab');
  await expect(panel.locator('.notification-view-all')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#notificationCloseBtn')).toBeFocused();
  await page.locator('#accountMenuButton').focus();
  await expect(page.locator('#notificationCloseBtn')).toBeFocused();
  await settle(page);
  expect(await panel.evaluate(node => { const rect = node.getBoundingClientRect(); return rect.left >= 0 && rect.right <= innerWidth + 1 && rect.bottom <= innerHeight + 1; })).toBe(true);
  if (info.project.use.viewport.width <= 600) expect(await panel.evaluate(node => Math.abs(node.getBoundingClientRect().bottom - innerHeight))).toBeLessThan(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
  await page.screenshot({ path: info.outputPath('notifications.png') });
  await page.keyboard.press('Escape');
  await expect(panel).toBeHidden();
  await expect(page.locator('#notificationBell')).toBeFocused();
  const animations = await page.evaluate(() => window.headerAnimations);
  if (info.project.use.reducedMotion === 'reduce') expect(animations).toEqual([]);
  else {
    expect(animations.length).toBeGreaterThan(0);
    for (const animation of animations) {
      expect(animation.duration).toBeGreaterThanOrEqual(150);
      expect(animation.duration).toBeLessThanOrEqual(400);
      animation.frames.forEach(frame => expect(Object.keys(frame).every(key => ['opacity', 'transform'].includes(key))).toBe(true));
    }
  }
  expect(errors).toEqual([]);
});

test('read-all keeps the request contract and only confirms a successful response', async ({ page }) => {
  const model = await setup(page);
  await open(page);
  model.holdWrite = true;
  const button = page.locator('#notificationMarkAllBtn');
  await button.click();
  await expect(button).toBeDisabled();
  await expect(page.locator('#notificationFeedback')).toBeHidden();
  await expect.poll(() => Boolean(model.pending)).toBe(true);
  await model.pending();
  await expect(button).toBeEnabled();
  await expect(page.locator('#notificationFeedback')).toHaveText(/All notifications marked as read/);
  await expect(page.locator('#notificationPanel .is-unread')).toHaveCount(0);
  const writes = model.requests.filter(request => request.method === 'POST');
  expect(writes).toEqual([{ path: '/api/notifications/read-all', query: '', method: 'POST', body: null, contentType: 'application/json' }]);
  model.holdWrite = false;
  model.failWrite = true;
  await button.click();
  await expect(page.locator('#notificationFeedback')).toHaveClass(/is-error/);
  await expect(page.locator('#notificationFeedback')).toContainText('Couldn’t mark notifications as read');
  await page.getByRole('button', { name: 'Dismiss notification message' }).click();
  await expect(button).toBeFocused();
});

test('resolved history and filter empties use the existing summary and query rules', async ({ page }) => {
  const model = await setup(page);
  model.rows.forEach(row => { row.status = 'resolved'; });
  await emit(page);
  await open(page);
  await expect(page.locator('#notificationPanelMeta')).toHaveText('0 active alert(s)');
  await expect(page.locator('#notificationCaughtUp')).toContainText('All caught up');
  await expect(page.locator('#notificationCaughtUp')).toContainText('2 unread in history');
  await expect(page.locator('.notification-resolved')).not.toHaveAttribute('open', '');
  await page.locator('[data-notify-filter="unread"]').click();
  await expect(page.locator('#notificationPanel .notification-row')).toHaveCount(2);
  expect(model.requests.some(request => request.query === '?limit=20&read_state=unread')).toBe(true);
  await page.locator('[data-notify-filter="high"]').click();
  await expect(page.locator('#notificationPanel .notification-row')).toHaveCount(2);
  expect(model.requests.some(request => request.query === '?limit=20&severity=high')).toBe(true);
  model.rows = [{ ...model.rows[0], severity: 'critical', status: 'active' }];
  await emit(page);
  await expect(page.locator('#notificationPanelList')).toContainText('No matching alerts');
  await expect(page.locator('#notificationCaughtUp')).toBeHidden();
  await expect(page.locator('#notificationPanelMeta')).toHaveText('1 active alert(s)');
  await page.locator('[data-notify-filter="all"]').click();
  await expect(page.locator('#notificationPanel .notification-row')).toHaveCount(1);
  expect(model.requests.some(request => request.query === '?limit=20')).toBe(true);
});

test('guard panel and account menu remain mutually exclusive through rapid toggles and outside clicks', async ({ page }) => {
  await setup(page, 'guard');
  await open(page);
  await expect(page.locator('.notification-view-all')).toHaveCount(0);
  await page.locator('#accountMenuButton').click();
  await expect(page.locator('#accountMenu')).toBeVisible();
  await expect(page.locator('#notificationPanel')).toBeHidden();
  await page.locator('#notificationBell').click();
  await expect(page.locator('#accountMenu')).toBeHidden();
  await expect(page.locator('#notificationPanel')).toBeVisible();
  await page.locator('#notificationBell').evaluate(button => { button.click(); button.click(); button.click(); button.click(); });
  await expect(page.locator('#notificationPanel')).toBeVisible();
  await settle(page);
  await expect(page.locator('#notificationPanel')).not.toHaveClass(/is-closing/);
  await page.locator('#notificationBackdrop').click({ position: { x: 4, y: 100 } });
  await expect(page.locator('#notificationPanel')).toBeHidden();
  await expect(page.locator('#notificationBell')).toBeFocused();
  await expect(page.locator('body')).not.toHaveClass(/notifications-open/);
});

test('Students tabs fit their labels, slide the underline and retain keyboard and hash behavior', async ({ page }, info) => {
  await setup(page, 'admin', '/students#directory');
  await expect(page.locator('.top-nav-page-title h2')).toHaveText('Parking operations');
  await expect(page.locator('.top-nav-page-title')).not.toContainText('Students & Vehicles');
  const group = page.locator('.student-tabs-bar .flow-tabs');
  const register = page.locator('#registerTab');
  const directory = page.locator('#directoryTab');
  await expect(directory).toHaveAttribute('aria-selected', 'true');
  await expect(group).toHaveCSS('display', 'flex');
  const sizes = await group.evaluate(node => ({ group: node.getBoundingClientRect().width, buttons: [...node.querySelectorAll('button')].map(button => ({ width: button.getBoundingClientRect().width, scroll: button.scrollWidth, client: button.clientWidth, left: button.offsetLeft })) }));
  expect(sizes.buttons[0].width).toBeLessThan(190);
  expect(sizes.buttons[1].width).toBeLessThan(200);
  expect(sizes.buttons[0].left).toBeLessThan(5);
  expect(sizes.buttons.every(button => button.scroll <= button.client + 1)).toBe(true);
  await directory.focus();
  await page.keyboard.press('ArrowLeft');
  await expect(register).toHaveAttribute('aria-selected', 'true');
  await expect(page).toHaveURL(/#register$/);
  await expect(register).toBeFocused();
  await expect.poll(() => group.locator('.header-slide-marker').evaluate(node => Math.round(node.getBoundingClientRect().width))).toBe(Math.round((await register.boundingBox()).width));
  await page.keyboard.press('End');
  await expect(directory).toHaveAttribute('aria-selected', 'true');
  await expect(page).toHaveURL(/#directory$/);
  await settle(page);
  await page.screenshot({ path: info.outputPath('student-tabs.png') });
  if (info.project.name.includes('phone')) {
    await page.setViewportSize({ width: 320, height: 740 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  }
});
