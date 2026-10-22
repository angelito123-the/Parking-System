const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const qr = 'abcdefghij-0123456789-0123456789-abcdef';
const fixtures = () => [
  { id: 9801, type: 'SUSPICIOUS_SCAN_BEHAVIOR', title: 'Repeated scan requires verification', message: 'Review the recent gate activity before allowing entry.', severity: 'high', status: 'active', is_read: false, related_gate_id: 'Gate 1', related_zone_id: 'Basketball Area Parking', source: 'GATE_SCANNER', related_qr_id: qr, created_at: '2026-10-23T01:00:00Z' },
  { id: 9802, type: 'PENDING_ENTRY_APPROVAL', title: 'Entry approval requested', message: 'The guard has requested a manual verification.', severity: 'medium', status: 'active', is_read: true, related_gate_id: 'Gate 2', source: 'MANUAL_ENTRY', created_at: '2026-10-23T00:00:00Z' },
  { id: 9803, type: 'FULL_PARKING_ZONE', title: 'Parking capacity restored', message: 'A parking space has been released.', severity: 'low', status: 'resolved', is_read: false, related_zone_id: 'Hangar Parking Zone', source: 'PARKING_MONITOR', created_at: '2026-10-22T23:00:00Z', resolved_at: '2026-10-23T02:00:00Z' },
  { id: 9804, type: 'INVALID_QR_ATTEMPT', title: 'Invalid QR scan', message: 'Verify the vehicle credential.', severity: 'critical', status: 'active', is_read: false, created_at: '2026-10-22T22:00:00Z' },
  { id: 9805, type: 'LOW_SLOT_WARNING', title: 'Low capacity warning cleared', message: 'Spaces are available.', severity: 'low', status: 'resolved', is_read: true, created_at: '2026-10-22T21:00:00Z' }
];
const card = (page, id) => page.locator('#alertsList .alerts-log-row:not(.alert-exiting)[data-alert-key="' + id + '"]');
const cards = page => page.locator('#alertsList .alerts-log-row:not(.alert-exiting)');

async function installMocks(page) {
  const model = { rows: fixtures(), requests: [], failWrite: false, failRead: false, hold: false, pending: null };
  await page.route('**/api/notifications**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    model.requests.push({ method: request.method(), path: url.pathname, query: url.search, body: request.postData(), contentType: request.headers()['content-type'] });
    if (request.method() === 'POST') {
      if (model.failWrite) return route.fulfill({ status: 500, json: { ok: false } });
      if (url.pathname.endsWith('/read-all')) model.rows.forEach(row => { row.is_read = true; });
      else {
        const row = model.rows.find(row => url.pathname.includes('/' + row.id + '/'));
        if (url.pathname.endsWith('/read')) row.is_read = true;
        if (url.pathname.endsWith('/resolve')) { row.status = 'resolved'; row.resolved_at = '2026-10-23T03:00:00Z'; }
      }
      return route.fulfill({ json: { ok: true } });
    }
    if (url.pathname.endsWith('/summary')) return route.fulfill({ json: { ok: true, summary: { unread_total: model.rows.filter(row => !row.is_read).length, active_total: model.rows.filter(row => row.status === 'active').length }, operational: {} } });
    if (url.pathname !== '/api/notifications') return route.fulfill({ json: { ok: true } });
    const respond = () => {
      if (model.failRead) return route.fulfill({ status: 503, json: { ok: false, message: 'Temporarily unavailable' } });
      let rows = model.rows;
      for (const field of ['status', 'type', 'severity']) if (url.searchParams.has(field)) rows = rows.filter(row => row[field] === url.searchParams.get(field));
      const read = url.searchParams.get('read_state');
      if (read) rows = rows.filter(row => row.is_read === (read === 'read'));
      return route.fulfill({ json: { ok: true, rows, total: rows.length } });
    };
    if (model.hold) model.pending = respond;
    else await respond();
  });
  return model;
}

async function showAll(page) {
  await page.goto('/admin/alerts');
  await expect(page.locator('#alertsFilterChips')).toContainText('Initial snapshot: all statuses');
  await page.locator('#alertsFilterStatus').selectOption('all');
  await page.locator('#alertsFilterForm button[type="submit"]').click();
  await expect(cards(page)).toHaveCount(5);
}

test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    // No background SSE calls: each test explicitly triggers the existing refresh event.
    window.EventSource = class { addEventListener() {} close() {} };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', { headers: { origin: base }, maxRedirects: 0, form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD } });
  expect(response.headers().location).toBe('/admin');
});

test('severity, readable metadata and resolved priority are consistent and accessible', async ({ page, context }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await installMocks(page);
  await showAll(page);
  await expect(page.locator('#alertsCountUnread')).toHaveText('2');
  await expect(page.locator('#alertsCountHigh')).toHaveText('2');
  await expect(page.locator('#alertsCountResolved')).toHaveText('2');
  await expect(card(page, 9801).locator('.alert-type-name')).toHaveText('Suspicious scan behavior');
  await expect(card(page, 9801).locator('.alert-new')).toHaveText('NEW');
  await expect(card(page, 9802).locator('.alert-read')).toHaveText('Read');
  await expect(card(page, 9802).locator('.alerts-read-btn')).toHaveCount(0);
  await expect(card(page, 9803).locator('.alert-new, .alerts-read-btn, .alerts-resolve-btn')).toHaveCount(0);
  await expect(card(page, 9803).locator('.alert-resolved-time')).toContainText('10:00:00 AM');
  await expect(card(page, 9805).locator('.alert-resolved-time')).toContainText('time not recorded');
  await expect(card(page, 9804).locator('.alert-severity')).toHaveText('Critical');
  const accents = [];
  for (const id of [9801, 9802, 9803]) {
    accents.push(await card(page, id).evaluate(el => getComputedStyle(el).borderLeftColor));
    const glyph = await card(page, id).locator('.alert-type-icon i').evaluate(el => getComputedStyle(el, '::before').content);
    expect(glyph).not.toBe('none');
  }
  expect(new Set(accents).size).toBe(3);
  const copy = card(page, 9801).locator('.alert-qr-copy');
  await copy.focus();
  await expect(card(page, 9801).getByRole('tooltip')).toHaveText(qr);
  await page.keyboard.press('Escape');
  await expect(card(page, 9801).getByRole('tooltip')).toBeHidden();
  await copy.click();
  await expect(copy).toHaveAttribute('aria-label', 'QR identifier copied');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(qr);
  await expect(page.locator('.ui-toast-success')).toContainText('QR identifier copied');
  await page.locator('#alertsLogTitle').focus();
  await page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 2000).map(a => a.finished)));
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.locator('#alertsLogTitle').scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath('alerts-polished.png') });
  expect(errors).toEqual([]);
});

test('read, resolve and bulk feedback reflect server responses without changing request contracts', async ({ page }) => {
  const model = await installMocks(page);
  await showAll(page);
  model.failWrite = true;
  await card(page, 9801).getByRole('button', { name: 'Mark as read' }).click();
  await expect(page.locator('.ui-toast-error')).toContainText('could not be updated');
  await expect(card(page, 9801).locator('.alert-new')).toBeVisible();
  await expect(page.locator('.ui-toast-success')).toHaveCount(0);
  model.failWrite = false;
  await card(page, 9801).getByRole('button', { name: 'Mark as read' }).click();
  await expect(card(page, 9801).locator('.alert-read')).toHaveText('Read');
  await expect(card(page, 9801).locator('.alerts-read-btn')).toHaveCount(0);
  await expect(page.locator('.ui-toast-success')).toContainText('Alert marked as read');
  await card(page, 9802).getByRole('button', { name: 'Resolve', exact: true }).click();
  await expect(card(page, 9802).locator('.alert-resolved')).toHaveText('Resolved');
  await expect(card(page, 9802).locator('.alerts-log-actions button')).toHaveCount(0);
  await page.locator('#alertsMarkAllReadBtn').click();
  await expect(page.locator('#alertsMarkAllReadBtn')).toBeEnabled();
  await expect(page.locator('#alertsCountUnread')).toHaveText('0');
  await expect(page.locator('.ui-toast-success').last()).toContainText('All alerts marked as read');
  expect(model.requests.filter(r => r.method === 'POST').map(r => ({ ...r, contentType: undefined }))).toEqual([
    { method: 'POST', path: '/api/notifications/9801/read', query: '', body: null, contentType: undefined },
    { method: 'POST', path: '/api/notifications/9801/read', query: '', body: null, contentType: undefined },
    { method: 'POST', path: '/api/notifications/9802/resolve', query: '', body: null, contentType: undefined },
    { method: 'POST', path: '/api/notifications/read-all', query: '', body: null, contentType: undefined }
  ]);
  expect(model.requests.filter(r => r.method === 'POST').every(r => r.contentType === 'application/json')).toBe(true);
});

test('filters collapse, removable chips and unread removal preserve keyboard navigation', async ({ page }) => {
  await installMocks(page);
  await showAll(page);
  const toggle = page.locator('#alertsFilterToggle');
  await toggle.click();
  await toggle.click();
  await expect(page.locator('#alertsFilterForm')).toBeVisible();
  await toggle.click();
  await expect(page.locator('#alertsFilterForm')).toBeHidden();
  await toggle.click();
  await page.locator('#alertsFilterReadState').selectOption('unread');
  await page.locator('#alertsFilterStatus').selectOption('active');
  await page.locator('#alertsFilterForm button[type="submit"]').click();
  await expect(cards(page)).toHaveCount(2);
  await expect(page.locator('#alertsFilterChips')).toContainText('Read state: Unread');
  const button = card(page, 9801).getByRole('button', { name: 'Mark as read' });
  await button.focus();
  await button.press('Enter');
  await expect(cards(page)).toHaveCount(1);
  await expect(page.locator('#alertsLogTitle')).toBeFocused();
  await page.getByRole('button', { name: 'Remove read state filter: Unread' }).click();
  await expect(cards(page)).toHaveCount(3);
  await expect(toggle).toBeFocused();
  await expect(page.locator('#alertsFilterReadState')).toHaveValue('all');
});

test('refresh has busy feedback, recoverable errors and a friendly empty state', async ({ page }, info) => {
  const model = await installMocks(page);
  await showAll(page);
  model.hold = true;
  await page.locator('#alertsRefreshBtn').click();
  await expect.poll(() => Boolean(model.pending)).toBe(true);
  await expect(page.locator('#alertsRefreshBtn')).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('#alertsLoading')).toBeVisible();
  await expect(page.locator('#alertsRefreshBtn i')).toHaveCSS('animation-name', info.project.use.reducedMotion === 'reduce' ? 'none' : 'alerts-spin');
  model.failRead = true;
  model.hold = false;
  await model.pending();
  await expect(page.locator('#alertsList')).toContainText('Alerts unavailable');
  await expect(page.locator('#alertsCountScope')).toContainText('Last loaded alerts');
  await expect(page.locator('#alertsLoading')).toBeHidden();
  model.failRead = false;
  model.rows = [];
  await page.locator('#alertsRefreshBtn').click();
  await expect(page.locator('#alertsList')).toContainText('No alerts, all clear');
  await expect(page.locator('#alertsCountUnread')).toHaveText('0');
});

test('live updates stay escaped and motion honors reduced motion and low-power devices', async ({ page }, info) => {
  const model = await installMocks(page);
  await showAll(page);
  await page.locator('#alertsFilterToggle').click();
  await expect(page.locator('#alertsFilterForm')).toBeHidden();
  await card(page, 9801).scrollIntoViewIfNeeded();
  model.rows.unshift({ ...fixtures()[0], id: 9899, title: '<img src=x onerror=alert(1)>', message: '<script>alert(1)</script>', related_qr_id: '" onclick="alert(1)', source: '<svg onload=alert(1)>' });
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('naap:notifications-updated')));
  await expect(card(page, 9899)).toBeVisible();
  await expect(card(page, 9899).locator('img, script, svg')).toHaveCount(0);
  await expect(card(page, 9899).locator('.alerts-log-title')).toHaveText('<img src=x onerror=alert(1)>');
  if (info.project.use.reducedMotion === 'reduce') await expect(card(page, 9899)).not.toHaveClass(/is-arriving/);
  else await expect(card(page, 9899)).toHaveClass(/is-arriving/);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('naap:notifications-updated')));
  await expect(card(page, 9899)).not.toHaveClass(/is-arriving/);
  await page.addInitScript(() => Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 2 }));
  await page.reload();
  await expect(page.locator('body')).toHaveClass(/motion-lite/);
  await page.locator('#alertsRefreshBtn').click();
  await expect(page.locator('#alertsList .is-arriving')).toHaveCount(0);
});
