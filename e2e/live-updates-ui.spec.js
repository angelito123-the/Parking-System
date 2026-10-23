const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const now = Date.parse('2026-10-23T06:00:00Z');
const cards = page => page.locator('#updatesList .live-event');
const fixtures = () => Array.from({ length: 20 }, (_, index) => ({
  full_name: index === 2 ? null : index === 3 ? '<svg onload="window.unsafeText=true">' : `Student ${index}`,
  student_number: `ST-${index}`, plate_number: `ABC-${index}`, sticker_code: `QR-${index}`,
  action: index === 4 ? 'VERIFY' : index % 2 ? 'EXIT' : 'ENTRY',
  result: index === 2 ? 'INVALID' : 'VALID', gate: index === 3 ? 'Admin Console' : `Gate ${index % 4 + 1}`,
  scanned_at: new Date(now - (index < 6 ? 3600000 : index < 11 ? 86400000 : 172800000) - index * 60000).toISOString(),
  ...(index === 0 ? { scan_source: 'manual' } : index === 1 ? { scan_source: 'camera_phone' } : {})
}));

test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    window.updateAnimations = [];
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (frames, options) {
      if (this.closest('.live-updates-page')) window.updateAnimations.push({ frames, duration: options.duration, target: this.className });
      return animate.call(this, frames, options);
    };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', { headers: { origin: base }, maxRedirects: 0, form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD } });
  expect(response.headers().location).toBe('/admin');
});

async function open(page) {
  const model = { rows: fixtures(), requests: [], fail: false, hold: false, pending: null, inside: [{ is_overstay: true }] };
  await page.route('**/api/dashboard-stats', route => {
    model.requests.push({ method: route.request().method(), path: new URL(route.request().url()).pathname, body: route.request().postData() });
    const respond = () => route.fulfill({ status: model.fail ? 503 : 200, json: model.fail ? { ok: false } : { ok: true, movementLogs: model.rows, insideVehicles: model.inside, overstayAlerts: model.inside.filter(row => row.is_overstay), metrics: { todayEntries: 999, currentlyInside: 999 } } });
    if (model.hold) model.pending = respond;
    else return respond();
  });
  await page.goto('/admin/updates');
  await expect(page.locator('#updatesLastUpdated')).not.toContainText('--');
  expect(model.requests).toEqual([]); // Server-rendered data still needs no initial API request.
  await page.clock.setFixedTime(new Date(now));
  await page.locator('#updatesRefreshBtn').click();
  await expect(cards(page)).toHaveCount(14);
  return model;
}

async function settle(page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 3000).map(a => a.finished)));
}

test('responsive stats and labeled events remain accessible in light, dark and reduced motion', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const model = await open(page);
  const width = info.project.use.viewport.width;
  const columns = await page.locator('.updates-stats-grid').evaluate(el => getComputedStyle(el).gridTemplateColumns.split(' ').length);
  expect(columns).toBe(width <= 600 ? 1 : width <= 1100 ? 2 : 4);
  await expect(page.locator('#updatesMetricEntries')).toHaveText(String(model.rows.filter(row => row.scanned_at.startsWith('2026-10-23') && row.action === 'ENTRY').length));
  await expect(page.locator('#updatesMetricInside')).toHaveText('1');
  await expect(page.locator('#updatesMetricOverstay')).toHaveText('1');
  await expect(page.locator('.has-overstay')).toHaveCount(1);
  expect(await page.locator('.has-overstay').evaluate(el => getComputedStyle(el).borderLeftColor)).toBe(await page.locator('#updatesMetricOverstay').evaluate(el => getComputedStyle(el).color));
  await expect(cards(page).first().locator('.live-direction')).toHaveText('ENTRY');
  await expect(cards(page).nth(1).locator('.live-direction')).toHaveText('EXIT');
  await expect(cards(page).first().locator('.live-method')).toHaveText('Manual');
  await expect(cards(page).nth(1).locator('.live-method')).toHaveText('Scanned: Phone camera');
  await expect(cards(page).nth(2).locator('.live-method')).toHaveText('Method unavailable');
  await expect(cards(page).nth(2).locator('.live-unknown-note')).toBeVisible();
  await expect(cards(page).nth(2).locator('.live-result')).toHaveText('Result INVALID');
  await expect(cards(page).nth(3).locator('.live-event-name')).toHaveText('<svg onload="window.unsafeText=true">');
  await expect(cards(page).nth(3).locator('svg')).toHaveCount(0);
  await expect(cards(page).nth(3)).toContainText('Source Admin Console');
  expect(await page.evaluate(() => window.unsafeText)).toBeUndefined();
  expect(await cards(page).first().evaluate(el => getComputedStyle(el).borderLeftColor)).not.toBe(await cards(page).nth(1).evaluate(el => getComputedStyle(el).borderLeftColor));
  await expect(page.locator('.updates-day-title')).toHaveText(['Today', 'Yesterday', 'Oct 21, 2026']);
  await expect(cards(page).first().locator('time')).toHaveText('1 hour ago');
  await expect(cards(page).first().locator('time')).toHaveAttribute('title', /Oct 23, 2026.*1:00:00 PM.*Philippine/);
  await expect(page.locator('.updates-day-title').first()).toHaveCSS('position', 'sticky');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await settle(page);
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
  await page.screenshot({ path: info.outputPath('live-updates.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('a narrow low-power device shows honest missing-data labels without animation or overflow', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.addInitScript(() => Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 2 }));
  const model = await open(page);
  model.rows = [{ full_name: null, action: 'VERIFY', result: '<img src=x onerror=alert(1)>', scanned_at: null }];
  model.inside = [];
  await page.locator('#updatesRefreshBtn').click();
  await expect(cards(page)).toHaveCount(1);
  await expect(page.locator('.updates-day-title')).toHaveText('Date not recorded');
  await expect(cards(page).first()).toContainText('Not recorded');
  await expect(cards(page).first().locator('time')).toHaveText('Time not recorded');
  await expect(cards(page).first().locator('img')).toHaveCount(0);
  await expect(page.locator('.has-overstay')).toHaveCount(0);
  expect(await page.evaluate(() => window.updateAnimations)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  expect(await page.locator('#updatesFilters button').evaluateAll(nodes => nodes.every(node => node.getBoundingClientRect().width >= 44 && node.getBoundingClientRect().height >= 44))).toBe(true);
});

test('filter chips only filter loaded records and preserve displayed totals', async ({ page }) => {
  const model = await open(page);
  const totals = await page.locator('.updates-stats-grid p').allTextContents();
  for (const [filter, expected] of [['entry', 9], ['exit', 10], ['unknown', 1], ['all', 14]]) {
    await page.locator(`[data-update-filter="${filter}"]`).click();
    await expect(cards(page)).toHaveCount(expected);
    await expect(page.locator(`[data-update-filter="${filter}"]`)).toHaveAttribute('aria-pressed', 'true');
  }
  await expect(page.locator('#updatesFilterCount')).toHaveText('Showing 14 of 20 matching recent events');
  expect(await page.locator('.updates-stats-grid p').allTextContents()).toEqual(totals);
  expect(model.requests).toEqual([{ method: 'GET', path: '/api/dashboard-stats', body: null }]);
  model.rows = model.rows.filter(row => row.full_name);
  await page.locator('#updatesRefreshBtn').click();
  await expect(page.locator('#updatesFilterCount')).toContainText('19 matching');
  await page.locator('[data-update-filter="unknown"]').click();
  await expect(page.locator('.updates-friendly-empty')).toContainText('No matching events');
  model.rows = [];
  await page.locator('#updatesRefreshBtn').click();
  await expect(page.locator('#updatesFilterCount')).toContainText('0 matching');
  await page.locator('[data-update-filter="all"]').click();
  await expect(page.locator('.updates-friendly-empty')).toContainText('No activity yet');
});

test('refresh exposes loading, success, failure and truthful ticking snapshot times', async ({ page, context }) => {
  const model = await open(page);
  await expect(page.locator('#updatesRefreshBtn')).toHaveText('Updated');
  await expect(page.locator('#updatesLastUpdated')).toHaveText('Last updated: Just now');
  await page.clock.setFixedTime(new Date(now + 12000));
  await expect(page.locator('#updatesLastUpdated')).toHaveText('Last updated: 12 seconds ago');
  model.hold = true;
  await page.locator('#updatesRefreshBtn').click();
  await expect(page.locator('#updatesRefreshBtn')).toBeDisabled();
  await expect(page.locator('#updatesRefreshBtn')).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('#updatesLoading')).toBeVisible();
  await expect(page.locator('#updatesLiveStatus')).toHaveText('Refreshing');
  await expect.poll(() => Boolean(model.pending)).toBe(true);
  await model.pending();
  await expect(page.locator('#updatesLoading')).toBeHidden();
  await expect(page.locator('#updatesLastUpdated')).toHaveText('Last updated: Just now');
  await expect(page.locator('#updatesRefreshBtn .ph-check')).toHaveCount(1);
  const priorTime = await page.locator('#updatesLastUpdated').getAttribute('title');
  model.hold = false;
  model.fail = true;
  await page.clock.setFixedTime(new Date(now + 24000));
  await page.locator('#updatesRefreshBtn').click();
  await expect(page.locator('#updatesRefreshError')).toBeVisible();
  await expect(page.locator('#updatesLiveStatus')).toHaveText('Update failed');
  await expect(cards(page)).toHaveCount(14);
  await expect(page.locator('#updatesLastUpdated')).toHaveAttribute('title', priorTime);
  await expect(page.locator('#updatesLastUpdated')).toHaveText('Last updated: 12 seconds ago');
  await context.setOffline(true);
  await expect(page.locator('#updatesLiveStatus')).toHaveText('Offline');
  await context.setOffline(false);
  model.fail = false;
  await page.locator('#updatesRefreshBtn').click();
  await expect(page.locator('#updatesRefreshError')).toBeHidden();
  await expect(page.locator('#updatesLiveStatus')).toHaveText('Live');
  await page.clock.setFixedTime(new Date(now + 71000));
  await expect(page.locator('#updatesLiveStatus')).toHaveText('Waiting for update');
});

test('polling reuses rows, preserves the visible scroll anchor and respects motion preferences', async ({ page }, info) => {
  const model = await open(page);
  await settle(page);
  await page.locator('#updatesList').scrollIntoViewIfNeeded();
  await cards(page).first().evaluate(node => { window.savedRow = node; window.savedName = node.querySelector('.live-event-name'); });
  model.rows.unshift({ ...model.rows[0], full_name: 'New arrival', scanned_at: new Date(now).toISOString() });
  await page.locator('#updatesRefreshBtn').click();
  await expect(cards(page).first()).toContainText('New arrival');
  expect(await cards(page).nth(1).evaluate(node => node === window.savedRow && node.querySelector('.live-event-name') === window.savedName)).toBe(true);
  await settle(page);
  await page.locator('#updatesList').evaluate(list => {
    list.scrollTop = 230;
    const top = list.getBoundingClientRect().top;
    window.anchor = [...list.querySelectorAll('.live-event')].find(node => node.getBoundingClientRect().bottom > top + 44);
    window.anchorOffset = window.anchor.getBoundingClientRect().top - top;
  });
  model.rows.unshift({ ...model.rows[0], full_name: 'Another arrival', scanned_at: new Date(now + 1000).toISOString() });
  // Trigger the existing listener without scrolling the page to the toolbar.
  await page.locator('#updatesRefreshBtn').evaluate(button => button.click());
  await expect(cards(page).first()).toContainText('Another arrival');
  await settle(page);
  expect(await page.locator('#updatesList').evaluate(list => Math.abs(window.anchor.getBoundingClientRect().top - list.getBoundingClientRect().top - window.anchorOffset))).toBeLessThan(2);
  const motions = await page.evaluate(() => window.updateAnimations);
  if (info.project.use.reducedMotion === 'reduce') expect(motions).toEqual([]);
  else {
    expect(motions.length).toBeGreaterThan(0);
    for (const motion of motions) {
      expect(motion.duration).toBeGreaterThanOrEqual(150);
      expect(motion.duration).toBeLessThanOrEqual(400);
      for (const frame of motion.frames) expect(Object.keys(frame).every(key => ['transform', 'opacity'].includes(key))).toBe(true);
    }
  }
});
