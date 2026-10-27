const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const bay = (page, code) => page.locator(`#parkingSlotsList .parking-plan-bay[data-slot-code="${code}"]`);
const section = page => page.locator('#parkingSlotsList .parking-zone-section:visible');
const settle = page => page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 3000).map(a => a.finished)));
function fixtures() {
  const slots = Array.from({ length: 20 }, (_, index) => ({ id: 9500 + index, slot_code: `A-${String(index + 1).padStart(2, '0')}`, zone: 'Basketball Area Parking', slot_type: 'standard', occupancy: 'available', status: 'available' }));
  Object.assign(slots[0], { occupancy: 'occupied', occupied_by_plate: '27900Q', occupied_by_name: 'Vehicle owner <img src=x onerror=alert(1)>', occupied_by_type: 'student' });
  Object.assign(slots[2], { slot_type: 'reserved', reserved_for: 'Faculty' });
  Object.assign(slots[3], { occupancy: 'disabled', status: 'disabled', disabled_reason: 'School event', occupied_by_plate: 'AB0O12', occupied_by_type: 'student' });
  Object.assign(slots[4], { occupancy: 'disabled', status: 'disabled' });
  Object.assign(slots[5], { occupancy: 'occupied', slot_type: 'reserved', reserved_for: 'Faculty' });
  slots.push(...Array.from({ length: 20 }, (_, index) => ({ id: 9600 + index, slot_code: `H-${String(index + 1).padStart(2, '0')}`, zone: 'Hangar Parking Zone', slot_type: 'standard', occupancy: 'available', status: 'available' })));
  return slots;
}
test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    window.EventSource = class extends EventTarget { close() {} };
    window.mapAnimations = [];
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (frames, options) {
      if (this.closest('#parkingSlotsList')) window.mapAnimations.push({ className: this.className, frames, duration: options.duration });
      return animate.call(this, frames, options);
    };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
});
async function setup(page) {
  const model = { slots: fixtures(), requests: [], fail: false, hold: false, pending: null };
  await page.route('**/api/parking-slot-overview', route => {
    model.requests.push({ url: new URL(route.request().url()).pathname, method: route.request().method() });
    const respond = () => route.fulfill(model.fail ? { status: 503, json: { ok: false } } : { json: { ok: true, slots: model.slots, summary: { total: model.slots.length, available: model.slots.filter(s => s.occupancy === 'available').length, occupied: model.slots.filter(s => s.occupancy === 'occupied').length, disabled: model.slots.filter(s => s.occupancy === 'disabled').length } } });
    if (model.hold) model.pending = respond;
    else return respond();
  });
  await page.route('**/api/parking-slot-history?*', route => {
    model.requests.push({ url: new URL(route.request().url()).pathname + new URL(route.request().url()).search, method: route.request().method() });
    return route.fulfill({ json: { ok: true, rows: [] } });
  });
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', { headers: { origin: base }, maxRedirects: 0, form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD } });
  expect(response.headers().location).toBe('/admin');
  await page.goto('/admin/slots');
  await page.locator('#slotsRefreshBtn').click();
  await expect(bay(page, 'A-01')).toHaveAttribute('data-parking-visual-state', 'occupied');
  await page.locator('#parkingZonePicker').selectOption('Basketball Area Parking');
  await settle(page);
  return model;
}
async function audit(page) {
  await settle(page);
  const result = await new AxeBuilder({ page }).include('.parking-space-layout').include('.parking-status-legend').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
}

test('compact zones retain bay order, show accurate summaries and have no nested vertical scroll', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await setup(page);
  await expect(section(page).locator('.parking-plan-bay')).toHaveCount(20);
  expect(await section(page).locator('.parking-plan-bay').evaluateAll(nodes => nodes.map(n => n.dataset.slotCode))).toEqual(Array.from({ length: 20 }, (_, i) => `A-${String(i + 1).padStart(2, '0')}`));
  await expect(section(page).locator('.map-zone-count strong')).toHaveText(['15', '2', '1', '2']);
  await expect(section(page).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '10');
  await expect(section(page).locator('.parking-plan-divider')).toHaveCount(8);
  await expect(section(page).locator('.parking-plan-divider').first()).toHaveText('');
  await expect(section(page).locator('.parking-plan-divider').first()).toHaveAccessibleName('Parking divider / curb');
  await expect(page.locator('#parkingSlotsList')).toHaveCSS('overflow-y', 'visible');
  await expect(page.locator('#parkingSlotsList')).toHaveCSS('max-height', 'none');
  const dimensions = await bay(page, 'A-02').boundingBox();
  expect(dimensions.height).toBeGreaterThanOrEqual(44);
  expect(dimensions.height).toBeLessThanOrEqual(58);
  expect(dimensions.width / dimensions.height).toBeGreaterThan(1.45);
  expect(dimensions.width / dimensions.height).toBeLessThan(2.5);
  await expect(bay(page, 'A-01').locator('.map-plate')).toHaveText('27900Q');
  await expect(bay(page, 'A-04').locator('.map-plate')).toHaveText('AB0O12');
  await bay(page, 'A-01').focus();
  await expect(page.locator('#parkingBayTooltip')).toContainText('Vehicle owner <img');
  await expect(page.locator('#parkingBayTooltip img')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page.locator('#parkingBayTooltip')).toBeHidden();
  await audit(page);
  await section(page).evaluate(n => n.scrollIntoView({ block: 'start' }));
  await settle(page);
  await page.screenshot({ path: info.outputPath('compact-map.png') });
  await page.locator('#parkingZonePicker').selectOption('Hangar Parking Zone');
  await expect(section(page).locator('.parking-plan-row')).toHaveCount(20);
  await expect(section(page).locator('.parking-plan-divider')).toHaveCount(0);
  expect(await section(page).locator('.parking-plan-row').evaluateAll(rows => rows.every(row => row.firstElementChild.classList.contains('parking-plan-bay') && row.lastElementChild.classList.contains('parking-plan-empty')))).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  expect(errors).toEqual([]);
});

test('legend, arrows and available shortcut reuse selection without hiding inventory or changing filters', async ({ page }) => {
  const model = await setup(page);
  const originalRequests = model.requests.length;
  await page.locator('[data-map-status="reserved"]').click();
  await expect(bay(page, 'A-03')).toHaveClass(/map-status-match/);
  await expect(bay(page, 'A-02')).toHaveClass(/map-status-muted/);
  await expect(section(page).locator('.parking-plan-bay')).toHaveCount(20);
  await audit(page);
  // The existing 20-second overview poll can run during a slow accessibility audit.
  expect(model.requests.slice(originalRequests).every(r => r.method === 'GET' && r.url === '/api/parking-slot-overview')).toBe(true);
  await bay(page, 'A-01').focus();
  await page.keyboard.press('ArrowRight');
  await expect(bay(page, 'A-02')).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(bay(page, 'A-04')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#slotInspectorTitle')).toHaveText('A-04');
  await expect(bay(page, 'A-04')).toBeFocused();
  await expect(page.locator('#slotEditorState')).toHaveValue('disabled');
  await page.locator('#findAvailableBay').click();
  await expect(page.locator('#slotInspectorTitle')).toHaveText('A-02');
  await expect(bay(page, 'A-02')).toBeFocused();
  await expect(page.locator('#parkingSlotSearch')).toHaveValue('');
  await expect(page.locator('[data-slot-filter="all"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(section(page).locator('.parking-plan-bay')).toHaveCount(20);
  await page.locator('[data-parking-view="table"]').click();
  await expect(page.locator('#parkingMapControls')).toBeHidden();
  expect(await page.locator('#parkingSlotsTableRegion').evaluate(n => n.clientWidth <= innerWidth && n.scrollWidth > 0)).toBe(true);
  await page.locator('[data-slot-select="H-01"]').click();
  await expect(page.locator('#slotInspectorTitle')).toHaveText('H-01');
  await page.locator('[data-parking-view="map"]').click();
  await expect(page.locator('#parkingZonePicker')).toHaveValue('Hangar Parking Zone');
  await page.locator('[data-slot-pill="A-03"]').click();
  await expect(page.locator('#parkingZonePicker')).toHaveValue('Basketball Area Parking');
  await expect(bay(page, 'A-03')).toBeFocused();
  await expect(page.locator('#slotEditorState')).toHaveValue('available');
  expect(model.requests.every(r => r.method === 'GET')).toBe(true);
});

test('refresh retains the selected bay and zone, animates arrivals, and handles loading and failure honestly', async ({ page }, info) => {
  const model = await setup(page);
  await bay(page, 'A-02').click();
  await page.locator('#parkingZonePicker').selectOption('Hangar Parking Zone');
  model.slots[1].occupancy = 'occupied';
  model.slots[1].occupied_by_plate = 'NEW000';
  model.hold = true;
  await page.locator('#slotsRefreshBtn').click();
  await expect(page.locator('#parkingMapLoading')).toBeVisible();
  await expect(page.locator('#parkingSlotsList')).toHaveAttribute('aria-busy', 'true');
  await model.pending(); model.hold = false;
  await expect(page.locator('#parkingMapLoading')).toBeHidden();
  await expect(page.locator('#parkingZonePicker')).toHaveValue('Hangar Parking Zone');
  await expect(page.locator('#slotInspectorTitle')).toHaveText('A-02');
  await page.locator('#parkingZonePicker').selectOption('Basketball Area Parking');
  await expect(bay(page, 'A-02').locator('.map-plate')).toHaveText('NEW000');
  await expect(bay(page, 'A-02')).toHaveAttribute('aria-pressed', 'true');
  model.fail = true;
  await page.locator('#slotsRefreshBtn').click();
  await expect(page.locator('#slotsLastUpdated')).toContainText('showing previous data');
  await expect(bay(page, 'A-02').locator('.map-plate')).toHaveText('NEW000');
  await expect(page.locator('#parkingMapLoading')).toBeHidden();
  const animations = await page.evaluate(() => window.mapAnimations);
  if (info.project.use.reducedMotion === 'reduce') expect(animations).toEqual([]);
  else expect(animations.some(a => a.className.includes('map-bay-car'))).toBe(true);
  for (const animation of animations) {
    expect(animation.duration).toBeGreaterThanOrEqual(150);
    expect(animation.duration).toBeLessThanOrEqual(400);
    animation.frames.forEach(frame => expect(Object.keys(frame).every(key => ['transform', 'opacity'].includes(key))).toBe(true));
  }
});

test('narrow low-power screens show empty zones and keep conditional zoom usable', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 2 }));
  await page.setViewportSize({ width: 320, height: 740 });
  const model = await setup(page);
  await page.locator('#parkingSlotSearch').fill('missing-space');
  await expect(section(page).locator('.map-zone-empty')).toContainText('No matching spaces');
  await expect(page.locator('#findAvailableBay')).toBeDisabled();
  await page.locator('#parkingSlotSearch').fill('');
  await expect(page.locator('#parkingMapZoom')).toBeHidden();
  // A future wide zone drawing gets zoom controls; normal two-column maps do not need them.
  const wideMapStyle = await page.addStyleTag({ content: '#parkingSlotsList .parking-plan { min-width: 600px !important; }' });
  await page.setViewportSize({ width: 360, height: 740 });
  await expect(page.locator('#parkingMapZoom')).toBeVisible();
  await page.locator('[data-map-zoom="in"]').click();
  await page.locator('[data-map-zoom="fit"]').click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await wideMapStyle.evaluate(n => n.remove());
  await page.setViewportSize({ width: 390, height: 740 });
  await expect(page.locator('#parkingMapZoom')).toBeHidden();
  await expect(section(page).locator('.parking-plan')).not.toHaveClass(/map-scaled/);
  await expect(section(page).locator('.map-bay-stage')).not.toHaveAttribute('style', /height|width/);
  model.slots = model.slots.filter(s => s.zone !== 'Basketball Area Parking');
  await page.locator('#slotsRefreshBtn').click();
  await page.locator('#parkingZonePicker').selectOption('Basketball Area Parking');
  await expect(section(page).locator('.map-zone-empty')).toContainText('No spaces in this zone yet');
  await audit(page);
  expect(await page.evaluate(() => window.mapAnimations)).toEqual([]);
});
