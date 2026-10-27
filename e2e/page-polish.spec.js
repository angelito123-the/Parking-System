const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

async function login(page) {
  const base = test.info().project.use.baseURL || process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', {
    headers: { origin: base }, maxRedirects: 0,
    form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD }
  });
  expect(response.headers().location).toBe('/admin');
}
test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => localStorage.setItem('theme', theme), info.project.name.includes('dark') ? 'dark' : 'light');
  await login(page);
});

test('parking status colors, chip navigation and live changes preserve occupancy', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const slots = [
    { id: 9901, slot_code: 'Z-01', zone: 'Basketball Area Parking', slot_type: 'standard', occupancy: 'available', status: 'available' },
    { id: 9902, slot_code: 'Z-02', zone: 'Basketball Area Parking', slot_type: 'standard', occupancy: 'occupied', status: 'available', occupied_by_plate: 'TEST-02' },
    { id: 9903, slot_code: 'Z-03', zone: 'Hangar Parking Zone', slot_type: 'reserved', occupancy: 'available', status: 'available', reserved_for: 'Faculty' },
    { id: 9904, slot_code: 'Z-04', zone: 'Hangar Parking Zone', slot_type: 'reserved', occupancy: 'disabled', status: 'disabled' }
  ];
  await page.route('**/api/parking-slot-overview', route => route.fulfill({ json: { ok: true, slots, summary: { total: 4, available: slots.filter(s => s.occupancy === 'available').length, occupied: slots.filter(s => s.occupancy === 'occupied').length, disabled: 1 } } }));
  await page.route('**/api/parking-slot-history?*', route => route.fulfill({ json: { ok: true, rows: [] } }));
  await page.goto('/admin/slots');
  await page.locator('#slotsRefreshBtn').click();
  const map = page.locator('#parkingSlotsList');
  await expect(map.locator('[data-slot-code]')).toHaveCount(4);
  for (const [code, color, status] of [
    ['Z-01', 'rgb(101, 214, 156)', 'Available'], ['Z-02', 'rgb(245, 194, 102)', 'Occupied'],
    ['Z-03', 'rgb(132, 186, 255)', 'Reserved'], ['Z-04', 'rgb(180, 190, 204)', 'Maintenance']
  ]) {
    const tile = map.locator(`[data-slot-code="${code}"]`);
    await expect(tile.locator('.parking-plan-state')).toHaveCSS('color', color);
    await expect(tile).toHaveCSS('border-top-color', 'rgb(229, 237, 245)');
    await expect(tile.locator('.parking-plan-state')).toHaveText(status);
    await expect(tile.locator('.parking-plan-state-icon')).toHaveAttribute('aria-hidden', 'true');
  }
  await page.locator('[data-parking-view="table"]').click();
  await page.locator('[data-slot-pill="Z-03"]').click();
  await expect(map).toBeVisible();
  await expect(map.locator('[data-slot-code="Z-03"]')).toBeFocused();
  await expect(page.locator('#slotInspectorTitle')).toHaveText('Z-03');
  await expect(page.locator('#slotEditorState')).toHaveValue('available');
  await page.locator('#parkingSlotSearch').fill('');
  slots[0].occupancy = 'occupied';
  await page.locator('#slotsRefreshBtn').click();
  await expect(map.locator('[data-slot-code="Z-01"] .parking-plan-state')).toHaveCSS('color', 'rgb(245, 194, 102)');
  await expect(map.locator('[data-slot-code="Z-01"] .parking-plan-state')).toHaveText('Occupied');
  await expect(page.locator('[data-slot-pill="Z-01"]')).toHaveCount(0);
  if (info.project.use.reducedMotion === 'reduce') await expect(page.locator('.parking-state-change')).toHaveCount(0);
  await page.screenshot({ path: info.outputPath('slots-polished.png') });
  expect(errors).toEqual([]);
});

test('student disclosure, tabs and validation remain usable with rapid input', async ({ page }, info) => {
  await page.goto('/students#register');
  await page.locator('#regSubmitBtn').click();
  await expect(page.locator('#regForm .form-error-summary')).toBeVisible();
  const field = page.locator('#regForm input[name="full_name"]');
  await field.fill('Local UI review');
  await field.blur();
  await expect(field).toHaveAttribute('data-field-valid', 'true');
  const toggle = page.locator('#vehicleToggle');
  await toggle.click();
  await expect(page.locator('#vehicleSection')).toBeVisible();
  await toggle.click();
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#vehicleSection')).toBeVisible();
  await toggle.click();
  await expect(page.locator('#vehicleSection')).toBeHidden();
  await expect(page.locator('#vehicleSection input').first()).toBeDisabled();
  await page.locator('#directoryTab').click();
  const button = page.locator('[data-ui-action="toggle-student-details"]').first();
  await button.click();
  await expect(button).toHaveAttribute('aria-expanded', 'true');
  const details = page.locator('#' + await button.getAttribute('aria-controls'));
  await expect(details).toBeVisible();
  await button.click();
  await expect(details).toBeHidden();
  const menu = page.locator('#studentDirectory [data-action-menu-trigger]').first();
  await menu.click();
  await menu.press('ArrowDown');
  await expect(page.locator('.action-menu.is-open [role="menuitem"]').first()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(menu).toBeFocused();
  await page.screenshot({ path: info.outputPath('students-polished.png') });
});

test('QR preview, copy feedback and destructive confirmation preserve native actions', async ({ page, context }, info) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/stickers');
  const tools = page.locator('.sticker-tools:visible').first();
  const qr = tools.getByRole('link', { name: 'View QR', exact: true });
  const href = await qr.getAttribute('href');
  expect(href).toMatch(/^\/stickers\/\d+\/qr$/);
  await qr.click();
  const modal = page.getByRole('dialog', { name: 'Vehicle QR code' });
  await expect(modal.locator('img')).toBeVisible();
  expect(await modal.locator('img').evaluate(img => img.naturalWidth)).toBeGreaterThan(200);
  await page.keyboard.press('Escape');
  await expect(qr).toBeFocused();
  await tools.getByRole('button', { name: 'Copy link', exact: true }).click();
  await expect(tools.getByRole('button', { name: 'Link copied' })).toBeVisible();
  await expect(page.locator('.ui-toast-success')).toContainText('Verification link copied');
  await tools.getByRole('button', { name: 'Replace QR', exact: true }).click();
  await expect(page.locator('#confirmDialog')).toContainText('Replace');
  await page.keyboard.press('Escape');
  await expect(tools.getByRole('button', { name: 'Replace QR', exact: true })).toBeFocused();
  await page.locator('.sticker-management-actions:visible').first().getByRole('button', { name: 'Revoke sticker' }).click();
  await expect(page.locator('#confirmDialog')).toContainText('Revoke');
  await page.keyboard.press('Escape');
  await page.route('**' + href, route => route.abort());
  await page.reload();
  await qr.click();
  await expect(modal.locator('[role="status"]')).toContainText('Unable to load');
  await page.keyboard.press('Escape');
  await expect(tools.getByRole('link', { name: 'Download', exact: true })).toHaveAttribute('download');
  await page.screenshot({ path: info.outputPath('stickers-polished.png') });
});

test('polished pages retain contrast, names and narrow-screen fit', async ({ page }) => {
  for (const route of ['/admin/slots', '/students#register', '/students#directory', '/stickers']) {
    await page.goto(route);
    // Assess final text colors after finite entrance effects, not an in-between opacity frame.
    await page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 2000).map(a => a.finished)));
    const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(n => ({ target: n.target, message: n.failureSummary })) })), route).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), route).toBe(true);
  }
});
