const { test, expect } = require('@playwright/test');
require('dotenv').config();

async function signIn(page, baseURL, role) {
  const response = await page.request.post('/login', {
    headers: { origin: new URL(baseURL).origin },
    form: { username: process.env[`${role.toUpperCase()}_USERNAME`], password: process.env[`${role.toUpperCase()}_PASSWORD`] },
    maxRedirects: 0
  });
  expect(response.headers().location).toBe(`/${role}`);
  await page.addInitScript(() => { window.EventSource = class extends EventTarget { close() {} }; });
}

for (const role of ['admin', 'guard']) {
  test(`${role} can filter paired gate history with correct editing permissions`, async ({ page, baseURL }) => {
    await signIn(page, baseURL, role);
    const queries = [];
    await page.route('**/api/vehicle-sessions?*', route => {
      queries.push(new URL(route.request().url()).searchParams);
      return route.fulfill({ json: { ok: true, page: 1, limit: 10, total: 1, rows: [{ vehicle_id: 999, vehicle_plate: 'GATE-TEST', entry_gate: 'Gate 1', exit_gate: 'Gate 4', entry_time: '2026-10-18T01:00:00Z', exit_time: '2026-10-18T02:00:00Z', entry_guard: 'Test Guard', exit_guard: 'Test Guard' }] } });
    });
    await page.goto(`/${role}`);
    const panel = page.locator('#vehicleGateHistory');
    await expect(panel.locator('tbody')).toContainText('GATE-TEST');
    await expect(panel.locator('tbody')).toContainText('Gate 1');
    await expect(panel.locator('tbody')).toContainText('Gate 4');
    await expect(panel.locator('#gateDirectionSettings')).toHaveCount(role === 'admin' ? 1 : 0);
    const gateId = await panel.locator('#gateHistoryGate option', { hasText: 'Gate 4' }).getAttribute('value');
    await panel.locator('#gateHistoryGate').selectOption(gateId);
    await panel.locator('#gateHistoryFrom').fill('2026-10-18');
    await panel.locator('#gateHistoryTo').fill('2026-10-18');
    await panel.getByRole('button', { name: 'Apply filters' }).click();
    await expect.poll(() => queries.at(-1).get('gate_id')).toBe(gateId);
    expect(queries.at(-1).get('date_from')).toBe('2026-10-18');
    await page.route('**/api/vehicle-sessions?*', route => route.fulfill({ status: 503, json: { ok: false, message: 'History temporarily unavailable. Try again.' } }));
    await panel.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(panel.locator('#gateHistoryStatus')).toContainText('History temporarily unavailable');
    await expect(panel).toHaveAttribute('aria-busy', 'false');
  });
}

async function manualFixture(page, baseURL, occupancy) {
  await signIn(page, baseURL, 'guard');
  await page.route('**/api/gate-lookup?*', route => route.fulfill({ json: { ok: true, results: [{ entity_type: 'student', full_name: 'Manual Test', student_number: 'TEST', plate_number: 'MANUAL-TEST', sticker_status: 'active', qr_token: 'manual-test', last_action: null }] } }));
  await page.route('**/api/parking-slot-overview?*', route => route.fulfill({ json: { ok: true, summary: { total: 1, available: occupancy === 'available' ? 1 : 0, disabled: occupancy === 'disabled' ? 1 : 0 }, slots: [{ id: 999, slot_code: 'TEST-01', zone: 'Test zone', occupancy }] } }));
  await page.goto('/scanner');
  await page.locator('#gateSearchInput').fill('MANUAL-TEST');
  await page.locator('#gateSearchBtn').click();
  await page.locator('.select-vehicle-btn').click();
}

test('manual entry explains closed parking and prevents an impossible submission', async ({ page, baseURL }) => {
  await manualFixture(page, baseURL, 'disabled');
  await expect(page.locator('#gateLogFeedback')).toContainText('All parking spaces are disabled');
  await expect(page.locator('#gateEntryBtn')).toBeDisabled();
  await expect(page.locator('#gateExitBtn')).toBeHidden();
});

test('manual entry remains usable and reports the chosen gate after saving', async ({ page, baseURL }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let submitted;
  await page.route('**/api/manual-movement', route => {
    submitted = route.request().postDataJSON();
    return route.fulfill({ json: { ok: true, movement_saved: true, action: 'ENTRY', parking_slot: 'TEST-01' } });
  });
  await manualFixture(page, baseURL, 'available');
  await page.locator('#gateNameSelect').selectOption('Gate 1');
  await page.locator('.slot-option-btn[data-selectable="1"]').click();
  await page.locator('#gateEntryBtn').click();
  await expect(page.locator('#gateSearchStatus')).toContainText('Entry recorded at Gate 1');
  expect(submitted).toMatchObject({ token: 'manual-test', action: 'ENTRY', gate: 'Gate 1', slot_id: '999' });
  expect(errors).toEqual([]);
});

test('manual entry gives a clear exit-only gate error before submitting', async ({ page, baseURL }) => {
  await manualFixture(page, baseURL, 'available');
  await page.locator('#gateNameSelect').selectOption('Gate 4');
  await page.locator('.slot-option-btn[data-selectable="1"]').click();
  await page.locator('#gateEntryBtn').click();
  await expect(page.locator('#gateLogFeedback')).toContainText('Gate 4 does not allow entry');
});

test('manual lookup and slot selection survive missing camera and map decoration scripts', async ({ page, baseURL }) => {
  await page.route('**/js/scanner-guidance.js*', route => route.abort());
  await page.route('**/js/parking-layout.js*', route => route.abort());
  await manualFixture(page, baseURL, 'available');
  await page.locator('.slot-option-btn[data-selectable="1"]').click();
  await expect(page.locator('#gateLogFeedback')).toContainText('TEST-01');
  await expect(page.locator('#gateEntryBtn')).toBeEnabled();
});
