const { test, expect } = require('@playwright/test');

test('manual slot selection keeps keyboard focus and the existing map nodes', async ({ page, baseURL }) => {
  await manualFixture(page, baseURL, 'available');
  const slot = page.locator('.slot-option-btn[data-selectable="1"]');
  await expect(page.locator('#gateEntryBtn')).toBeDisabled();
  await slot.focus();
  await slot.evaluate(element => { window.originalManualSlot = element; });
  await page.keyboard.press('Enter');
  await expect(slot).toBeFocused();
  await expect(slot).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#gateEntryBtn')).toBeEnabled();
  expect(await slot.evaluate(element => element === window.originalManualSlot && element.isConnected)).toBe(true);
  await page.locator('#gateNameSelect').selectOption('Gate 4');
  await expect(page.locator('#manualSelectedGate')).toHaveText('Gate 4');
});

test('manual lookup ignores older responses that finish after the latest search', async ({ page, baseURL }) => {
  await signIn(page, baseURL, 'guard');
  let releaseOldSearch;
  let oldSearchReceived;
  const received = new Promise(resolve => { oldSearchReceived = resolve; });
  const pending = new Promise(resolve => { releaseOldSearch = resolve; });
  await page.route('**/api/gate-lookup?*', async route => {
    const query = new URL(route.request().url()).searchParams.get('q');
    if (query === 'OLDER') { oldSearchReceived(); await pending; }
    await route.fulfill({ json: { ok: true, results: [{
      full_name: query, plate_number: query, sticker_status: 'active', qr_token: query, last_action: null
    }] } });
  });
  await page.goto('/scanner');
  await page.locator('#gateSearchInput').fill('OLDER');
  await page.locator('#gateSearchBtn').click();
  await received;
  await expect(page.locator('#gateSearchBtn')).toHaveText('Searching...');
  await page.locator('#gateSearchInput').fill('LATEST');
  await page.locator('#gateSearchInput').press('Enter');
  await expect(page.locator('#gateResultsContainer')).toContainText('LATEST');
  const oldResponse = page.waitForResponse(response => new URL(response.url()).searchParams.get('q') === 'OLDER');
  releaseOldSearch();
  await oldResponse;
  await page.waitForFunction(() => document.getElementById('gateSearchBtn').disabled === false);
  await expect(page.locator('#gateResultsContainer')).not.toContainText('OLDER');
  await expect(page.locator('#gateResultsContainer')).toContainText('LATEST');
  await expect(page.locator('#gateResultsContainer')).toHaveAttribute('aria-busy', 'false');
});

test('manual movement locks the selection while saving and preserves server errors for retry', async ({ page, baseURL }) => {
  let releaseSave;
  const pending = new Promise(resolve => { releaseSave = resolve; });
  const submissions = [];
  await page.route('**/api/manual-movement', async route => {
    submissions.push(route.request().postDataJSON());
    if (submissions.length === 1) await pending;
    await route.fulfill({ status: submissions.length === 1 ? 409 : 200, json: submissions.length === 1
      ? { ok: false, movement_saved: false, message: 'Slot is no longer available. Select another slot.' }
      : { ok: true, movement_saved: true } });
  });
  await manualFixture(page, baseURL, 'available');
  await page.locator('#gateNameSelect').selectOption('Gate 1');
  await page.locator('.slot-option-btn[data-selectable="1"]').click();
  await page.locator('#gateEntryBtn').click();
  await expect(page.locator('#gateEntryBtn')).toBeDisabled();
  await expect(page.locator('#gateEntryBtn')).toContainText('Recording entry...');
  await expect(page.locator('#gateNameSelect')).toBeDisabled();
  await expect(page.locator('#gateSearchInput')).toHaveAttribute('readonly', '');
  await page.locator('#gateEntryBtn').evaluate(element => element.click());
  expect(submissions).toHaveLength(1);
  releaseSave();
  await expect(page.locator('#gateLogFeedback')).toContainText('Slot is no longer available');
  await expect(page.locator('#gateEntryBtn')).toBeEnabled();
  await expect(page.locator('#gateNameSelect')).toBeEnabled();
  await page.locator('#gateEntryBtn').click();
  await expect(page.locator('#gateSearchStatus')).toContainText('Entry recorded at Gate 1');
  await expect(page.locator('#gateLogFeedback')).toContainText('Entry recorded at Gate 1');
  await expect(page.locator('#gateSearchInput')).toBeFocused();
  await expect(page.locator('#gateEntryBtn')).toBeDisabled();
  expect(submissions).toHaveLength(2);
  expect(submissions[1]).toMatchObject({ token: 'manual-test', action: 'ENTRY', gate: 'Gate 1', slot_id: '999' });
});

require('dotenv').config();

test('manual parking ignores a stale map after selecting another vehicle', async ({ page, baseURL }) => {
  await signIn(page, baseURL, 'guard');
  let releaseOldMap;
  let mapRequested;
  const received = new Promise(resolve => { mapRequested = resolve; });
  const pending = new Promise(resolve => { releaseOldMap = resolve; });
  await page.route('**/api/gate-lookup?*', route => route.fulfill({ json: { ok: true, results: [
    { full_name: 'Student A', plate_number: 'STUDENT-A', qr_token: 'student-a', sticker_status: 'active' },
    { full_name: 'Visitor B', plate_number: 'VISITOR-B', qr_token: 'visitor-b', sticker_status: 'active', entity_type: 'visitor' }
  ] } }));
  await page.route('**/api/parking-slot-overview?*', async route => {
    const scope = new URL(route.request().url()).searchParams.get('scope');
    if (scope === 'all') { mapRequested(); await pending; }
    await route.fulfill({ json: { ok: true, summary: { total: 1, available: 1 }, slots: [
      { id: scope === 'all' ? 1 : 2, slot_code: scope === 'all' ? 'OLD-01' : 'VISITOR-01', zone: 'Test zone', occupancy: 'available' }
    ] } });
  });
  await page.goto('/scanner?q=TEST');
  await page.locator('.select-vehicle-btn').first().click();
  await received;
  await page.locator('.select-vehicle-btn').nth(1).click();
  await expect(page.locator('#slotMap')).toContainText('VISITOR-01');
  const oldResponse = page.waitForResponse(response => response.url().includes('parking-slot-overview?scope=all'));
  releaseOldMap();
  await oldResponse;
  await expect(page.locator('#slotMap')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#slotMap')).toContainText('VISITOR-01');
  await expect(page.locator('#slotMap')).not.toContainText('OLD-01');
  await expect(page.locator('#gateLogInfo')).toContainText('Visitor B');
});


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
