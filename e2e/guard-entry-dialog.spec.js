const { test, expect } = require('@playwright/test');
require('dotenv').config();

const overview = (code) => ({
  ok: true,
  slots: [{ id: 1, slot_code: code, zone: 'Basketball Area Parking', occupancy: 'available' }],
  summary: { total: 1, available: 1, occupied: 0, disabled: 0 }
});

test.beforeEach(async ({ page, baseURL }) => {
  // Keep all entry mutations local to the browser; no parking records are changed.
  await page.addInitScript(() => {
    window.EventSource = class extends EventTarget { close() {} };
  });
  await page.route('**/api/auto-scan/pending-entries?*', (route) => route.fulfill({ json: {
    ok: true,
    rows: [{ id: 987654, full_name: 'Dialog Test', student_number: 'TEST', plate_number: 'TEST', created_at: new Date().toISOString() }]
  } }));
  await page.route('**/api/auto-scan/pending-entries/*/*', (route) => route.fulfill({ status: 500, json: { ok: false, message: 'Test request failed' } }));
  await page.route('**/api/parking-slot-overview', (route) => route.fulfill({ json: overview('A-01') }));
  const login = await page.request.post('/login', {
    headers: { origin: new URL(baseURL).origin },
    form: { username: process.env.GUARD_USERNAME || 'guard', password: process.env.GUARD_PASSWORD || 'guard123' },
    maxRedirects: 0
  });
  expect(login.headers().location).toBe('/guard');
  await page.goto('/guard');
  await expect(page.locator('.guard-open-entry-btn')).toBeVisible();
});

async function openEntry(page) {
  await page.locator('.guard-open-entry-btn').click();
  await expect(page.locator('#guardEntryModal')).toHaveAttribute('aria-hidden', 'false');
}

test('entry confirmation requires a selected slot, including after cancellation fails', async ({ page }) => {
  await openEntry(page);
  await expect(page.locator('#guardSlotMap')).toContainText('A-01');
  await expect(page.locator('#guardEntryConfirmBtn')).toBeDisabled();
  await page.locator('#guardEntryCancelBtn').click();
  await expect(page.locator('#guardEntryHint')).toHaveText('Test request failed');
  await expect(page.locator('#guardEntryConfirmBtn')).toBeDisabled();
  await page.locator('.guard-slot-btn').click();
  await expect(page.locator('#guardEntryConfirmBtn')).toBeEnabled();
  await page.locator('#guardEntryConfirmBtn').click();
  await expect(page.locator('#guardEntryHint')).toHaveText('Test request failed');
  await expect(page.locator('#guardEntryConfirmBtn')).toBeEnabled();
});

for (const failed of [false, true]) {
  test(`a stale slot ${failed ? 'error' : 'response'} cannot overwrite a reopened dialog`, async ({ page }) => {
    let release;
    const waiting = new Promise((resolve) => { release = resolve; });
    let requestStarted;
    const started = new Promise((resolve) => { requestStarted = resolve; });
    let requests = 0;
    await page.route('**/api/parking-slot-overview', async (route) => {
      if (++requests === 1) {
        requestStarted();
        await waiting;
        await route.fulfill({ status: failed ? 500 : 200, json: failed ? { ok: false, message: 'Old request failed' } : overview('OLD-SLOT') });
      } else {
        await route.fulfill({ json: overview('CURRENT-SLOT') });
      }
    });
    await openEntry(page);
    await started;
    await page.locator('#guardEntryCloseBtn').click();
    await openEntry(page);
    await expect(page.locator('#guardSlotMap')).toContainText('CURRENT-SLOT');
    await page.locator('.guard-slot-btn').click();
    const response = page.waitForResponse('**/api/parking-slot-overview');
    release();
    await (await response).finished();
    await page.waitForTimeout(100);
    await expect(page.locator('#guardSlotMap')).toContainText('CURRENT-SLOT');
    await expect(page.locator('#guardEntryHint')).toHaveText('Selected slot CURRENT-SLOT.');
    await expect(page.locator('#guardEntryConfirmBtn')).toBeEnabled();
  });
}

for (const action of ['confirm', 'cancel']) {
  test(`the current dialog still completes ${action} normally`, async ({ page }) => {
    const url = `**/api/auto-scan/pending-entries/*/${action}`;
    await page.route(url, (route) => route.fulfill({ json: { ok: true, parking_slot: 'A-01' } }));
    await openEntry(page);
    await expect(page.locator('#guardSlotMap')).toContainText('A-01');
    if (action === 'confirm') await page.locator('.guard-slot-btn').click();
    const request = page.waitForRequest(url);
    await page.locator(action === 'confirm' ? '#guardEntryConfirmBtn' : '#guardEntryCancelBtn').click();
    expect((await request).postDataJSON()).toEqual(action === 'confirm'
      ? { slot_id: 1, gate: 'Main Gate' }
      : { reason: 'Cancelled by guard dashboard.' });
    await expect(page.locator('#guardEntryModal')).toHaveAttribute('aria-hidden', 'true');
    await expect(page.locator('#guardQueueLiveAlert')).toContainText(action === 'confirm' ? 'ENTRY confirmed' : 'Pending request cancelled');
  });

  for (const failed of [false, true]) {
    test(`a stale ${action} ${failed ? 'error' : 'response'} leaves the reopened dialog intact`, async ({ page }) => {
      let release;
      const waiting = new Promise((resolve) => { release = resolve; });
      let requestStarted;
      const started = new Promise((resolve) => { requestStarted = resolve; });
      const url = `**/api/auto-scan/pending-entries/*/${action}`;
      await page.route(url, async (route) => {
        requestStarted();
        await waiting;
        await route.fulfill({ status: failed ? 500 : 200, json: failed ? { ok: false, message: 'Old action failed' } : { ok: true, parking_slot: 'A-01' } });
      });
      await openEntry(page);
      await page.locator('.guard-slot-btn').click();
      await page.locator(action === 'confirm' ? '#guardEntryConfirmBtn' : '#guardEntryCancelBtn').click();
      await started;
      await page.locator('#guardEntryCloseBtn').click();
      await openEntry(page);
      await expect(page.locator('#guardSlotMap')).toContainText('A-01');
      const response = page.waitForResponse(url);
      release();
      await (await response).finished();
      await page.waitForTimeout(100);
      await expect(page.locator('#guardEntryModal')).toHaveAttribute('aria-hidden', 'false');
      await expect(page.locator('#guardEntryHint')).toHaveText('Select an available slot to continue.');
      await expect(page.locator('#guardEntryConfirmBtn')).toBeDisabled();
      await expect(page.locator('#guardEntryCancelBtn')).toBeEnabled();
    });
  }
}
