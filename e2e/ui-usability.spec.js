const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
require('dotenv').config();
async function signIn(page, role) {
  const baseURL = test.info().project.use.baseURL || process.env.E2E_BASE_URL || 'http://127.0.0.1:3000';
  const response = await page.request.post(baseURL + '/login', {
    headers: { origin: baseURL },
    form: { username: process.env[role.toUpperCase() + '_USERNAME'], password: process.env[role.toUpperCase() + '_PASSWORD'] },
    maxRedirects: 0
  });
  expect(response.headers().location).toBe('/' + role);
}

test.beforeEach(async ({ page }, testInfo) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => localStorage.setItem('theme', theme), testInfo.project.name.includes('dark') ? 'dark' : 'light');
});


for (const role of ['admin', 'guard']) {
  test(`${role} notification and account panels never cover one another`, async ({ page }, testInfo) => {
    const errors = [];
    const writes = [];
    const queries = [];
    const rows = [
      { id: 9001, title: 'Entry attempt after denial', message: 'Manual EXIT denied: last movement is already EXIT.', severity: 'medium', type: 'SUSPICIOUS_SCAN_BEHAVIOR', status: 'resolved', is_read: false, created_at: '2026-10-19T01:00:42Z' },
      { id: 9002, title: 'Parking zone full: Basketball Area Parking', message: 'No spaces remain in this zone. Entry can resume when a slot is released.', severity: 'high', type: 'FULL_PARKING_ZONE', status: 'active', is_read: false, created_at: '2026-10-18T12:19:50Z' },
      { id: 9003, title: 'Parking status updated', message: 'The parking inventory has been checked.', severity: 'low', type: 'PARKING_STATUS', status: 'resolved', is_read: true, created_at: '2026-10-18T10:00:00Z' }
    ];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => { window.EventSource = class extends EventTarget { close() {} }; });
    await page.route('**/api/notifications**', route => {
      const url = new URL(route.request().url());
      if (route.request().method() === 'POST') {
        writes.push(url.pathname);
        if (url.pathname.endsWith('/read-all')) rows.forEach(row => { row.is_read = true; });
        else {
          const row = rows.find(item => String(item.id) === url.pathname.split('/')[3]);
          if (row && url.pathname.endsWith('/read')) row.is_read = true;
          if (row && url.pathname.endsWith('/resolve')) row.status = 'resolved';
        }
        return route.fulfill({ json: { ok: true } });
      }
      if (url.pathname.endsWith('/summary')) return route.fulfill({ json: { ok: true, summary: { active_total: rows.filter(row => row.status === 'active').length, unread_total: rows.filter(row => !row.is_read).length } } });
      queries.push(url.searchParams.toString());
      const filtered = rows.filter(row => (!url.searchParams.has('severity') || row.severity === url.searchParams.get('severity')) && (!url.searchParams.has('read_state') || !row.is_read));
      return route.fulfill({ json: { ok: true, rows: filtered } });
    });
    await signIn(page, role);
    await page.goto('/' + role);
    const bell = page.locator('#notificationBell');
    const panel = page.locator('#notificationPanel');
    const account = page.locator('#accountMenuButton');
    const menu = page.locator('#accountMenu');
    await bell.click();
    await expect(panel.locator('.notification-row')).toHaveCount(3);
    await expect(panel.locator('[data-notification-id="9001"]')).toBeHidden();
    await panel.locator('.notification-resolved summary').click();
    await expect(panel.locator('[data-notification-id="9001"]').getByRole('img', { name: 'Resolved', exact: true })).toBeVisible();
    await expect(panel.locator('[data-notification-id="9001"] .sev-medium')).toHaveCount(0);
    await expect(panel.locator('.notification-row').first()).not.toContainText(/\bmedium\b/i);
    await expect(panel.locator('.notification-chip')).toHaveCount(3);
    await expect(panel.locator('[data-notification-id="9001"] .notification-category')).toHaveText('suspicious scan behavior');
    await panel.screenshot({ path: testInfo.outputPath('notifications.png') });
    const audit = await new AxeBuilder({ page }).include('#notificationPanel').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(audit.violations.map(item => ({ id: item.id, targets: item.nodes.map(node => ({ target: node.target, summary: node.failureSummary })) }))).toEqual([]);
    expect(await panel.evaluate(element => {
      const box = element.getBoundingClientRect();
      return box.left >= 0 && box.right <= innerWidth + 1 && box.bottom <= innerHeight + 1;
    })).toBe(true);
    await account.click();
    await expect(menu).toBeVisible();
    await expect(panel).toBeHidden();
    await expect(panel).toHaveAttribute('inert', '');
    await expect(bell).toHaveAttribute('aria-expanded', 'false');
    const logout = menu.locator('a[href="/logout"]');
    expect(await logout.evaluate(element => {
      const box = element.getBoundingClientRect();
      return element.contains(document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2));
    })).toBe(true);
    await page.keyboard.press('Escape');
    await expect(account).toBeFocused();
    await account.press('Enter');
    await bell.click();
    await expect(menu).toBeHidden();
    await expect(panel).toBeVisible();
    await expect(page.locator('#notificationCloseBtn')).toBeFocused();
    await account.focus();
    await expect(page.locator('#notificationCloseBtn')).toBeFocused();
    await page.keyboard.press('Escape');
    await account.focus();
    await account.press('Enter');
    await expect(panel).toBeHidden();
    await expect(menu).toBeVisible();
    await bell.focus();
    await bell.press('Space');
    await expect(menu).toBeHidden();
    await expect(panel).toBeVisible();
    await panel.getByRole('button', { name: 'High priority', exact: true }).click();
    await expect(panel.locator('.notification-row')).toHaveCount(1);
    expect(queries.at(-1)).toContain('severity=high');
    await panel.getByRole('button', { name: 'All', exact: true }).click();
    await expect(panel.locator('.notification-row')).toHaveCount(3);
    await panel.locator('.notification-resolved summary').click();
    await panel.locator('[data-notification-id="9001"]').getByRole('button', { name: 'Mark read', exact: true }).click();
    await expect(panel.locator('[data-notification-id="9001"] .notification-read-btn')).toHaveCount(0);
    expect(writes).toContain('/api/notifications/9001/read');
    await panel.getByRole('button', { name: 'Resolve', exact: true }).click();
    await expect(panel.locator('.notification-resolve-btn')).toHaveCount(0);
    expect(writes).toContain('/api/notifications/9002/resolve');
    await panel.getByRole('button', { name: 'Mark all read', exact: true }).click();
    await expect(panel.locator('.notification-read-btn')).toHaveCount(0);
    expect(writes).toContain('/api/notifications/read-all');
    await page.keyboard.press('Escape');
    await expect(panel).toBeHidden();
    await expect(bell).toBeFocused();
    expect(errors).toEqual([]);
  });
}

function slotHistoryRows() {
  return [
    { full_name: 'Santos, Maria Elena', student_number: '2026-00128', plate_number: 'ABC 1234', parking_slot: 'H-20', entry_gate: 'Gate 1', parked_at: '2026-10-21T01:00:00Z', exited_at: null, duration_label: '25m', is_ongoing: true },
    { full_name: 'Reyes, Juan Miguel', student_number: '2026-00456', plate_number: 'XYZ 5678', parking_slot: 'H-20', entry_gate: 'Main Gate', parked_at: '2026-10-20T00:15:30Z', exited_at: '2026-10-20T02:45:40Z', duration_label: '2h 30m', is_ongoing: false },
    { full_name: 'History <img src=x onerror=alert(1)>', student_number: 'LONG-STUDENT-NUMBER-2026-REVIEW', plate_number: 'CHECK-123', parking_slot: 'H-20', entry_gate: null, parked_at: null, exited_at: '2026-10-19T02:45:40Z', duration_label: '-', is_ongoing: false }
  ];
}

async function selectHistorySlot(page) {
  await signIn(page, 'admin');
  await page.goto('/admin/slots');
  await page.locator('#parkingSlotSearch').fill('H-20');
  await page.locator('#parkingSlotsList [data-slot-code="H-20"]').click();
  await expect(page.locator('#slotInspectorTitle')).toContainText('H-20');
  await expect(page.locator('#slotInspectorHistory')).not.toContainText('Loading');
}

test('slot history separates entry and exit details and restores focus', async ({ page }, testInfo) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/parking-slot-history?*', route => route.fulfill({ json: { ok: true, rows: slotHistoryRows() } }));
  await selectHistorySlot(page);
  const trigger = page.locator('#openSlotHistoryBtn');
  await trigger.click();
  const modal = page.locator('#slotHistoryModal');
  const dialog = modal.getByRole('dialog');
  const close = dialog.getByRole('button', { name: 'Close slot history' });
  const list = page.locator('#slotHistoryList');
  const cards = list.locator('.slot-history-card');
  await expect(dialog).toHaveAccessibleName('Slot H-20 history');
  await expect(cards).toHaveCount(3);
  await expect(cards.nth(0).locator('.slot-history-status')).toHaveText('Still parked');
  await expect(cards.nth(1).locator('.slot-history-status')).toHaveText('Exited');
  await expect(list).not.toContainText('COMPLETED');
  await expect(cards.nth(0)).toContainText('Awaiting exit');
  await expect(cards.nth(1)).toContainText('Entry gate: Main Gate');
  await expect(cards.nth(1).locator('.slot-history-entry time')).toHaveAttribute('datetime', '2026-10-20T00:15:30.000Z');
  await expect(cards.nth(1).locator('.slot-history-exit time')).toHaveAttribute('datetime', '2026-10-20T02:45:40.000Z');
  await expect(cards.nth(1)).toContainText('2h 30m');
  await expect(cards.nth(2)).toContainText('Not recorded');
  await expect(cards.nth(2).locator('h4')).toHaveText('History <img src=x onerror=alert(1)>');
  await expect(list.locator('img')).toHaveCount(0);
  await expect(list).not.toHaveAttribute('aria-busy');
  await expect(close).toBeFocused();
  await expect(page.locator('.app-shell')).toHaveAttribute('inert', '');
  await dialog.screenshot({ path: testInfo.outputPath('slot-history.png') });
  const audit = await new AxeBuilder({ page }).include('#slotHistoryModal').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) }))).toEqual([]);
  expect(await dialog.evaluate(element => {
    const box = element.getBoundingClientRect();
    return box.left >= 0 && box.right <= innerWidth + 1 && box.top >= 0 && box.bottom <= innerHeight + 1;
  })).toBe(true);
  expect(await list.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await page.keyboard.press('Tab');
  await expect(list).toBeFocused();
  await page.keyboard.press('End');
  await expect.poll(() => list.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
  await expect(close).toBeInViewport();
  await page.keyboard.press('Tab');
  await expect(close).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(list).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
  await expect(page.locator('.app-shell')).not.toHaveAttribute('inert', '');
  await trigger.click();
  await close.click();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await modal.locator('.slot-history-backdrop').click({ position: { x: 3, y: 3 } });
  await expect(dialog).toBeHidden();
  expect(errors).toEqual([]);
});

test('slot history handles empty, failed, and outdated responses', async ({ page }) => {
  let mode = 'empty';
  let delayed;
  await page.route('**/api/parking-slot-history?*', route => {
    if (mode === 'pending') { delayed = route; return; }
    return mode === 'error'
      ? route.fulfill({ status: 500, json: { ok: false, message: 'Please try again later.' } })
      : route.fulfill({ json: { ok: true, rows: [] } });
  });
  await selectHistorySlot(page);
  const trigger = page.locator('#openSlotHistoryBtn');
  const modal = page.locator('#slotHistoryModal');
  const list = page.locator('#slotHistoryList');
  mode = 'pending';
  await trigger.click();
  await expect(list).toHaveAttribute('aria-busy', 'true');
  await expect(list.locator('.ui-skeleton')).toBeVisible();
  await expect(list.locator('.ui-skeleton')).toHaveAttribute('aria-hidden', 'true');
  await expect.poll(() => Boolean(delayed)).toBe(true);
  await page.keyboard.press('Escape');
  mode = 'empty';
  await trigger.click();
  await expect(list).toContainText('No parking history');
  const response = page.waitForResponse('**/api/parking-slot-history?*');
  await delayed.fulfill({ json: { ok: true, rows: slotHistoryRows() } });
  await (await response).finished();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(list).toContainText('No parking history');
  await expect(list.locator('.slot-history-card')).toHaveCount(0);
  await page.keyboard.press('Escape');
  mode = 'error';
  await trigger.click();
  await expect(list).toContainText('Please try again later.');
  await expect(list).not.toHaveAttribute('aria-busy');
  await expect(modal.locator('#slotHistoryMeta')).toHaveText('History unavailable');
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
});

test('key pages fit the screen and have no serious accessibility violations', async ({ page }) => {
  test.setTimeout(150_000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  for (const [role, paths] of [['admin', ['/admin', '/admin/slots', '/students', '/students#directory', '/visitor-passes', '/stickers', '/reports']], ['guard', ['/guard', '/visitor-passes', '/scanner', '/scanner/auto?mode=remote']]]) {
    await signIn(page, role);
    for (const path of paths) {
      await page.goto(path);
      if (path.startsWith("/scanner/auto")) await expect(page.locator("#chipCameraState")).toHaveText("Camera Ready");
      const violations = (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations.filter(item => ['serious', 'critical'].includes(item.impact));
      expect(violations.map(item => ({ id: item.id, targets: item.nodes.map(node => ({ target: node.target, summary: node.failureSummary })) })), path).toEqual([]);
      expect(await page.evaluate(() => [...document.querySelectorAll('main > *,main .panel,main .reg-panel,main .directory-panel')].filter(element => {
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && (rect.right > innerWidth + 1 || rect.left < -1);
      }).map(element => element.className)), path).toEqual([]);
    }
  }
  expect(errors).toEqual([]);
});

test('parking map and table share filters, types, selection, and history', async ({ page }, testInfo) => {
  const slots = [
    { id: 9001, slot_code: 'A-01', zone: 'Basketball Area Parking', slot_type: 'standard', occupancy: 'available', status: 'available' },
    { id: 9002, slot_code: 'A-02', zone: 'Basketball Area Parking', slot_type: 'standard', occupancy: 'occupied', status: 'available', occupied_by_plate: 'REVIEW-123' },
    { id: 9003, slot_code: 'H-01', zone: 'Hangar Parking Zone', slot_type: 'reserved', occupancy: 'available', status: 'available', reserved_for: 'Faculty' },
    { id: 9004, slot_code: 'H-02', zone: 'Hangar Parking Zone', slot_type: 'reserved', occupancy: 'disabled', status: 'disabled', disabled_reason: 'School event' }
  ];
  await page.route('**/api/parking-slot-overview', route => route.fulfill({ json: { ok: true, slots, summary: { total: 4, available: 2, occupied: 1, disabled: 1 } } }));
  await page.route('**/api/parking-slot-history?*', route => route.fulfill({ json: { ok: true, rows: [] } }));
  await signIn(page, 'admin');
  await page.goto('/admin/slots');
  await page.locator('#slotsRefreshBtn').click();
  await expect(page.locator('#slotMetricTotal')).toHaveText('4');
  const map = page.locator('#parkingSlotsList');
  const table = page.locator('#parkingSlotsTableRegion');
  await expect(map.locator('[data-slot-code="H-02"] .parking-plan-state')).toHaveText('Blocked');
  await expect(map.locator('[data-slot-code="H-01"]')).toContainText('Reserved');
  await page.getByRole('button', { name: 'Table', exact: true }).click();
  await expect(map).toBeHidden();
  await expect(table).toBeVisible();
  await expect(table.locator('tbody tr')).toHaveCount(4);
  await page.locator('[data-slot-filter="reserved"]').click();
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await expect(table).toContainText('Available');
  await expect(table).toContainText('Blocked');
  await expect(table).toContainText('Faculty');
  await page.locator('#parkingSlotSearch').fill('H-02');
  await expect(table.locator('tbody tr')).toHaveCount(1);
  await table.getByRole('button', { name: 'View H-02' }).click();
  await expect(page.locator('#slotInspectorTitle')).toHaveText('H-02');
  await expect(page.locator('#slotInspectorStatus')).toHaveText('Blocked');
  await expect(page.locator('#slotEditorState')).toHaveValue('disabled');
  await page.locator('#openSlotHistoryBtn').click();
  await expect(page.getByRole('dialog', { name: 'Slot H-02 history' })).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Map', exact: true }).click();
  await expect(map.locator('[data-slot-code]')).toHaveCount(1);
  await expect(map.locator('[data-slot-code="H-02"]')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#parkingSlotSearch').fill('NO-MATCH');
  await expect(map).toContainText('No slots match');
  await page.locator('#parkingSlotSearch').fill('');
  await page.locator('[data-slot-filter="all"]').click();
  await page.getByRole('button', { name: 'Table', exact: true }).click();
  await expect(table.locator('tbody tr')).toHaveCount(4);
  await table.scrollIntoViewIfNeeded();
  await page.screenshot({ path: testInfo.outputPath('parking-table.png') });
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) }))).toEqual([]);
});

test('student tabs support keyboard navigation and retain the selected section', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/students');
  const register = page.getByRole('tab', { name: 'Register student' });
  const directory = page.getByRole('tab', { name: 'Student directory' });
  await register.focus();
  await page.keyboard.press('ArrowRight');
  await expect(directory).toBeFocused();
  await expect(directory).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel', { name: 'Student directory' })).toBeVisible();
  await expect(page.getByRole('tabpanel', { name: 'Register student' })).toBeHidden();
  await page.reload();
  await expect(directory).toHaveAttribute('aria-selected', 'true');
  await directory.focus();
  await page.keyboard.press('Home');
  await expect(register).toBeFocused();
  await page.goto('/students#directory');
  await expect(directory).toHaveAttribute('aria-selected', 'true');
});

test('phone navigation opens, traps focus, closes, and restores focus with reduced motion', async ({ page }, testInfo) => {
  test.skip(!testInfo.project.name.includes('phone'), 'Phone drawer only.');
  await signIn(page, 'guard');
  await page.goto('/guard');
  const sidebar = page.locator('#mobileSidebar');
  const trigger = page.getByRole('button', { name: 'Open navigation', exact: true });
  await expect(sidebar).toBeHidden();
  await expect(sidebar).toHaveAttribute('inert', '');
  await trigger.click();
  await expect(sidebar).toBeVisible();
  const close = page.locator('#mobileNavClose');
  await expect(close).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(sidebar.getByRole('link', { name: 'Visitor Passes' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(close).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(sidebar).toBeHidden();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await sidebar.getByRole('link', { name: 'Manual Lookup' }).click();
  await expect(page).toHaveURL(/\/scanner$/);
  await expect(sidebar).toBeHidden();
  await trigger.click();
  await expect(sidebar.getByRole('link', { name: 'Manual Lookup' })).toHaveAttribute('aria-current', 'page');
  await page.setViewportSize({ width: 1280, height: 900 });
  await expect(sidebar).not.toHaveAttribute('inert', '');
  await expect(page.locator('.content-area')).not.toHaveAttribute('inert', '');
});

test('phone scanner actions and camera are visible without scrolling', async ({ page }, testInfo) => {
  test.skip(!testInfo.project.name.includes('phone'), 'Phone layout only.');
  await signIn(page, 'guard');
  await page.goto('/guard');
  await expect(page.locator('.hero-primary-action')).toBeInViewport();
  await page.locator('.hero-primary-action').click();
  await expect(page.locator('#autoQrReader video')).toBeVisible();
  expect(await page.locator('#autoCameraWrapper').evaluate(element => element.getBoundingClientRect().top)).toBeLessThan(520);
  await expect(page.locator('#autoGateSelect')).toBeInViewport();
  await expect(page.locator('#toggleAutoCameraBtn')).toBeInViewport();
  expect(await page.locator('#autoGateSelect').evaluate(element => parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(16);
});

test('directory search, optional filters and import controls stay usable', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/students#directory');
  const filters = page.locator('.directory-advanced-filters');
  await expect(filters).not.toHaveAttribute('open', '');
  await expect(page.locator('#studentSearch')).toBeInViewport();
  const name = await page.locator('.sc-name').first().innerText();
  await page.locator('#studentSearch').fill(name);
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.locator('#studentSearch')).toHaveValue(name);
  await expect(filters).not.toHaveAttribute('open', '');
  expect(await page.locator('.sc-name').allTextContents()).toEqual(expect.arrayContaining([name]));
  expect((await page.locator('.sc-name').allTextContents()).every(value => value.toLowerCase().includes(name.toLowerCase()))).toBeTruthy();
  await filters.locator('summary').click();
  await page.locator('#directorySort').selectOption('name');
  await page.locator('#directoryDirection').selectOption('asc');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.locator('#directorySort')).toHaveValue('name');
  await expect(page.locator('#directoryDirection')).toHaveValue('asc');
  await page.getByRole('link', { name: 'Clear filters', exact: true }).click();
  await expect(page.locator('#studentSearch')).toHaveValue('');
  await expect(filters).not.toHaveAttribute('open', '');
  await filters.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#directoryCourse')).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page.locator('#directoryCourse')).toBeHidden();
  await page.locator('#studentImportToggle').click();
  await expect(page.getByRole('link', { name: 'Download CSV template' })).toBeVisible();
  await page.locator('#studentImportClose').click();
  await expect(page.locator('#studentImportPanel')).toBeHidden();
  const card = page.locator('.student-card').first();
  await card.getByRole('button', { name: 'Details', exact: true }).click();
  await expect(card.locator('.sc-vehicles')).toBeVisible();
});

test('desktop student values align with their column headings', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.includes('phone'), 'Desktop columns only.');
  await signIn(page, 'admin');
  await page.goto('/students#directory');
  const layout = await page.evaluate(() => {
    const row = document.querySelector('.student-card');
    const headings = [...document.querySelectorAll('.student-directory-columns > span')];
    const cells = [row.querySelector('.sc-meta'), ...[...row.querySelectorAll('.sc-info-row > .sc-info-item')].filter(cell => cell.getBoundingClientRect().width > 0), row.querySelector('.sc-header-actions')];
    return cells.map((cell, index) => {
      const rect = cell.getBoundingClientRect();
      const heading = headings[index].getBoundingClientRect();
      return { offset: Math.abs(rect.left - heading.left), overflow: rect.right - heading.right };
    });
  });
  expect(layout).toHaveLength(6);
  for (const cell of layout) {
    expect(cell.offset).toBeLessThanOrEqual(2);
    expect(cell.overflow).toBeLessThanOrEqual(2);
  }
});

test('sign-in works with readable phone fields and password visibility control', async ({ page }) => {
  await page.goto('/login');
  await expect(page.locator('.login-form')).toHaveCSS('opacity', '1');
  await expect(page.locator('.login-btn')).toBeInViewport();
  await page.getByLabel('Username', { exact: true }).fill(process.env.ADMIN_USERNAME);
  await page.locator('#password').fill(process.env.ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Show password', exact: true }).click();
  await expect(page.locator('#password')).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Hide password', exact: true }).click();
  await expect(page.locator('#password')).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
});

test('registration explains errors and excludes a removed optional vehicle', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/students');
  const form = page.locator('#regForm');
  await expect(form).toHaveAttribute('novalidate', '');
  let submitted;
  await page.route('**/students', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    submitted = new URLSearchParams(route.request().postData());
    return route.fulfill({ status: 303, headers: { location: '/students?success=1' } });
  });
  await form.locator('[type="submit"]').click();
  await expect(form.locator('.form-error-summary')).toContainText('these 4 fields');
  await expect(page.locator('#s_student_number')).toBeFocused();
  expect(submitted).toBeUndefined();
  await page.locator('#s_student_number').fill('FRIENDLY-REVIEW');
  await page.locator('#s_full_name').fill('Interface Review');
  await page.locator('#s_program').selectOption({ index: 1 });
  await page.locator('#s_year_level').selectOption('1');
  await page.locator('#s_email').fill('invalid-email');
  await form.locator('[type="submit"]').click();
  await expect(page.locator('#s_email-error')).toContainText('complete email address');
  await expect(page.locator('#s_full_name')).toHaveValue('Interface Review');
  await page.locator('#s_email').fill('review@example.invalid');
  await page.locator('#vehicleToggle').click();
  await expect(page.locator('#v_plate')).toBeFocused();
  await page.locator('#v_plate').fill('REMOVE-123');
  await page.locator('#vehicleToggle').click();
  await expect(page.locator('#v_plate')).toBeDisabled();
  await expect(page.locator('#vehicleToggle')).toHaveAttribute('aria-expanded', 'false');
  await form.locator('[type="submit"]').click();
  await expect(page).toHaveURL(/success=1/);
  expect(submitted.get('full_name')).toBe('Interface Review');
  expect(submitted.has('plate_number')).toBe(false);
});

test('password guidance and matching validation keep mistakes on the form', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/account/security');
  const form = page.locator('form[action="/account/password"]');
  await expect(form).toHaveAttribute('novalidate', '');
  await page.locator('#current_password').fill('TestCurrentAccess2026');
  await page.locator('#new_password').fill('adminPassword123');
  await page.locator('#confirm_password').fill('DifferentAccess2026');
  await form.locator('[type="submit"]').click();
  await expect(page.locator('#new_password-error')).toContainText('predictable words');
  await expect(page.locator('#confirm_password-error')).toContainText('do not match');
  await expect(page.locator('#current_password')).toHaveValue('TestCurrentAccess2026');
  await page.locator('#new_password').fill('PrivateAccess2026');
  await page.locator('#confirm_password').fill('PrivateAccess2026');
  await expect(form.locator('.form-error-summary')).toBeHidden();
  await expect(form.locator('.password-requirements .is-met')).toHaveCount(5);
  await page.getByRole('button', { name: 'Show new password', exact: true }).click();
  await expect(page.locator('#new_password')).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Hide new password', exact: true }).click();
  await expect(page.locator('#new_password')).toHaveAttribute('type', 'password');
  await expect(form).not.toHaveAttribute('data-loading', 'true');
  const violations = (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations;
  expect(violations.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) }))).toEqual([]);
});

test('visitor forms reject an end time before the start without losing details', async ({ page }) => {
  await signIn(page, 'guard');
  await page.goto('/visitor-passes');
  const form = page.locator('#visitorRegisterForm');
  await expect(form).toHaveAttribute('novalidate', '');
  await form.locator('[name="visitor_name"]').fill('Visitor Review');
  await page.locator('#visitorValidFrom').fill('2026-10-01T12:00');
  await page.locator('#visitorValidUntil').fill('2026-10-01T11:00');
  await form.locator('[type="submit"]').click();
  await expect(page.locator('#visitorValidUntil-error')).toContainText('after the start time');
  await expect(form.locator('[name="visitor_name"]')).toHaveValue('Visitor Review');
  await expect(form).not.toHaveAttribute('data-loading', 'true');
});

test('backup downloads leave the page usable for another action', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/admin/data');
  await page.route('**/admin/data/backup', route => route.fulfill({
    status: 200, contentType: 'application/octet-stream',
    headers: { 'content-disposition': 'attachment; filename="test.naapbackup"' }, body: 'test-download'
  }));
  await page.locator('#backupPassphrase').fill('ReviewPassphrase2026');
  await page.locator('#backupPassphraseConfirmation').fill('ReviewPassphrase2026');
  const form = page.locator('.backup-create-form');
  for (let attempt = 0; attempt < 2; attempt++) {
    const download = page.waitForEvent('download');
    await form.locator('[type="submit"]').click();
    expect((await download).suggestedFilename()).toBe('test.naapbackup');
    await expect(form).not.toHaveAttribute('data-loading', 'true');
    await expect(page.locator('body')).not.toHaveClass(/page-transitioning/);
  }
});


// Render the same partial used by the visitor queue with an isolated fixture.
// Intercept mutations so confirmation tests cannot approve or reject real passes.
async function visitorActionFixture(page) {
  const ejs = require('ejs');
  const path = require('node:path');
  const actions = await ejs.renderFile(path.join(__dirname, '../views/partials/visitor_pass_actions.ejs'), {
    pass: { id: 999999999, visitor_name: 'Example Visitor', approval_status: 'PENDING', pass_state: 'PENDING', pass_code: 'UI-REVIEW' },
    inQueue: true, currentRole: 'admin'
  });
  await page.route('**/visitor-passes', async route => {
    const response = await route.fetch();
    const body = (await response.text()).replace('</main>', '<section class="panel" id="reviewVisitorActions"><h2>Example visitor request</h2><div class="visitor-pending-actions record-actions">' + actions + '</div></section></main>');
    await route.fulfill({ response, body });
  });
  const submissions = [];
  await page.route('**/visitor-passes/999999999/*', async route => {
    submissions.push({ url: route.request().url(), body: route.request().postData() || '' });
    await route.fulfill({ status: 200, contentType: 'text/html', body: '<main>Saved test response</main>' });
  });
  await page.goto('/visitor-passes');
  return { actions: page.locator('#reviewVisitorActions'), submissions };
}

test('visitor confirmations support keyboard cancellation and preserve the optional reason', async ({ page }) => {
  await signIn(page, 'admin');
  const { actions, submissions } = await visitorActionFixture(page);
  const nativeDialogs = [];
  page.on('dialog', async dialog => { nativeDialogs.push(dialog.type()); await dialog.dismiss(); });
  const reject = actions.getByRole('button', { name: 'Reject pass', exact: true });
  await reject.click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Reject visitor pass?');
  await expect(dialog.getByRole('button', { name: 'Go back' })).toBeFocused();
  await expect(page.locator('.app-shell')).toHaveAttribute('inert', '');
  await page.keyboard.press('Shift+Tab');
  await expect(page.locator('#confirmDialogNote')).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(dialog.getByRole('button', { name: 'Reject pass', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#confirmDialogNote')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(reject).toBeFocused();
  await expect(page.locator('.app-shell')).not.toHaveAttribute('inert', '');
  await expect(page.locator('body')).not.toHaveClass(/page-transitioning/);
  expect(submissions).toHaveLength(0);
  await reject.click();
  await page.locator('#confirmDialogNote').fill('  Duplicate request  ');
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.filter(item => ['serious', 'critical'].includes(item.impact))).toEqual([]);
  await dialog.getByRole('button', { name: 'Reject pass', exact: true }).click();
  await expect(page.getByText('Saved test response')).toBeVisible();
  expect(submissions).toHaveLength(1);
  expect(new URLSearchParams(submissions[0].body).get('approval_note')).toBe('Duplicate request');
  expect(nativeDialogs).toEqual([]);
});

test('visitor approval and cancellation use matching action labels and distinct tones', async ({ page }) => {
  await signIn(page, 'admin');
  const { actions, submissions } = await visitorActionFixture(page);
  await actions.getByRole('button', { name: 'Cancel pass', exact: true }).click();
  let dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Cancel visitor pass?');
  await expect(dialog.getByRole('button', { name: 'Cancel pass', exact: true })).toBeVisible();
  await expect(page.locator('#confirmDialogNote')).toBeHidden();
  await dialog.getByRole('button', { name: 'Go back' }).click();
  expect(submissions).toHaveLength(0);
  await actions.getByRole('button', { name: 'Approve pass', exact: true }).click();
  dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Approve visitor pass?');
  await expect(page.locator('#confirmDialog')).toHaveAttribute('data-tone', 'primary');
  await dialog.getByRole('button', { name: 'Approve pass', exact: true }).click();
  await expect(page.getByText('Saved test response')).toBeVisible();
  expect(submissions).toHaveLength(1);
  expect(submissions[0].url).toMatch(/\/approve$/);
});

test('account confirmations return focus and never sign out on cancellation', async ({ page }) => {
  await signIn(page, 'admin');
  await signIn(page, 'admin'); // Ensure there is another device session to display.
  await page.goto('/account/security');
  const signOut = page.getByRole('button', { name: 'Sign out device', exact: true }).first();
  await expect(signOut).toBeVisible();
  await signOut.click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Sign out this device?');
  await expect(dialog.getByRole('button', { name: 'Go back' })).toBeFocused();
  await expect(dialog.getByRole('button', { name: 'Sign out device', exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: 'Go back' }).click();
  await expect(signOut).toBeFocused();
  await expect(page).toHaveURL(/\/account\/security$/);
  await expect(page.locator('body')).not.toHaveClass(/page-transitioning/);
});

test('primary form actions share sizing and align with their forms', async ({ page }) => {
  await signIn(page, 'admin');
  for (const [route, name] of [['/students', 'Register student'], ['/visitor-passes', 'Request visitor pass'], ['/admin/slots', 'Add parking space'], ['/admin/users', 'Create account'], ['/account/security', 'Change password']]) {
    await page.goto(route);
    const button = page.getByRole('button', { name, exact: true });
    await expect(button).toBeVisible();
    const layout = await button.evaluate(element => {
      const rect = element.getBoundingClientRect();
      const form = element.closest('form').getBoundingClientRect();
      return { height: rect.height, font: getComputedStyle(element).fontSize, left: Math.abs(rect.left - form.left) };
    });
    expect(layout.height, route).toBeGreaterThanOrEqual(44);
    expect(layout.font, route).toBe('14px');
    expect(layout.left, route).toBeLessThan(2);
  }
});


test('account deletion confirmation returns focus to the closed actions menu', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/admin/users');
  const menu = page.locator('.action-menu').first();
  const trigger = menu.locator('[data-action-menu-trigger]');
  await trigger.click();
  await menu.getByRole('menuitem', { name: 'Delete account', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Delete account?');
  await expect(dialog.getByRole('button', { name: 'Delete account', exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: 'Go back' }).click();
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('body')).not.toHaveClass(/page-transitioning/);
});


test('QR controls have consistent gaps and access-changing actions remain separated', async ({ page }, testInfo) => {
  await signIn(page, 'admin');
  await page.goto('/stickers');
  const desktop = !testInfo.project.name.includes('phone');
  const tools = desktop ? page.locator('.sticker-tools').first() : page.locator('.mobile-button-grid:visible').first();
  await expect(tools).toBeVisible();
  const rects = await tools.locator('button, a').evaluateAll(elements => elements.map(element => {
    const r = element.getBoundingClientRect(); return { left:r.left, right:r.right, top:r.top, bottom:r.bottom, height:r.height };
  }));
  for (let i=0; i<rects.length; i++) {
    expect(rects[i].height).toBeGreaterThanOrEqual(44);
    for (let j=i+1; j<rects.length; j++) {
      const a=rects[i], b=rects[j];
      expect(a.right+7 <= b.left || b.right+7 <= a.left || a.bottom+7 <= b.top || b.bottom+7 <= a.top).toBe(true);
    }
  }
  const management = page.locator('.sticker-management-actions:visible').first();
  const replace = await tools.getByRole('button', { name: 'Replace QR', exact: true }).boundingBox();
  const revoke = await management.getByRole('button', { name: 'Revoke sticker', exact: true }).boundingBox();
  expect(revoke.x >= replace.x + replace.width + 7 || revoke.y >= replace.y + replace.height + 10).toBe(true);
  if (desktop) {
    await page.setViewportSize({ width:1200, height:900 });
    await expect(page.locator('.desktop-only-table')).toBeHidden();
    await expect(page.locator('.mobile-data-list')).toBeVisible();
  }
});

test('QR email controls are removed and QR downloads and print cards remain available', async ({ page }) => {
  await signIn(page, 'admin');
  await page.goto('/stickers');
  await expect(page.locator('[data-email-preview], #emailPreviewModal, #email-deliveries')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Email QR', exact: true })).toHaveCount(0);
  const qrLink = page.getByRole('link', { name: 'View QR', exact: true }).first();
  const qrResponse = await page.request.get(await qrLink.getAttribute('href'));
  expect(qrResponse.status()).toBe(200);
  expect(qrResponse.headers()['content-type']).toContain('image/png');
  const printLink = page.getByRole('link', { name: 'Print card', exact: true }).first();
  expect((await page.request.get(await printLink.getAttribute('href'))).status()).toBe(200);
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
  expect(audit.violations.filter(item => ['serious','critical'].includes(item.impact))).toEqual([]);
});

for (const [path, endpoint, buttonId, metricId, statusId, result] of [
  ['/admin', '/api/dashboard-stats', 'refreshInsideBtn', 'metricStudents', 'insideLastUpdated', { ok: true, metrics: { students: 7 }, insideVehicles: [], overstayAlerts: [] }],
  ['/admin/slots', '/api/parking-slot-overview', 'slotsRefreshBtn', 'slotMetricTotal', 'slotsLastUpdated', { ok: true, slots: [], summary: { total: 0, available: 0, occupied: 0, disabled: 0 } }]
]) {
  test(`refresh feedback preserves data and supports retry on ${path}`, async ({ page }) => {
    let mode = 'pending';
    let pending;
    await page.route('**' + endpoint, route => {
      if (mode === 'pending') { pending = route; return; }
      return route.fulfill({ json: result });
    });
    await signIn(page, 'admin');
    await page.goto(path);
    const button = page.locator('#' + buttonId);
    const metric = page.locator('#' + metricId);
    const initialValue = await metric.textContent();
    await button.click();
    await expect(button).toBeDisabled();
    await expect(button).toHaveAttribute('aria-busy', 'true');
    await expect.poll(() => Boolean(pending)).toBe(true);
    await pending.fulfill({ status: 503, json: { ok: false } });
    await expect(button).toBeEnabled();
    await expect(metric).toHaveText(initialValue);
    await expect(page.locator('#' + statusId)).toHaveText('Update failed · showing previous data');
    const errorToast = page.locator('.ui-toast-error');
    await expect(errorToast.getByRole('alert')).toContainText('try Refresh again');
    const audit = await new AxeBuilder({ page }).include('.ui-toast-stack').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(audit.violations.map(item => item.id)).toEqual([]);
    await errorToast.getByRole('button', { name: 'Dismiss message' }).click();
    await expect(errorToast).toHaveCount(0);
    mode = 'success';
    await button.click();
    await expect(page.locator('.ui-toast-success')).toContainText('updated');
    await expect(page.locator('#' + statusId)).toHaveClass(/is-current/);
    await expect(metric).toHaveText(path === '/admin' ? '7' : '0');
    await page.evaluate(() => window.NaapFeedback.show('<img src=x onerror=alert(1)>', { tone: 'info' }));
    await expect(page.locator('.ui-toast-info')).toContainText('<img src=x onerror=alert(1)>');
    await expect(page.locator('.ui-toast-info img')).toHaveCount(0);
  });
}

test('parking form keeps required-field errors inline without submitting', async ({ page }) => {
  let submitted = false;
  await signIn(page, 'admin');
  await page.goto('/admin/slots');
  page.on('request', request => { if (request.method() === 'POST' && new URL(request.url()).pathname === '/admin/slots') submitted = true; });
  const form = page.locator('.parking-space-form');
  await form.getByRole('button', { name: 'Add parking space' }).click();
  await expect(form.locator('.form-error-summary')).toBeVisible();
  await expect(page.locator('#newSlotCode')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#newSlotCode')).toBeFocused();
  await expect(form.locator('.form-field-error:visible')).toHaveCount(2);
  await page.locator('#newSlotCode').fill('REVIEW-ONLY');
  await expect(page.locator('#newSlotCode')).not.toHaveAttribute('aria-invalid');
  expect(submitted).toBe(false);
});

test('tablet layouts keep key pages within the viewport', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.includes('phone'), 'Tablet coverage uses the desktop browser.');
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 768, height: 1024 });
  for (const [role, paths] of [['admin', ['/admin', '/admin/slots', '/students#directory', '/visitor-passes']], ['guard', ['/guard', '/scanner/auto?mode=remote']]]) {
    await signIn(page, role);
    for (const path of paths) {
      await page.goto(path);
      if (path.includes('/scanner/auto')) await expect(page.locator('#chipCameraState')).toHaveText('Camera Ready');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), path).toBe(true);
      const violations = (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations;
      expect(violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) })), path).toEqual([]);
    }
  }
});

test('scan-result presentation keeps explicit statuses and accessible contrast', async ({ page }, testInfo) => {
  await signIn(page, 'guard');
  await page.goto('/scanner/auto?mode=remote');
  await expect(page.locator('#chipCameraState')).toHaveText('Camera Ready');
  await page.locator('#toggleAutoCameraBtn').click();
  const card = page.locator('#autoResultCard');
  // Exercise presentation states only; QR eligibility remains covered by scanner tests.
  for (const [state, title, message] of [
    ['success', 'EXIT recorded', 'Exit recorded at Gate 4.'],
    ['invalid', 'Unauthorized (INVALID)', 'The vehicle QR could not be verified.'],
    ['invalid', 'Unauthorized (EXPIRED)', 'This vehicle sticker has expired.'],
    ['warning', 'Scan paused', 'Wait before scanning the same vehicle again.']
  ]) {
    await card.evaluate((element, data) => {
      element.className = `auto-result-card state-${data.state}`;
      element.querySelector('h3').textContent = data.title;
      element.querySelector('#autoResultMessage').textContent = data.message;
    }, { state, title, message });
    await card.scrollIntoViewIfNeeded();
    await expect(card).toHaveAttribute('aria-live', 'polite');
    await expect(card.getByRole('heading')).toHaveText(title);
    const audit = await new AxeBuilder({ page }).include('#autoResultCard').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) })), title).toEqual([]);
  }
  await card.screenshot({ path: testInfo.outputPath('scan-result.png') });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.evaluate(() => window.NaapFeedback.show('Display check.', { tone: 'success' }));
  expect(await page.locator('.ui-toast').evaluate(element => getComputedStyle(element).animationDuration)).toBe('0.18s');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  expect(await page.locator('.ui-toast').evaluate(element => getComputedStyle(element).animationName)).toBe('none');
});
