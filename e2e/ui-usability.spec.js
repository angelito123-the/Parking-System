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

test('key pages fit the screen and have no serious accessibility violations', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  for (const [role, paths] of [['admin', ['/admin', '/students', '/students#directory', '/reports']], ['guard', ['/guard', '/scanner', '/scanner/auto?mode=remote']]]) {
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
  await page.getByRole('link', { name: 'Reset', exact: true }).click();
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
