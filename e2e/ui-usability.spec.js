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
