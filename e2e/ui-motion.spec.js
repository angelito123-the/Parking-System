const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

async function signIn(page) {
  const origin = test.info().project.use.baseURL || process.env.E2E_BASE_URL;
  const response = await page.request.post(origin + '/login', {
    headers: { origin }, form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD }, maxRedirects: 0
  });
  expect(response.headers().location).toBe('/admin');
}

test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => localStorage.setItem('theme', theme), info.project.name.includes('dark') ? 'dark' : 'light');
});

test('native sign-in shows pending state and only confirms the server redirect', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let pending;
  let busyState;
  await page.exposeFunction('captureLoginBusy', state => { busyState = state; });
  await page.route('**/login', route => {
    if (route.request().method() === 'POST') { pending = route; return; }
    return route.continue();
  });
  await page.goto('/login');
  const logo = await page.locator('.brand-logo').getAttribute('src');
  await page.getByLabel('Username', { exact: true }).fill(process.env.ADMIN_USERNAME);
  await page.getByLabel('Password', { exact: true }).fill(process.env.ADMIN_PASSWORD);
  await page.evaluate(() => {
    document.querySelector('.login-form').addEventListener('submit', () => {
      const button = document.querySelector('.login-btn');
      window.captureLoginBusy({
        disabled: button.disabled,
        spinner: getComputedStyle(button.querySelector('.button-spinner')).display !== 'none',
        check: getComputedStyle(button.querySelector('.button-success')).display !== 'none',
        label: button.querySelector('.button-label').textContent
      });
    });
    window.addEventListener('pageswap', event => {
      sessionStorage.setItem('motion-test-outgoing', JSON.stringify({
        target: event.activation?.entry?.url,
        success: document.querySelector('.login-btn').classList.contains('is-success'),
        check: getComputedStyle(document.querySelector('.button-success')).display !== 'none'
      }));
    });
  });
  // Do not wait for navigation while the real native request is deliberately held.
  await page.getByRole('button', { name: 'Sign in', exact: true }).click({ noWaitAfter: true });
  await expect.poll(() => Boolean(pending)).toBe(true);
  expect(pending.request().isNavigationRequest()).toBe(true);
  // The submit listener records state before the browser starts its native navigation.
  await expect.poll(() => busyState).toEqual({ disabled: true, spinner: true, check: false, label: 'Signing in' });
  await pending.continue();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.locator('.sidebar-brand-mark img')).toHaveAttribute('src', logo);
  const outgoing = await page.evaluate(() => JSON.parse(sessionStorage.getItem('motion-test-outgoing')));
  expect(new URL(outgoing.target).pathname).toBe('/admin');
  expect(outgoing.success).toBe(true);
  expect(outgoing.check).toBe(true);
  await expect(page.locator('.ui-toast-success')).toContainText('Signed in successfully.');
  await page.screenshot({ path: info.outputPath('dashboard-motion.png'), animations: 'disabled' });
  expect(errors).toEqual([]);
});

test('server login errors keep the form usable and respect reduced motion', async ({ page }, info) => {
  await page.goto('/login');
  await page.getByLabel('Username', { exact: true }).fill('motion-review-nonexistent');
  await page.getByLabel('Password', { exact: true }).fill('Invalid-review-password');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('.login-error')).toBeVisible();
  await expect(page.locator('.login-btn')).toBeEnabled();
  await expect(page.locator('.button-success')).toBeHidden();
  await expect(page.locator('.login-btn')).toHaveCSS('animation-name', info.project.name === 'motion-reduced' ? 'none' : 'loginErrorShake');
  await expect(page.locator('#username')).toHaveValue('motion-review-nonexistent');
  await page.locator('#username').focus();
  await expect(page.locator('.input-wrap').first()).toHaveCSS('position', 'relative');
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) }))).toEqual([]);
});

test('metric sparklines use actual readings and refresh feedback retains existing values', async ({ page }, info) => {
  let pending;
  await page.route('**/api/dashboard-stats', route => { pending = route; });
  await signIn(page);
  await page.goto('/admin');
  await expect(page.locator('.metric-sparkline')).toHaveCount(4);
  await expect(page.locator('.metric-icon-tile')).toHaveCount(4);
  await expect(page.locator('.metric-sparkline').first()).toHaveAttribute('aria-label', /^1 reading this visit:/);
  await expect(page.locator('.metric-sparkline polyline').first()).toHaveAttribute('points', '');
  await expect(page.locator('#metricStudents .sr-only')).toHaveCount(0);
  const before = await page.locator('#metricStudents').textContent();
  await page.locator('#refreshInsideBtn').click();
  await expect(page.locator('#overviewLoading')).toBeVisible();
  await expect(page.locator('#metricStudents')).toHaveText(before);
  await expect(page.locator('.dashboard-refresh-icon')).toHaveCSS('animation-name', info.project.name === 'motion-reduced' ? 'none' : 'ui-rotate');
  await expect.poll(() => Boolean(pending)).toBe(true);
  await pending.fulfill({ json: { ok: true, metrics: { students: 30, vehicles: 40, currentlyInside: 7, overstayAlerts: 2 }, insideVehicles: [], overstayAlerts: [] } });
  await expect(page.locator('#overviewLoading')).toBeHidden();
  await expect(page.locator('#metricStudents')).toHaveText('30');
  await expect(page.locator('#metricVehicles')).toHaveText('40');
  await expect(page.locator('[data-motion-metric="overstay"]')).toHaveClass(/has-alerts/);
  await expect(page.locator('.metric-sparkline').first()).toHaveAttribute('aria-label', /^2 readings this visit: .*, 30\./);
  expect((await page.locator('.metric-sparkline polyline').first().getAttribute('points')).split(' ')).toHaveLength(2);
  await expect(page.locator('#insideLastUpdated')).toContainText('Last updated:');
  pending = null;
  await page.locator('#refreshInsideBtn').click();
  await expect(page.locator('#overviewLoading')).toBeVisible();
  await expect.poll(() => Boolean(pending)).toBe(true);
  await pending.fulfill({ status: 503, json: { ok: false } });
  await expect(page.locator('#overviewLoading')).toBeHidden();
  await expect(page.locator('#metricStudents')).toHaveText('30');
  await expect(page.locator('.metric-sparkline').first()).toHaveAttribute('aria-label', /^2 readings this visit:/);
  await expect(page.locator('#insideLastUpdated')).toContainText('showing previous data');
  await expect(page.locator('.ui-toast-error')).toBeVisible();
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.failureSummary) }))).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test('navigation, theme transitions and mobile collapse preserve keyboard controls', async ({ page }, info) => {
  await signIn(page);
  await page.goto('/admin');
  await page.locator('#accountMenuButton').click();
  const toggle = page.locator('#themeToggle');
  const oldTheme = await page.locator('html').getAttribute('data-theme');
  await toggle.click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', oldTheme === 'dark' ? 'light' : 'dark');
  await expect(toggle).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('#accountMenuButton')).toBeFocused();
  if (page.viewportSize().width <= 1080) {
    await page.locator('#mobileNavTrigger').click();
    await expect(page.locator('#mobileNavClose')).toBeFocused();
    await page.locator('#mobileSidebar a[href="/students"]').click();
    await expect(page).toHaveURL(/\/students$/);
    await page.locator('#mobileNavTrigger').click();
    await page.keyboard.press('Escape');
    await expect(page.locator('#mobileNavTrigger')).toBeFocused();
    await expect(page.locator('#mobileSidebar')).toBeHidden();
    await expect(page.locator('#mobileSidebar')).toHaveAttribute('inert', '');
  } else {
    await page.locator('#mobileSidebar a[href="/students"]').click();
    await expect(page.locator('.side-nav a[aria-current="page"]')).toHaveText('Students');
    await expect(page.locator('.side-nav a[aria-current="page"]')).toHaveClass(/nav-motion-arrive/);
  }
  if (info.project.name === 'motion-reduced') {
    expect(await page.evaluate(() => document.getAnimations().filter(animation => animation.playState === 'running').length)).toBe(0);
  }
});

test('low-power devices and unavailable session storage keep the native UI usable', async ({ page }, info) => {
  test.skip(info.project.name !== 'motion-desktop', 'One capability fallback check is sufficient.');
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'hardwareConcurrency', { value: 2 });
    const get = Storage.prototype.getItem;
    const set = Storage.prototype.setItem;
    Storage.prototype.getItem = function (key) { if (this === sessionStorage) throw new DOMException('Unavailable', 'SecurityError'); return get.call(this, key); };
    Storage.prototype.setItem = function (key, value) { if (this === sessionStorage) throw new DOMException('Unavailable', 'SecurityError'); return set.call(this, key, value); };
  });
  await page.goto('/login');
  await expect(page.locator('body')).toHaveClass(/motion-lite/);
  await expect(page.locator('.brand-orb--one')).toHaveCSS('animation-name', 'none');
  await page.getByLabel('Username', { exact: true }).fill(process.env.ADMIN_USERNAME);
  await page.getByLabel('Password', { exact: true }).fill(process.env.ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.locator('#metricStudents .sr-only')).toHaveCount(0);
  await page.locator('#accountMenuButton').click();
  await expect(page.locator('#accountMenu')).toBeVisible();
  expect(errors).toEqual([]);
});
