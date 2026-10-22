const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

test.beforeEach(async ({ page }, info) => {
  await page.route('https://**', route => route.abort());
  await page.addInitScript(theme => {
    localStorage.setItem('theme', theme);
    window.directoryAnimations = [];
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (frames, options) {
      if (this.matches('.sc-vehicles, .vehicle-edit-form')) window.directoryAnimations.push({ frames, duration: options.duration });
      return animate.call(this, frames, options);
    };
  }, info.project.name.includes('dark') ? 'dark' : 'light');
  const base = process.env.E2E_BASE_URL;
  const response = await page.request.post(base + '/login', {
    headers: { origin: base }, maxRedirects: 0,
    form: { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD }
  });
  expect(response.headers().location).toBe('/admin');
});

async function openVehicle(page) {
  await page.goto('/students#directory');
  const student = page.locator('.student-card').filter({ has: page.locator('.sv-item') }).first();
  const details = student.locator('[data-ui-action="toggle-student-details"]');
  await details.click();
  const vehicle = student.locator('.sv-item').first();
  const edit = vehicle.locator('.btn-edit-xs');
  await edit.click();
  const form = vehicle.locator('.vehicle-edit-form form');
  await expect(form).toBeVisible();
  return { student, details, vehicle, edit, form, panel: vehicle.locator('.vehicle-edit-form') };
}

test('directory disclosures keep their width, animate height only and return focus safely', async ({ page }, info) => {
  const { details, vehicle, edit, form, panel, student } = await openVehicle(page);
  await expect(details).toHaveText('Details');
  await expect(edit).toBeHidden();
  await expect(vehicle.getByRole('button', { name: 'Close', exact: true })).toHaveCount(0);
  await expect(form.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(1);
  await expect(form.getByLabel('Plate Number', { exact: true })).toBeFocused();
  const width = (await details.boundingBox()).width;
  const model = form.getByLabel('Model', { exact: true });
  await model.fill('Unsaved local draft');
  await form.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(panel).toBeHidden();
  await expect(edit).toBeFocused();
  await edit.click();
  await expect(model).toHaveValue('Unsaved local draft');
  await form.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(panel).toBeHidden();
  // Rapid reversals must not leave a stale inert/overflow state after the last animation.
  await details.evaluate(button => { button.click(); button.click(); button.click(); });
  await expect(student.locator('.sc-vehicles')).toBeHidden();
  await expect(details).toHaveText('Details');
  expect((await details.boundingBox()).width).toBe(width);
  await details.click();
  await expect(student.locator('.sc-vehicles')).toBeVisible();
  await expect(student.locator('.sc-vehicles')).toHaveJSProperty('inert', false);
  await expect.poll(() => student.locator('.sc-vehicles').evaluate(el => el.style.overflow)).toBe('');
  await edit.click();
  await form.getByRole('button', { name: 'Cancel', exact: true }).evaluate(button => {
    button.click();
    document.getElementById('editVehicleBtn_' + button.dataset.targetId).click();
  });
  await expect(panel).toBeVisible();
  await expect.poll(() => panel.evaluate(el => el.style.overflow)).toBe('');
  const motions = await page.evaluate(() => window.directoryAnimations);
  if (info.project.use.reducedMotion === 'reduce') expect(motions).toEqual([]);
  else {
    expect(motions.length).toBeGreaterThan(2);
    for (const motion of motions) {
      expect(motion.duration).toBe(240);
      for (const frame of motion.frames) expect(Object.keys(frame).sort()).toEqual(['height', 'opacity']);
    }
  }
});

test('plate typing, existing validation and borderless edit fields remain accessible', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const { vehicle, form, panel } = await openVehicle(page);
  const plate = form.getByLabel('Plate Number', { exact: true });
  await plate.fill('o0ab-12');
  await expect(plate).toHaveValue('O0AB-12');
  await plate.evaluate(el => el.setSelectionRange(2, 2));
  await plate.pressSequentially('c');
  await expect(plate).toHaveValue('O0CAB-12');
  expect(await plate.evaluate(el => el.selectionStart)).toBe(3);
  await expect(plate).toHaveCSS('text-transform', 'uppercase');
  expect(await plate.evaluate(el => getComputedStyle(el).fontVariantNumeric)).toContain('slashed-zero');
  await expect(vehicle.locator('.sv-plate')).toHaveCSS('text-transform', 'uppercase');
  expect(await vehicle.locator('.sv-plate').evaluate(el => getComputedStyle(el).fontFamily)).toContain('monospace');
  await expect(panel).toHaveCSS('border-top-width', '0px');
  await expect(form).toHaveCSS('border-top-width', '0px');
  await expect.poll(() => plate.evaluate(el => getComputedStyle(el.closest('.vehicle-input-wrap'), '::after').opacity)).toBe('1');
  let posted = false;
  await page.route('**/vehicles/*/edit', route => { posted = true; return route.abort(); });
  await plate.fill('');
  await form.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(plate).toHaveAttribute('aria-invalid', 'true');
  await expect(form.locator('.vehicle-field-error').first()).toBeVisible();
  await expect(plate).toBeFocused();
  expect(posted).toBe(false);
  await expect(form.locator('.is-loading')).toHaveCount(0);
  // Optional model/color and the native required constraint are unchanged.
  await plate.fill('O0-123');
  await form.getByLabel('Model', { exact: true }).fill('');
  await form.getByLabel('Color', { exact: true }).fill('');
  expect(await form.evaluate(el => el.checkValidity())).toBe(true);
  await expect(form.locator('.vehicle-field-error').first()).toBeHidden();
  await page.evaluate(() => Promise.allSettled(document.getAnimations().filter(a => a.effect.getComputedTiming().endTime < 2000).map(a => a.finished)));
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(audit.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await vehicle.scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath('vehicle-edit.png') });
  expect(errors).toEqual([]);
});

test('vehicle save remains a native POST with pending feedback and server-confirmed success', async ({ page }) => {
  const { form } = await openVehicle(page);
  const action = await form.getAttribute('action');
  let pending;
  let busy;
  await page.exposeFunction('captureVehicleBusy', state => { busy = state; });
  await page.route('**' + action, route => { pending = route; });
  await form.getByLabel('Plate Number', { exact: true }).fill('test-o012');
  await form.getByLabel('Model', { exact: true }).fill('Review model');
  await form.getByLabel('Color', { exact: true }).fill('Blue');
  await page.evaluate(() => document.addEventListener('submit', event => {
    const button = event.target.querySelector('.btn-save-sm');
    window.captureVehicleBusy({ busy: button.getAttribute('aria-busy'), loading: button.classList.contains('is-loading'), spinner: getComputedStyle(button, '::after').content, success: Boolean(document.querySelector('.ui-toast-success')) });
  }, { once: true }));
  await form.getByRole('button', { name: 'Save changes', exact: true }).click({ noWaitAfter: true });
  await expect.poll(() => Boolean(pending)).toBe(true);
  await expect.poll(() => busy).toEqual({ busy: 'true', loading: true, spinner: '""', success: false });
  expect(pending.request().isNavigationRequest()).toBe(true);
  expect(pending.request().method()).toBe('POST');
  expect(Object.fromEntries(new URLSearchParams(pending.request().postData()))).toEqual({ plate_number: 'TEST-O012', model: 'Review model', color: 'Blue' });
  // Simulate the existing redirect, without writing to any vehicle record.
  await pending.fulfill({ status: 302, headers: { location: '/students?esuccess=1' } });
  await expect(page).toHaveURL(/\/students\?esuccess=1/);
  await expect(page.locator('.ui-toast-success')).toContainText('updated');
  expect(await page.locator('.ui-toast-success strong').evaluate(el => getComputedStyle(el, '::before').content)).toContain('✓');
  await page.unroute('**' + action);
  const second = await openVehicle(page);
  await page.route('**' + action, route => route.fulfill({ status: 302, headers: { location: '/students?error=vduplicate' } }));
  await second.form.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(page.locator('.ui-toast-error')).toBeVisible();
  await expect(page.locator('.ui-toast-success')).toHaveCount(0);
});
