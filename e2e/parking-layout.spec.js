const { test, expect } = require('@playwright/test');
require('dotenv').config();

async function signIn(page, baseURL, role) {
  const response = await page.request.post('/login', {
    headers: { origin: new URL(baseURL).origin },
    form: {
      username: process.env[`${role.toUpperCase()}_USERNAME`],
      password: process.env[`${role.toUpperCase()}_PASSWORD`]
    },
    maxRedirects: 0
  });
  expect(response.headers().location).toBe(`/${role}`);
}

// Verify the real inventory and its physical arrangement without changing records.
async function expectParkingLayouts(page) {
  const basketball = page.locator('.parking-plan[data-parking-zone="Basketball Area Parking"]');
  const hangar = page.locator('.parking-plan[data-parking-zone="Hangar Parking Zone"]');
  await expect(basketball.locator('.parking-plan-bay')).toHaveCount(20);
  await expect(basketball.locator('.parking-plan-divider')).toHaveCount(8);
  const basketballCodes = await basketball.locator('.parking-plan-bay').evaluateAll(buttons => buttons.map(button => button.dataset.slotCode));
  expect(basketballCodes).toEqual(Array.from({ length: 20 }, (_, index) => `A-${String(index + 1).padStart(2, '0')}`));
  await expect(hangar.locator('.parking-plan-bay')).toHaveCount(20);
  await expect(hangar.locator('.parking-plan-divider')).toHaveCount(0);
  const arrangement = await hangar.locator('.parking-plan-row').evaluateAll(rows => rows.map(row => {
    const children = Array.from(row.children);
    return children.map(child => child.className);
  }));
  expect(arrangement).toHaveLength(20);
  for (const row of arrangement) {
    expect(row[0]).toContain('parking-plan-bay');
    expect(row[1]).toBe('parking-plan-lane');
    expect(row[2]).toBe('parking-plan-empty');
  }
  const codes = await hangar.locator('.parking-plan-bay').evaluateAll(buttons => buttons.map(button => button.dataset.slotCode));
  expect(codes).toEqual(Array.from({ length: 20 }, (_, index) => `H-${String(index + 1).padStart(2, '0')}`));
}

test('administrator sees 20 basketball spaces with dividers and 20 left-side Hangar spaces', async ({ page, baseURL }) => {
  await signIn(page, baseURL, 'admin');
  await page.goto('/admin/slots');
  await expectParkingLayouts(page);
});

test('bulk parking closure confirms the full scope and supports keyboard cancellation', async ({ page, baseURL }) => {
  await signIn(page, baseURL, 'admin');
  const submissions = [];
  await page.route('**/admin/slots/disable-all', route => {
    submissions.push(new URLSearchParams(route.request().postData()));
    return route.fulfill({ contentType: 'text/html', body: '<p>Saved test response</p>' });
  });
  await page.goto('/admin/slots');
  // A filtered map must not silently narrow an action that says "all".
  await page.locator('#parkingSlotSearch').fill('A-01');
  const trigger = page.getByRole('button', { name: 'Disable all parking slots', exact: true });
  await trigger.click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toHaveAccessibleName('Disable all parking slots?');
  await expect(dialog).toContainText('every zone, including slots hidden by filters');
  await expect(dialog).toContainText('can still exit');
  await expect(dialog.getByRole('button', { name: 'Go back' })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
  expect(submissions).toHaveLength(0);
  await trigger.click();
  await page.locator('#confirmDialogNote').fill('  School foundation day  ');
  await dialog.getByRole('button', { name: 'Disable all parking slots', exact: true }).click();
  await expect(page.getByText('Saved test response')).toBeVisible();
  expect(submissions).toHaveLength(1);
  expect(submissions[0].get('confirm_disable_all')).toBe('yes');
  expect(submissions[0].get('approval_note')).toBe('School foundation day');
});

test('guard entry selection uses the same parking layouts', async ({ page, baseURL }) => {
  await page.addInitScript(() => {
    window.EventSource = class extends EventTarget { close() {} };
  });
  await page.route('**/api/auto-scan/pending-entries?*', route => route.fulfill({ json: {
    ok: true,
    rows: [{ id: 987654, full_name: 'Layout Check', student_number: 'LAYOUT', plate_number: 'LAYOUT', created_at: new Date().toISOString() }]
  } }));
  await signIn(page, baseURL, 'guard');
  await page.goto('/guard');
  await page.locator('.guard-open-entry-btn').click();
  await expectParkingLayouts(page);
  const selected = page.locator('.parking-plan[data-parking-zone="Hangar Parking Zone"] .parking-plan-bay').first();
  await selected.click();
  await expect(selected).toHaveClass(/selected/);
  await expect(page.locator('#guardEntryConfirmBtn')).toBeEnabled();
  const added = page.locator('.parking-plan[data-parking-zone="Basketball Area Parking"] .parking-plan-bay[data-slot-code="A-20"]');
  await added.click();
  await expect(added).toHaveClass(/selected/);
  await expect(selected).not.toHaveClass(/selected/);
  await expect(page.locator('#guardEntryConfirmBtn')).toBeEnabled();
});
