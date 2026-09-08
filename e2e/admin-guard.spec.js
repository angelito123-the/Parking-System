const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
require("dotenv").config();

const adminCredentials = {
  username: process.env.ADMIN_USERNAME || "admin",
  password: process.env.ADMIN_PASSWORD || "naap2024"
};
const guardCredentials = {
  username: process.env.GUARD_USERNAME || "guard",
  password: process.env.GUARD_PASSWORD || "guard123"
};

async function signIn(page, credentials) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(credentials.username);
  await page.locator("#password").fill(credentials.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForLoadState("domcontentloaded");
  if (page.url().includes("/login/2fa")) {
    throw new Error("E2E account requires a TOTP code. Use a dedicated local account without TOTP for automated browser checks.");
  }
  await expect(page).not.toHaveURL(/\/login(?:\/2fa)?$/);
}

async function expectPhosphorIconFont(page) {
  await page.evaluate(() => document.fonts.ready);
  const icon = page.locator('.top-nav .ph:visible').first();
  await expect(icon).toBeVisible();
  const rendered = await icon.evaluate((element) => ({
    fontFamily: getComputedStyle(element).fontFamily,
    glyph: getComputedStyle(element, '::before').content
  }));
  expect(rendered.fontFamily).toContain('Phosphor');
  expect(rendered.glyph).not.toBe('none');
  expect(rendered.glyph).not.toBe('normal');
}

function collectPageErrors(page) {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

test.describe("administrator workflows", () => {
  test("loads account, sticker, parking-space, and recovery screens without browser errors", async ({ page }, testInfo) => {
    test.skip(testInfo.project.name.includes("mobile"), "Admin desktop workflow is covered in desktop Chromium.");
    const pageErrors = collectPageErrors(page);
    await signIn(page, adminCredentials);
    await expectPhosphorIconFont(page);

    const pages = [
      ["/admin/users", "User Management"],
      ["/stickers", "Sticker Management"],
      ["/admin/slots", "Parking Slot Monitoring"],
      ["/admin/data", "Backup & Recovery"]
    ];
    for (const [url, heading] of pages) {
      await page.goto(url);
      await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
    }

    await expect(pageErrors).toEqual([]);
  });

  test("important admin pages have no serious accessibility violations", async ({ page }, testInfo) => {
    test.skip(testInfo.project.name.includes("mobile"), "Admin desktop workflow is covered in desktop Chromium.");
    await signIn(page, adminCredentials);
    for (const url of ["/admin/users", "/stickers", "/admin/slots", "/admin/data"]) {
      await page.goto(url);
      const results = await new AxeBuilder({ page })
        .include("main")
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      const serious = results.violations.filter((item) => ["serious", "critical"].includes(item.impact));
      expect(serious, `${url}: ${serious.map((item) => item.id).join(", ")}`).toEqual([]);
    }
  });
});

test.describe("guard mobile workflow", () => {
  test("loads the dashboard and scanner at phone size with usable touch controls", async ({ page }, testInfo) => {
    test.skip(testInfo.project.name.includes("desktop"), "Guard phone workflow is covered in mobile Chromium.");
    const pageErrors = collectPageErrors(page);
    await signIn(page, guardCredentials);
    await expectPhosphorIconFont(page);
    await expect(page.getByRole("heading", { name: "Guard Dashboard", level: 1 })).toBeVisible();
    const dashboardAccessibility = await new AxeBuilder({ page })
      .include("main")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(
      dashboardAccessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact)),
      "Guard dashboard has serious accessibility violations."
    ).toEqual([]);

    const menuButton = page.getByRole("button", { name: /open navigation/i });
    await expect(menuButton).toBeVisible();
    const menuBox = await menuButton.boundingBox();
    expect(menuBox.width).toBeGreaterThanOrEqual(44);
    expect(menuBox.height).toBeGreaterThanOrEqual(44);

    await page.goto("/scanner");
    await expect(page.getByRole("heading", { name: "Manual Gate Tools", level: 1 })).toBeVisible();
    const scannerAccessibility = await new AxeBuilder({ page })
      .include("main")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(
      scannerAccessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact)),
      "Guard scanner has serious accessibility violations."
    ).toEqual([]);
    await expect(pageErrors).toEqual([]);
  });

  test("cannot open administrator-only recovery tools", async ({ page }, testInfo) => {
    test.skip(testInfo.project.name.includes("desktop"), "Guard phone workflow is covered in mobile Chromium.");
    await signIn(page, guardCredentials);
    await page.goto("/admin/data");
    await expect(page).toHaveURL(/\/forbidden|\/admin\/data/);
    await expect(page.getByText(/do not have permission|forbidden/i).first()).toBeVisible();
  });
});
