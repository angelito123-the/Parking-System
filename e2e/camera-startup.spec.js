const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");
const ejs = require("ejs");

const root = path.join(__dirname, "..");
const origin = "http://localhost:3999";

test.use({
  launchOptions: {
    args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"]
  }
});

async function serveScanner(page, options = {}) {
  const errors = [];
  const externalRequests = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/*", async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) {
      externalRequests.push(url.href);
      return route.abort();
    }
    if (options.blockAsset?.(url.pathname)) return route.abort();
    if (url.pathname === "/scanner/auto" || url.pathname === "/scanner") {
      const template = url.pathname === "/scanner" ? "scanner.ejs" : "scanner_auto.ejs";
      const html = ejs.render(fs.readFileSync(path.join(root, "views", template), "utf8"), {
        deferEntryConfirmation: url.searchParams.get("mode") === "remote",
        currentRole: "guard", scanCooldownSeconds: 10, cspNonce: "camera-test",
        include: name => name === "partials/header"
          ? '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/styles.css"><link rel="stylesheet" href="/design-system.css"></head><body>'
          : "</body></html>"
      });
      return route.fulfill({
        contentType: "text/html", body: html,
        headers: { "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-camera-test'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; img-src 'self' data: blob:;" }
      });
    }
    if (url.pathname.startsWith("/api/")) {
      return route.fulfill({ json: { ok: true, pending: [], entries: [], slots: [] } });
    }
    const asset = path.join(root, "public", url.pathname);
    if (!fs.existsSync(asset)) return route.fulfill({ status: 404, body: "Not found" });
    return route.fulfill({ path: asset });
  });
  return { errors, externalRequests };
}

async function expectLiveCamera(page) {
  await expect(page.locator("#chipCameraState")).toHaveText("Camera Ready");
  await expect(page.locator("#autoQrReader video")).toBeVisible();
  await expect.poll(() => page.locator("#autoQrReader video").evaluate(video => (
    video.readyState >= 2 && video.videoWidth > 0 && !video.paused
    && video.srcObject.getVideoTracks()[0].readyState === "live"
  ))).toBe(true);
  await expect(page.locator("#autoCameraStatus")).toContainText(/camera active/i);
}

for (const mode of ["", "?mode=remote"]) {
  test(`camera opens and restarts without external network access (${mode || "local"})`, async ({ page }) => {
    const { errors, externalRequests } = await serveScanner(page);
    await page.goto(`${origin}/scanner/auto${mode}`);
    await expectLiveCamera(page);
    await page.getByRole("button", { name: "Stop Camera", exact: true }).click();
    await expect(page.locator("#chipCameraState")).toHaveText("Camera Stopped");
    await expect(page.locator("#autoQrReader video")).toHaveCount(0);
    await page.getByRole("button", { name: "Start Camera", exact: true }).click();
    await expectLiveCamera(page);
    expect(errors).toEqual([]);
    expect(externalRequests).toEqual([]);
  });
}

test("permission denial displays a retryable error", async ({ page }) => {
  const { errors } = await serveScanner(page);
  await page.addInitScript(() => {
    const realGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    let denied = false;
    navigator.mediaDevices.getUserMedia = constraints => {
      if (!denied) {
        denied = true;
        return Promise.reject(new DOMException("Permission denied", "NotAllowedError"));
      }
      return realGetUserMedia(constraints);
    };
  });
  await page.goto(`${origin}/scanner/auto?mode=remote`);
  await expect(page.locator("#chipCameraState")).toHaveText("Camera Error");
  await expect(page.locator("#autoCameraStatus")).toContainText("Allow camera access");
  await page.getByRole("button", { name: "Start Camera", exact: true }).click();
  await expectLiveCamera(page);
  expect(errors).toEqual([]);
});

test("unsupported native QR detection falls back to the bundled decoder", async ({ page }) => {
  const { errors } = await serveScanner(page);
  await page.addInitScript(() => {
    window.BarcodeDetector = class {
      constructor() { throw new DOMException("QR format unavailable", "NotSupportedError"); }
    };
  });
  await page.goto(`${origin}/scanner/auto?mode=remote`);
  await expectLiveCamera(page);
  expect(errors).toEqual([]);
});

test("missing decoder files show an error instead of a false ready state", async ({ page }) => {
  let blockDecoders = true;
  const { errors } = await serveScanner(page, {
    blockAsset: pathname => blockDecoders && /\/vendor\/(jsqr|html5-qrcode)\//.test(pathname)
  });
  await page.goto(`${origin}/scanner/auto?mode=remote`);
  await expect(page.locator("#chipCameraState")).toHaveText("Camera Error");
  await expect(page.locator("#autoCameraStatus")).toContainText("Scanner files could not load");
  await expect(page.getByRole("button", { name: "Start Camera", exact: true })).toBeEnabled();
  expect(errors).toEqual([]);
  blockDecoders = false;
  await page.reload();
  await expectLiveCamera(page);
});

test("the backup scanner opens when the enhanced decoder is unavailable", async ({ page }) => {
  const { errors } = await serveScanner(page, { blockAsset: pathname => pathname.includes("/vendor/jsqr/") });
  await page.goto(`${origin}/scanner/auto?mode=remote`);
  await expectLiveCamera(page);
  expect(errors).toEqual([]);
});

test("camera readiness waits for permission and video playback", async ({ page }) => {
  await serveScanner(page);
  await page.addInitScript(() => {
    const realGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = constraints => new Promise((resolve, reject) => {
      window.allowTestCamera = () => realGetUserMedia(constraints).then(resolve, reject);
    });
  });
  await page.goto(`${origin}/scanner/auto?mode=remote`);
  await expect(page.locator("#chipCameraState")).toHaveText("Opening Camera");
  await expect(page.locator("#chipAutoState")).not.toHaveClass(/state-live/);
  await page.waitForFunction(() => typeof window.allowTestCamera === "function");
  await page.evaluate(() => window.allowTestCamera());
  await expectLiveCamera(page);
});

test("manual camera tools also load without external QR scripts", async ({ page }) => {
  const { errors, externalRequests } = await serveScanner(page);
  await page.goto(`${origin}/scanner`);
  await page.locator("#toggleCameraBtn").click();
  await expect.poll(() => page.locator("#qr-reader video").evaluateAll(videos => (
    videos.length === 1 && videos[0].videoWidth > 0 && !videos[0].paused
  ))).toBe(true);
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test("manual camera permission errors allow a direct retry", async ({ page }) => {
  const { errors } = await serveScanner(page);
  await page.addInitScript(() => {
    const getMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    let deny = true;
    navigator.mediaDevices.getUserMedia = constraints => {
      if (deny) { deny = false; return Promise.reject(new DOMException("Denied", "NotAllowedError")); }
      return getMedia(constraints);
    };
  });
  await page.goto(`${origin}/scanner`);
  await page.locator("#toggleCameraBtn").click();
  await expect(page.locator("#cameraStatus")).toContainText("Camera unavailable");
  await page.locator("#toggleCameraBtn").click();
  await expect(page.locator("#cameraStatus")).toHaveText("Scanner active");
  expect(errors).toEqual([]);
});

test("online lookup does not require offline storage support", async ({ page }) => {
  const { errors } = await serveScanner(page);
  await page.route("**/api/gate-lookup?*", route => route.fulfill({ json: { ok: true, results: [] } }));
  await page.goto(`${origin}/scanner?q=TEST`);
  await expect(page.locator("#gateSearchStatus")).toHaveText("No results found.");
  expect(errors).toEqual([]);
});

for (const brokenStorage of [false, true]) {
  test(`offline lookup recovers from unavailable support (storage=${brokenStorage})`, async ({ page }) => {
    const { errors } = await serveScanner(page);
    await page.addInitScript(broken => {
      Object.defineProperty(navigator, "onLine", { get: () => false });
      if (broken) window.OfflineManager = { searchOfflineRoster: async () => { throw new Error("IndexedDB unavailable"); } };
    }, brokenStorage);
    await page.goto(`${origin}/scanner?q=TEST`);
    await expect(page.locator("#gateSearchStatus")).toContainText("Offline lookup is unavailable");
    expect(errors).toEqual([]);
  });
}

test("manual history displays only movements the server saved", async ({ page }) => {
  const { errors } = await serveScanner(page);
  await page.route("**/api/gate-lookup?*", route => route.fulfill({ json: { ok: true, results: [{ qr_token: 'history-token', full_name: 'Review driver', plate_number: 'TEST', sticker_status: 'active', last_action: 'ENTRY' }] } }));
  let saved = false;
  await page.route("**/api/manual-movement", route => route.fulfill({ json: { ok: saved, movement_saved: saved, message: 'Test rejection' } }));
  await page.goto(`${origin}/scanner?q=TEST`);
  await page.locator('.select-vehicle-btn').click();
  await page.locator('#gateExitBtn').click();
  await expect(page.locator('#gateLogFeedback')).toContainText('Test rejection');
  await expect(page.locator('#scanHistoryList .scanner-history-item')).toHaveCount(0);
  saved = true;
  await page.locator('#gateExitBtn').click();
  await expect(page.locator('#scanHistoryList .scanner-history-item')).toHaveCount(1);
  await expect(page.locator('#scanHistoryList')).toContainText('Review driver');
  expect(errors).toEqual([]);
});
