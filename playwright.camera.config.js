const { defineConfig, devices } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./e2e",
  testMatch: "camera-startup.spec.js",
  timeout: 30_000,
  expect: { timeout: 7_000 },
  workers: 1,
  reporter: "line",
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: {
      args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"]
    }
  },
  projects: [
    { name: "camera-desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "camera-phone", use: { ...devices["Pixel 7"] } }
  ]
});
