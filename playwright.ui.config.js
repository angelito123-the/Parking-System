const { defineConfig, devices } = require('@playwright/test');
const baseURL = process.env.E2E_BASE_URL || 'http://127.0.0.1:3000';
module.exports = defineConfig({
  testDir: './e2e', testMatch: 'ui-usability.spec.js',
  timeout: 60_000, expect: { timeout: 7_000 }, workers: 1, reporter: 'line',
  use: {
    baseURL, serviceWorkers: 'block', reducedMotion: 'reduce',
    trace: 'retain-on-failure', screenshot: 'only-on-failure',
    launchOptions: { args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] }
  },
  webServer: {
    command: 'npm start', url: baseURL + '/healthz', reuseExistingServer: true,
    env: { PORT: new URL(baseURL).port || '3000' }, timeout: 60_000
  },
  projects: [
    { name: 'ui-desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
    { name: 'ui-phone', use: { ...devices['Pixel 7'], viewport: { width: 390, height: 844 } } },
    { name: 'ui-phone-dark', use: { ...devices['Pixel 7'], viewport: { width: 390, height: 844 }, colorScheme: 'dark' } }
  ]
});
