const fs = require('node:fs');
const path = require('node:path');
const { chromium, request } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
require('dotenv').config();
const baseURL = process.env.UI_REVIEW_BASE_URL || 'http://127.0.0.1:3019';
if (!['127.0.0.1', 'localhost'].includes(new URL(baseURL).hostname)) throw new Error('Use a local review application.');
const out = path.resolve(process.env.UI_REVIEW_ARTIFACT_DIR || 'test-results/ui-review');
fs.mkdirSync(out, { recursive: true });
(async () => {
  const browser = await chromium.launch({ args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] });
  const results = [];
  try {
    for (const role of ['admin', 'guard']) {
      const api = await request.newContext({ baseURL, extraHTTPHeaders: { origin: baseURL } });
      try {
        const login = await api.post('/login', { form: { username: process.env[role.toUpperCase() + '_USERNAME'], password: process.env[role.toUpperCase() + '_PASSWORD'] }, maxRedirects: 0 });
        if (login.headers().location !== '/' + role) throw new Error('Review login failed for ' + role);
        for (const [profile, viewport, theme] of [
          ['desktop', { width: 1440, height: 1000 }, 'light'],
          ['phone', { width: 390, height: 844 }, 'light'],
          ['phone-dark', { width: 390, height: 844 }, 'dark']
        ]) {
          const context = await browser.newContext({ storageState: await api.storageState(), viewport, serviceWorkers: 'block', reducedMotion: 'reduce' });
          await context.route('https://**', route => route.abort());
          await context.addInitScript(theme => localStorage.setItem('theme', theme), theme);
          const page = await context.newPage();
          let errors = [];
          page.on('pageerror', error => errors.push(error.message));
          for (const route of role === 'admin' ? ['/admin', '/students', '/students#directory', '/stickers', '/admin/users', '/reports', '/admin/slots', '/admin/data', '/visitor-passes', '/account/security'] : ['/guard', '/scanner', '/scanner/auto?mode=remote']) {
            errors = [];
            await page.goto(baseURL + route);
            await page.waitForTimeout(200);
            const name = profile + '-' + route.slice(1).replace(/[^a-z]/gi, '-');
            await page.screenshot({ path: path.join(out, name + '.png') });
            const layout = await page.evaluate(() => ({
              viewport: innerWidth,
              scannerActionTop: document.querySelector('.hero-primary-action')?.getBoundingClientRect().top,
              cameraTop: document.querySelector('#autoCameraWrapper')?.getBoundingClientRect().top,
              lookupTop: document.querySelector('#gateSearchInput')?.getBoundingClientRect().top,
              overflow: [...document.querySelectorAll('main > *,main .panel,main .reg-panel,main .directory-panel')].filter(element => {
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && (rect.right > innerWidth + 1 || rect.left < -1);
              }).map(element => element.className).slice(0, 5)
            }));
            const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
            const violations = axe.violations.map(item => ({ id: item.id, impact: item.impact, nodes: item.nodes.slice(0, 4).map(node => ({ target: node.target, summary: node.failureSummary })) }));
            const result = { name, ...layout, violations, errors: [...errors] };
            results.push(result);
            console.log(JSON.stringify(result));
          }
          await context.close();
        }
      } finally { await api.dispose(); }
    }
    fs.writeFileSync(path.join(out, 'audit.json'), JSON.stringify(results, null, 2));
    if (results.some(result => result.errors.length || result.overflow.length || result.violations.some(item => ['critical', 'serious'].includes(item.impact)))) process.exitCode = 1;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
