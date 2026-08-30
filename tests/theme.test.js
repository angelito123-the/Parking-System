const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.join(__dirname, '..');

test('final UI layer defines complete light and dark palettes', () => {
  const css = fs.readFileSync(path.join(projectRoot, 'public', 'design-system.css'), 'utf8');
  const rootIndex = css.indexOf(':root');
  const darkIndex = css.indexOf('[data-theme="dark"]');

  assert.ok(rootIndex >= 0, 'light palette should exist');
  assert.ok(darkIndex > rootIndex, 'dark palette must follow the light palette in the final layer');

  const darkPalette = css.slice(darkIndex, css.indexOf('\n}', darkIndex) + 2);
  for (const token of ['--bg', '--surface', '--surface-soft', '--line', '--text', '--text-secondary', '--muted']) {
    assert.match(darkPalette, new RegExp(`${token}\\s*:`), `dark palette should define ${token}`);
  }

  assert.match(css, /\.content-area,[\s\S]*?\.main-shell\s*\{[\s\S]*?background:\s*var\(--bg\)\s*!important/);
  assert.match(css, /:root\s*\{[\s\S]*--sidebar:\s*#ffffff/);
  assert.match(darkPalette, /--sidebar:\s*#11263f/);
  assert.match(css, /\.sidebar\s*\{[\s\S]*background:\s*var\(--sidebar\)/);
  assert.match(css, /\.side-nav a\.active[\s\S]*background:\s*var\(--sidebar-active\)/);
});

test('theme stylesheet version is consistent with the offline cache', () => {
  const header = fs.readFileSync(path.join(projectRoot, 'views', 'partials', 'header.ejs'), 'utf8');
  const worker = fs.readFileSync(path.join(projectRoot, 'public', 'sw.js'), 'utf8');
  const asset = '/design-system.css?v=20260829-directory-search';

  assert.ok(header.includes(asset));
  assert.ok(worker.includes(asset));
  assert.match(worker, /CACHE_NAME\s*=\s*`\$\{CACHE_PREFIX\}v28`/);
  assert.match(header, /localStorage\.setItem\('theme', newTheme\)/);
  assert.match(header, /setAttribute\('aria-pressed', isDark \? 'true' : 'false'\)/);
});
