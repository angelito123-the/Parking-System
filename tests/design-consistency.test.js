const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(projectRoot, ...parts), 'utf8');

test('shared UI layer defines one control scale and semantic status palette', () => {
  const css = read('public', 'design-system.css');

  for (const token of [
    '--ui-control-height',
    '--ui-control-height-large',
    '--ui-touch-target',
    '--status-success-bg',
    '--status-warning-bg',
    '--status-danger-bg',
    '--status-info-bg',
    '--status-neutral-bg'
  ]) {
    assert.ok(css.includes(`${token}:`), `missing ${token}`);
  }

  assert.match(css, /\.badge-expired[\s\S]*?var\(--status-warning-text\)/);
  assert.match(css, /\.badge-revoked[\s\S]*?var\(--status-danger-text\)/);
  assert.match(css, /\.badge-inside[\s\S]*?var\(--status-info-text\)/);
  assert.match(css, /\.vehicle-sticker-status\.state-none[\s\S]*?var\(--status-neutral-text\)/);
});

test('normal surfaces are flat while overlays retain deliberate elevation', () => {
  const css = read('public', 'design-system.css');

  assert.match(css, /\.panel,[\s\S]*?\.reg-panel,[\s\S]*?\.directory-panel[\s\S]*?box-shadow:\s*none\s*!important/);
  assert.match(css, /Normal surfaces stay flat[\s\S]*?\.student-card[\s\S]*?box-shadow:\s*none\s*!important/);
  assert.match(css, /\.account-menu,[\s\S]*?\.notification-panel[\s\S]*?box-shadow:\s*var\(--shadow-overlay\)\s*!important/);
});

test('narrow and touch layouts provide 44 pixel action targets', () => {
  const css = read('public', 'design-system.css');
  const responsiveContract = css.slice(css.indexOf('@media (max-width: 1080px), (any-pointer: coarse)'));

  assert.match(responsiveContract, /\.account-menu-trigger/);
  assert.match(responsiveContract, /\.notification-view-all/);
  assert.match(responsiveContract, /\.action-menu-trigger/);
  assert.match(responsiveContract, /\.pagination-control/);
  assert.match(responsiveContract, /min-height:\s*var\(--ui-touch-target\)\s*!important/);
  assert.match(responsiveContract, /width:\s*var\(--ui-touch-target\)\s*!important/);
});

test('scanner and verification parking maps use shared theme-aware states', () => {
  const scanner = read('views', 'scanner.ejs');
  const verify = read('views', 'verify.ejs');

  assert.match(scanner, /class="slot-option-btn \$\{occupancy\}/);
  assert.match(scanner, /class="scanner-parking-map"/);
  assert.doesNotMatch(scanner, /background:linear-gradient\(180deg,#ffffff,#eff6ff\)/);
  assert.match(verify, /design-system\.css\?v=20260902-consistency/);
  assert.match(verify, /\.status-chip\.expired[\s\S]*?var\(--status-warning-text\)/);
  assert.match(verify, /\.slot-btn\.occupied[\s\S]*?var\(--status-warning-text\)/);
});

test('registry views use shared badges and layout helpers instead of fixed light colors', () => {
  const stickers = read('views', 'stickers.ejs');
  const vehicles = read('views', 'vehicles.ejs');

  assert.match(stickers, /class="badge badge-plate"/);
  assert.match(vehicles, /class="badge badge-plate"/);
  assert.match(stickers, /class="mobile-button-grid"/);
  assert.doesNotMatch(stickers, /background:\s*#f1f5f9/);
  assert.doesNotMatch(vehicles, /background:\s*#f1f5f9/);
});
