const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { PNG } = require('pngjs');

const projectRoot = path.join(__dirname, '..');
const publicRoot = path.join(projectRoot, 'public');

test('manifest references complete install icon assets', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(publicRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.scope, '/');

  const expected = new Map([
    ['/icons/icon-192.png', [192, 192, 'any']],
    ['/icons/icon-512.png', [512, 512, 'any']],
    ['/icons/icon-maskable-512.png', [512, 512, 'maskable']]
  ]);

  for (const icon of manifest.icons) {
    if (!expected.has(icon.src)) continue;
    const [width, height, purpose] = expected.get(icon.src);
    const iconPath = path.join(publicRoot, icon.src.replace(/^\//, ''));
    assert.ok(fs.existsSync(iconPath), `${icon.src} should exist`);
    const png = PNG.sync.read(fs.readFileSync(iconPath));
    assert.equal(png.width, width);
    assert.equal(png.height, height);
    assert.equal(icon.purpose, purpose);
    expected.delete(icon.src);
  }

  assert.deepEqual([...expected.keys()], [], 'all required install icons should be declared');
});

test('service worker precaches and serves the offline navigation fallback', () => {
  const worker = fs.readFileSync(path.join(publicRoot, 'sw.js'), 'utf8');
  const offline = fs.readFileSync(path.join(publicRoot, 'offline.html'), 'utf8');
  assert.match(worker, /const OFFLINE_URL = ['"]\/offline\.html['"]/);
  assert.match(worker, /event\.request\.mode === ['"]navigate['"]/);
  assert.match(worker, /caches\.match\(OFFLINE_URL\)/);
  assert.match(offline, /You’re currently offline/);
  assert.match(offline, /id="retryButton"/);
});
