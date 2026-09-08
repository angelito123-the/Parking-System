const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.join(__dirname, '..');
const viewsRoot = path.join(projectRoot, 'views');
const publicRoot = path.join(projectRoot, 'public');
const phosphorRoot = path.join(publicRoot, 'vendor', 'phosphor');

function collectFiles(root, extensions) {
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) return collectFiles(fullPath, extensions);
    return extensions.has(path.extname(entry.name)) ? [fullPath] : [];
  });
}

test('Phosphor regular icon font is self-hosted and licensed', () => {
  const stylesheetPath = path.join(phosphorRoot, 'style.css');
  const fontPath = path.join(phosphorRoot, 'Phosphor.woff2');
  const licensePath = path.join(phosphorRoot, 'LICENSE');

  assert.ok(fs.existsSync(stylesheetPath), 'Phosphor stylesheet should exist');
  assert.ok(fs.statSync(fontPath).size > 1000, 'Phosphor font should contain icon data');
  assert.match(fs.readFileSync(licensePath, 'utf8'), /MIT License/);
  assert.match(fs.readFileSync(stylesheetPath, 'utf8'), /url\("\.\/Phosphor\.woff2"\) format\("woff2"\)/);
});

test('every Phosphor icon used by the interface exists in the vendored font map', () => {
  const stylesheet = fs.readFileSync(path.join(phosphorRoot, 'style.css'), 'utf8');
  const sourceFiles = [
    ...collectFiles(viewsRoot, new Set(['.ejs'])),
    ...collectFiles(path.join(publicRoot, 'js'), new Set(['.js'])),
    path.join(publicRoot, 'offline.html')
  ];
  const usedIcons = new Set();

  for (const file of sourceFiles) {
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/\bph-([a-z0-9-]+)/g)) usedIcons.add(match[0]);
  }

  assert.ok(usedIcons.size > 20, 'the interface should use the shared icon set');
  for (const icon of usedIcons) {
    assert.ok(stylesheet.includes(`.ph.${icon}:before`), `${icon} should exist in Phosphor`);
  }
});

test('templates use Phosphor instead of embedded SVG or emoji icons', () => {
  const templates = collectFiles(viewsRoot, new Set(['.ejs']));
  const templateSource = templates.map((file) => fs.readFileSync(file, 'utf8')).join('\n');

  assert.doesNotMatch(templateSource, /<svg\b/i);
  assert.doesNotMatch(templateSource, /\p{Extended_Pictographic}/u);
});

test('standalone pages and the offline cache load Phosphor assets', () => {
  const stylesheetUrl = '/vendor/phosphor/style.css?v=2.1.2';
  for (const relativePath of ['views/login.ejs', 'views/verify.ejs', 'public/offline.html']) {
    assert.ok(fs.readFileSync(path.join(projectRoot, relativePath), 'utf8').includes(stylesheetUrl));
  }

  const worker = fs.readFileSync(path.join(publicRoot, 'sw.js'), 'utf8');
  assert.ok(worker.includes(stylesheetUrl));
  assert.ok(worker.includes('/vendor/phosphor/Phosphor.woff2'));
});
