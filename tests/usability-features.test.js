const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.join(__dirname, '..');
const read = (...segments) => fs.readFileSync(path.join(projectRoot, ...segments), 'utf8');

test('student directory uses database filters and bounded pagination', () => {
  const server = read('server.js');
  const students = read('views', 'students.ejs');

  assert.match(server, /allowedPageSizes\s*=\s*new Set\(\[10, 25, 50\]\)/);
  assert.match(server, /filters\.vehicle_status === "with_vehicle"/);
  assert.match(server, /filters\.sticker_status === "active"/);
  assert.match(server, /LIMIT \? OFFSET \?/);
  assert.match(students, /name="course"/);
  assert.match(students, /name="year_level"/);
  assert.match(students, /name="vehicle_status"/);
  assert.match(students, /name="sticker_status"/);
  assert.match(students, /class="directory-pagination"/);
});

test('responsive navigation and account actions use accessible menus', () => {
  const header = read('views', 'partials', 'header.ejs');
  const footer = read('views', 'partials', 'footer.ejs');
  const css = read('public', 'design-system.css');

  assert.match(header, /id="mobileNavTrigger"[\s\S]*aria-controls="mobileSidebar"/);
  assert.match(header, /class="account-menu" id="accountMenu" role="menu"/);
  assert.match(header, /href="\/account\/security#password"/);
  assert.match(header, /id="themeToggle" role="menuitem"/);
  assert.match(footer, /body\.classList\.toggle\("mobile-nav-open", open\)/);
  assert.match(css, /@media \(max-width: 1080px\)[\s\S]*body\.mobile-nav-open \.sidebar/);
  assert.match(css, /body\[data-role="guard"\] \.side-nav a\.nav-primary-action/);
});

test('destructive records use overflow actions and a shared confirmation dialog', () => {
  const students = read('views', 'students.ejs');
  const users = read('views', 'admin_users.ejs');
  const footer = read('views', 'partials', 'footer.ejs');

  assert.match(students, /data-destructive-trigger/);
  assert.doesNotMatch(students, /onsubmit="return confirm/);
  assert.match(users, /data-destructive-trigger/);
  assert.doesNotMatch(users, /onsubmit="return confirm/);
  assert.match(footer, /role="alertdialog"/);
  assert.match(footer, /form\.requestSubmit\(\)/);
});
