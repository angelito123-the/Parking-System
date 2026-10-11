const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

for (const view of ['admin_slots', 'guard_dashboard', 'scanner', 'scanner_auto', 'verify']) {
  test(`${view} groups parking zones without colliding with object property names`, () => {
    const source = fs.readFileSync(path.join(__dirname, '../views', `${view}.ejs`), 'utf8');
    const expression = source.match(/(?:\(slots \|\| \[\]\)|slots)\.reduce\(\(acc, slot\) => \{[\s\S]*?return acc;\s*\}, [^;]+\)/);
    assert.ok(expression, `Parking zone grouping must exist in ${view}`);
    const slots = [
      { id: 1, zone: 'Basketball Area Parking' },
      { id: 2, zone: '__proto__' },
      { id: 3, zone: 'constructor' },
      { id: 4, zone: 'toString' },
      { id: 5, zone: 'Basketball Area Parking' },
      { id: 6, zone: null }
    ];
    const grouped = vm.runInNewContext(expression[0], { slots });
    assert.deepEqual(Object.keys(grouped), ['Basketball Area Parking', '__proto__', 'constructor', 'toString', 'General']);
    assert.deepEqual(Array.from(grouped['Basketball Area Parking'], (slot) => slot.id), [1, 5]);
    for (const zone of ['__proto__', 'constructor', 'toString', 'General']) {
      assert.equal(grouped[zone].length, 1);
      assert.ok(Object.hasOwn(grouped, zone));
    }
  });
}
