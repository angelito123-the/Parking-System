(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NaapPasswordPolicy = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const rules = [
    { label: 'At least 10 characters', message: 'Use at least 10 characters.', check: value => value.length >= 10 },
    { label: 'A lowercase letter', message: 'Add a lowercase letter.', check: value => /[a-z]/.test(value) },
    { label: 'An uppercase letter', message: 'Add an uppercase letter.', check: value => /[A-Z]/.test(value) },
    { label: 'A number', message: 'Add a number.', check: value => /\d/.test(value) },
    { label: 'Avoid starting with password, admin, guard or naap', message: 'Avoid predictable words at the beginning.', check: value => !/^(password|admin|guard|naap)/i.test(value) }
  ];
  function validatePassword(password) {
    const value = String(password || '');
    const issues = rules.filter(rule => !rule.check(value)).map(rule => rule.message);
    return { valid: issues.length === 0, issues };
  }
  return { rules, validatePassword };
}));
