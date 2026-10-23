const base = require('./playwright.motion.config');
module.exports = {
  ...base,
  testMatch: 'live-updates-ui.spec.js',
  projects: [...base.projects, { name: 'updates-tablet', use: { viewport: { width: 768, height: 1024 } } }]
};
