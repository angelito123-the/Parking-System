const base = require('./playwright.motion.config');
module.exports = { ...base, testMatch: 'header-polish.spec.js', projects: [...base.projects, { name: 'header-tablet', use: { viewport: { width: 768, height: 1024 } } }] };
