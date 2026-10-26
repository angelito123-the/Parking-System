const base = require('./playwright.header.config');
module.exports = { ...base, testMatch: 'sidebar-polish.spec.js', projects: [...base.projects, { name: 'sidebar-desktop-dark', use: { viewport: { width: 1440, height: 900 }, colorScheme: 'dark' } }] };
