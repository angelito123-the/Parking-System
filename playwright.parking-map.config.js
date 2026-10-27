const base = require('./playwright.sidebar.config');
module.exports = {
  ...base,
  testMatch: 'admin-parking-map.spec.js',
  projects: [
    ...base.projects.map(project => project.name === 'motion-desktop'
      ? { ...project, use: { ...project.use, viewport: { width: 1280, height: 1000 } } }
      : project),
    { name: 'map-wide', use: { viewport: { width: 1920, height: 1080 } } }
  ]
};
