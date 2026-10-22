const base = require('./playwright.ui.config');

module.exports = {
  ...base,
  testMatch: 'ui-motion.spec.js',
  use: { ...base.use, reducedMotion: 'no-preference' },
  projects: [
    ...base.projects.map(project => ({ ...project, name: project.name.replace('ui-', 'motion-') })),
    { name: 'motion-reduced', use: { viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' } }
  ]
};
