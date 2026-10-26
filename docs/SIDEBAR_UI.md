# Sidebar navigation polish

The sidebar uses the existing Express/EJS templates and locally hosted Phosphor icons. No React runtime, Framer Motion dependency, API, database, authentication, or role rules were added or changed. The Admin and Guard link arrays and their active-path rules remain unchanged.

## Presentation and interaction

- A single navy gradient highlight moves between active links using the Web Animations API and the previous page's navigation position. This is the native equivalent for this server-rendered application; navigation remains ordinary page loads.
- The logo and account card stay pinned above a scrolling menu. The version and sign-out shortcut stay pinned below it. Scroll fades and a thin hover/focus scrollbar indicate additional links.
- Sections expand/fade in and fade out before closing. Desktop collapse switches to an 88px icon rail with keyboard/hover tooltips. Both controls retain preferences locally, without storing credentials or session data.
- Rail mode temporarily reveals every section. Navigating to a page reveals its section when expanded, preventing a stored collapsed section from concealing the current page.
- The existing mobile/tablet drawer includes backdrop, Escape, close button, focus wrapping, and a deliberate left swipe. Vertical scrolling is unaffected. Browser height changes no longer dismiss the drawer; crossing the desktop breakpoint does.
- Account options use the existing `/account/security` and `/logout` links. The account menu supports arrows, Home/End, Escape, outside click, and focus dismissal. The dot and accompanying text reflect the browser's network connection.
- The existing notification summary updates both shortcut badges. Pulses occur only when the unread count changes. No additional requests or subscriptions are made.
- Motion is limited to transform/opacity for 180–280ms, with a 240ms desktop width transition. Reduced-motion and low-power browsers skip decorative effects. Initial link entrance is staggered once per role per tab.

## Files

- `views/partials/header.ejs`: navigation markup, assets, preference bootstrap, notification summary hook.
- `views/partials/footer.ejs`: drawer resize/swipe handling and keyboard coordination.
- `public/sidebar-polish.css`: responsive layout, navy highlight, tiles, focus styles, fades, rail, menus, and reduced-motion overrides.
- `public/js/sidebar-polish.js`: presentation state, native animation, tooltips, section/rail controls, and shared unread badges.
- `public/js/ui-motion.js`: skips the legacy active-link animation when the new single highlight exists.
- `public/sw.js`: caches the new assets for the installed app.
- `e2e/sidebar-polish.spec.js`, `playwright.sidebar.config.js`: responsive interaction and accessibility checks.
- `e2e/ui-motion.spec.js`, `tests/theme.test.js`: updated animation/cache regression expectations.

The development checkout uses `views/layouts/header.ejs` and `views/layouts/footer.ejs`. Its existing API client wrappers and other local work are preserved.

## Unchanged limitations

- The notification API supplies one unread notification total, including resolved-but-unread records. Both Alerts and Live Updates display that same total, described accessibly as “unread notifications”; it is not a separate unread vehicle movement count. The underlying status/count rules were left unchanged.
- There is no separate profile page in the current navigation. The account shortcut opens Account security, which already exists.
- The footer shows the current package version, `1.0.0`. Keep that display in sync with `package.json` when the application version changes.

## Verification

Use the existing local test database and account environment variables. Browser notification fixtures prevent real notification updates; no parking data is modified by these checks.

```sh
node --test
npx playwright test --config=playwright.sidebar.config.js
npx playwright test --config=playwright.header.config.js
npx playwright test --config=playwright.motion.config.js --grep "navigation"
```

The development checkout additionally supports `npm run lint` and `npm run build`.

Validated on 2026-10-26: 169 code tests; 24 sidebar browser scenarios in each checkout; 30 notification/header regression scenarios; and 4 navigation/theme regression scenarios. Sidebar checks include WCAG AA automated audits, dark mode, reduced motion, blocked storage, low-power devices, 320px phones, tablets, desktop rails, keyboard controls, and lower-link reachability. Development lint and build passed (52 JavaScript files and 26 templates). Screenshots were visually reviewed on desktop, phone, and in dark mode. Automated checks do not replace testing on the guards' physical devices.

Manual check: collapse the desktop menu, hover/focus each icon, open a page, expand its section, and scroll to User Accounts. On a phone, open the hamburger menu, scroll to the last item, open account options, press Escape twice, then reopen and swipe left. Routes, permissions, and sign-out behavior should match the existing app.
