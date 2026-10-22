# Motion and visual polish

The frontend is Express/EJS with plain browser JavaScript. These changes keep its existing split login, dashboard cards, sidebar, quick actions, tables, native form submissions, and role checks. No React runtime, Framer Motion, or new dependency is added.

## Files and responsibilities

| File | Responsibility |
| --- | --- |
| `public/ui-motion.css` | Shared motion tokens, entrances, card accents, menu/modal/toast animation, native page fades, and reduced-motion rules. |
| `public/js/ui-motion.js` | Reusable animation variants, count-up display, bounded live sparklines, refresh presentation, sidebar indicator memory, and confirmed sign-in presentation. |
| `public/login-theme.css` | Split-login entrance sequence, background orbs, input glow, and error shake. |
| `views/login.ejs` | Motion assets and success-check icon inside the existing submit button. |
| `views/dashboard.ejs` | Metric icons/sparklines, refresh icon, loading placeholder, and hooks after existing refreshes. |
| `views/partials/header.ejs` | Shared logo, motion assets, and animation around the existing theme toggle. |
| `views/partials/footer.ejs` | Brief mobile drawer closing state; existing focus and inert handling stay intact. |
| `public/sw.js` | Versioned motion assets in the existing static offline cache. |
| `e2e/ui-motion.spec.js`, `playwright.motion.config.js`, `tests/theme.test.js` | Motion, accessibility, native form, focus, and cache regression checks. |

The organized development tree uses `views/account/login.ejs`, `views/admin/dashboard.ejs`, and `views/layouts/header.ejs` / `footer.ejs` for the same screens.

## Animation behavior

- Login: two low-opacity gradient orbs drift behind the navy panel; logo, text, feature pills, and the form enter in a short stagger. The split layout is unchanged.
- Inputs: a pre-rendered inset glow fades in, and the icon nudges as focus enters. Color changes are immediate, preserving contrast.
- Sign-in: the existing native POST displays its spinner. The final same-origin destination from `pageswap` can show the success check during the browser's outgoing snapshot. An error returned by the server shakes the enabled button once. The authenticated destination also shows a success notice. No request is intercepted or resubmitted, and no redirect is delayed.
- Metrics: the visible number counts to the server value over 360ms, with the final value available to screen readers immediately. Reduced-motion and low-power clients show the final value directly.
- Sparklines: only the first reading and subsequent successful existing dashboard refreshes are plotted. A single reading is a dot. Up to 12 readings are kept in memory for this visit; there is no fabricated historical trend or extra API request.
- Cards: short staggered entrances, a small hover lift, gradient icon tiles, and a fading accent glow. Overstay emphasis runs briefly when the count becomes positive, then remains a static tint.
- Navigation: an active marker slides from the previous link on desktop; icons nudge on hover; the phone drawer closes over 240ms while retaining its keyboard focus rules.
- Status/header: Online and unread indicators pulse twice, then stop. Notifications and profile menus use a scale-fade entrance.
- Table/refresh: the first six rows enter with a short stagger; hover highlights the row. Manual refresh shows shimmer and a rotating icon while retaining previous data. The successful update timestamp fades in.
- Overlays: menus, dialogs, and toasts use short transform/opacity entrances. Native route fades and theme transitions are progressive enhancements.

## Limits and accessibility

Interaction transitions use transform and opacity for 180–360ms with ease-out timing. Slow decorative drift (18–24s) and active loading indicators use longer cycles so they do not flash rapidly. Orbs are hidden with the existing brand panel on phones; a third legacy orb is disabled. Status pulses are finite rather than continuous.

Reduced motion disables entrance/count-up/pulse/shimmer animation and native document fades. Hidden tabs pause animation. Data Saver and devices reporting two or fewer CPU threads skip JavaScript animation, count-up, orbs, and decorative card animation. Existing camera previews are excluded from theme snapshots. Counts reserve their width, and no layout dimensions are animated.

Native transitions and the outgoing login check depend on browser support. Unsupported browsers use ordinary navigation and the authenticated success notice. The underlying browser mechanism is documented in [Chrome's cross-document view transition guide](https://developer.chrome.com/docs/web-platform/view-transitions/cross-document). A crossfade does not change server authentication or access decisions.

To run the focused suite against an isolated local review server, use `playwright test --config=playwright.motion.config.js` with the existing E2E environment settings. Never run credential or write tests against the production database.
