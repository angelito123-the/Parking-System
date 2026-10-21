# Frontend design system

The shipped frontend uses EJS templates rendered by Express and plain browser JavaScript. It is not a React application. Existing routes, forms, role checks, queries, scanner logic, and parking eligibility remain the source of truth.

## Shared files

- `public/theme-tokens.css`: navy brand (`#102a46`), typography, spacing, radii, focus, and shadow tokens. Prefer these variables for new visual work.
- `public/design-system.css`: existing component and light/dark status palettes, connected to the shared tokens.
- `public/ui-polish.css`: layout refinements for shared screens and task-specific controls.
- `public/login-theme.css`: login presentation using the same tokens.
- `public/ui-motion.css`: short interaction animations and reduced-motion support.
- `views/partials/header.ejs` and `footer.ejs`: navigation, shared assets, and account controls.
- `public/js/form-feedback.js`: existing inline validation. Preserve form actions, names, constraints, and submitted values.
- `public/js/ui-states.js`: shared loading, empty, error, offline, and success messages.
- `public/js/ui-feedback.js`: dismissible success/error notices and keyboard access to scrollable tables. Messages use text nodes, never HTML from an API.

## Rules

Use navy for primary actions, neutral outlines for secondary actions, and explicit text alongside operational colors. Keep destructive actions visually separate. Use 44px minimum touch controls, with larger scanner actions. Tables scroll within their own labeled region and retain their column headings. Inputs must retain visible labels and error descriptions. Respect reduced motion and keyboard focus.

Parking occupancy and space type are separate: a reserved space may also be occupied or disabled. “Blocked” is a display label for the existing disabled state, not a new database value. Physical basketball and hangar layouts remain available.

When changing asset versions, update `public/sw.js` and the relevant templates together. Authenticated pages and API responses must remain outside the offline cache.

## Screen behavior

The parking map and table display the same filtered inventory. Both select the existing inspector and history; changing views does not save or assign anything. Search matches the existing slot, zone, vehicle, and student fields. The Reserved filter matches space type independently of availability. Configuration and zone warning forms follow the monitoring panel, keeping daily tasks near the top.

Dashboard and parking refresh buttons show a busy state and a dismissible result. Failed refreshes keep the previous data visible and identify it as stale. Automatic refreshes update the inline indicator without repeated toast messages. Existing server-rendered form results remain visible alongside the toast; no success is announced before the server responds.

Loading placeholders retain a readable message. Decorative skeletons are hidden from screen readers and stop animating with reduced motion. Scanner results retain the existing status titles, with stronger borders and readable text in both themes. Permission errors, inference, gate selection, and entry/exit decisions keep their existing logic.

## Validation

Use isolated local review databases for browser checks. Verify login, role navigation, parking selection, history, visitor forms, directory actions, and camera startup/permission recovery at phone, tablet, and desktop widths. Run accessibility checks in light and dark themes and verify normal and reduced motion. Never run browser write tests against Render or production TiDB.

Review limitation (2026-10-22): a long interruption of the local review run ended with an unhandled `ECONNRESET` in `express-mysql-session`, stopping both Node 24 preview servers. Restarting restored service. Session-store disconnect handling needs a separate backend investigation; this frontend change does not modify authentication or database handling. This was observed locally, not verified on Render. Camera checks use simulated media; test real phones and outdoor lighting before relying on the visual review alone.
