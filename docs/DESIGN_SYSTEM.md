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

## Rules

Use navy for primary actions, neutral outlines for secondary actions, and explicit text alongside operational colors. Keep destructive actions visually separate. Use 44px minimum touch controls, with larger scanner actions. Tables scroll within their own labeled region and retain their column headings. Inputs must retain visible labels and error descriptions. Respect reduced motion and keyboard focus.

Parking occupancy and space type are separate: a reserved space may also be occupied or disabled. “Blocked” is a display label for the existing disabled state, not a new database value. Physical basketball and hangar layouts remain available.

When changing asset versions, update `public/sw.js` and the relevant templates together. Authenticated pages and API responses must remain outside the offline cache.

## Validation

Use isolated local review databases for browser checks. Verify login, role navigation, parking selection, history, visitor forms, directory actions, and camera startup/permission recovery at phone, tablet, and desktop widths. Run accessibility checks in light and dark themes and verify normal and reduced motion. Never run browser write tests against Render or production TiDB.
