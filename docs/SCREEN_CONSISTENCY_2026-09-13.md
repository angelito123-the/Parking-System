# Screen consistency ? 13 September 2026

Standardized the existing student registration, visitor passes, parking-space configuration, user accounts, and account-security screens.

## Shared conventions

- Form actions sit below the fields, align with the form's start edge, and use the same spacing, 44-pixel minimum height, and 14-pixel labels. On narrow screens, form actions stack at full width.
- Editing existing records uses **Save changes**. Creation actions describe the result: **Register student**, **Request visitor pass**, **Add parking space**, and **Create account**. Account actions use **Change password** and **Sign out device**. Student and visitor filter reset links say **Clear filters**.
- Primary actions use blue. Viewing actions such as **View QR** and **View history** use the shared secondary style. Destructive actions use the danger style. Visitor row and queue actions share one template, including button order and wording.
- Visitor approval, rejection, and cancellation now use the same site dialog as student/account deletion and device sign-out. The title names the action, the description explains the effect, and the confirmation button repeats the action label. **Go back** consistently dismisses the dialog without submitting.
- The optional rejection reason remains available in the dialog. It is submitted once with the existing approval_note field and respects the database's 255-character limit. Cancellation no longer asks for a note that its endpoint did not save.
- Confirmation dialogs initially focus **Go back**, keep keyboard focus inside, support Escape, disable interaction with the background, and restore focus to the originating control. Closing a dialog opened from an actions menu returns focus to that menu's button.

## Status colors

| Meaning | Examples | Color |
| --- | --- | --- |
| Valid or available | Approved, Active, Available | Green |
| Waiting or needs attention | Pending, Expired, Occupied | Amber |
| Access denied | Rejected, Revoked, Suspended | Red |
| Current activity | Inside, current device | Blue |
| Inactive or completed | Exited, Cancelled, Disabled | Neutral |

Visitor badges and summary cards use the shared theme colors. The existing labels remain visible, so color is not the only way to interpret a state. Parking inspection status text follows readable capitalization. The visitor overstay description now includes the missing hours unit.

## Implementation and verification

Dialog behavior lives in public/js/confirmation-dialog.js. Visitor actions and status badges use shared EJS partials. Existing form endpoints and authorization rules are preserved. The service-worker cache is v39 and references the updated styles and dialog asset.

- 122 automated tests passed.
- UI browser suite: 44 passed, four platform-specific cases skipped, across desktop and emulated phone light/dark profiles. New checks cover action sizing/alignment, cancelled submissions, keyboard focus, rejection notes, single submission, approval/cancellation wording, and menu focus restoration.
- Camera browser suite: 26 passed.
- Page audit: 39 page/profile checks without detected JavaScript errors, panel overflow, or accessibility violations.
- Final dialog checks: desktop, 390-pixel phone, and 320-pixel dark layouts passed accessibility checks and were visually inspected.

Tests used an isolated local database. Confirmation submissions were intercepted with test responses, and preview screenshots use an example visitor. Physical phones and Safari were not tested. Unrelated local parking-zone changes were preserved and excluded from this deployment.

## Previews

[Registration](screen-consistency/registration-desktop.png), [visitor actions](screen-consistency/visitor-actions-desktop.png), [desktop confirmation](screen-consistency/confirmation-desktop.png), [phone confirmation](screen-consistency/confirmation-phone.png), [320-pixel dark confirmation](screen-consistency/confirmation-phone-dark.png).
