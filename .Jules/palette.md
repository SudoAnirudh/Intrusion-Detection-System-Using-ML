## 2026-01-08 - Adding Loading States to Synchronous Forms
**Learning:** Adding a visual loading state (spinner + disabled button) to a synchronous form submission significantly improves perceived performance and prevents double-submission.
**Action:** When implementing this pattern, ensure the loading state is triggered on the 'submit' event (which only fires if HTML5 validation passes) rather than the 'click' event, to avoid locking the UI on invalid forms. Also, remember that for standard page reloads, the state reset happens automatically when the new page loads.

## 2026-01-08 - Linking Descriptions with aria-describedby
**Learning:** Input fields often have helper text in `<span>` tags. These are invisible to screen readers unless programmatically linked.
**Action:** Always add `id` to the helper text span and `aria-describedby="[id]"` to the input field. This is a low-effort, high-impact accessibility win.

## 2026-01-08 - Accessible Toggle Buttons
**Learning:** Custom buttons acting as mode switches need state indication for screen readers. `aria-pressed` is a simple way to indicate "on/off" status for toggle buttons.
**Action:** When implementing view toggles, add `aria-pressed="true/false"` and `aria-controls="[target-id]"`. Ensure JavaScript updates the `aria-pressed` state on click.

## 2026-01-31 - Accessible Live Logs
**Learning:** Dynamic log updates (e.g., scrolling terminals) are invisible to screen readers without specific roles. Also, `overflow: auto` divs are not keyboard-focusable by default.
**Action:** Use `role="log"` and `aria-live="polite"` for the container. Add `tabindex="0"` to ensure keyboard users can focus and scroll the log history.

## 2026-06-15 - Dynamic Meter Accessibility
**Learning:** Visual gauges showing percentage (like threat levels) need `role="meter"` and programmatic updates to `aria-valuenow`.
**Action:** When updating the visual text of a gauge in JS, always update `aria-valuenow` and `aria-valuetext` to ensure screen readers receive the same live data.

## 2026-06-16 - Focus Management for Synchronous Reloads
**Learning:** When a form submits synchronously and reloads the page with a result, screen reader users lose context and start at the top of the page.
**Action:** Add `tabindex="-1"` and `role="status"` to the result container, and use JavaScript to programmatically `focus()` the element on page load.

## 2026-08-12 - Dark Mode Dropdowns & Focus Visibility
**Learning:** Native `<select>` dropdowns in dark themes often default to system colors (white background) for options, creating poor contrast or white-on-white text if `color: white` is set on the parent.
**Action:** Always explicitly style `select option` with the theme's background and text colors. Also, enforcing a global `:focus-visible` ring with `!important` ensures consistent keyboard accessibility without relying on browser defaults which may be invisible on dark backgrounds.
