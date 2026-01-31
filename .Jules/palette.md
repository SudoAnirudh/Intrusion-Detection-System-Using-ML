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
