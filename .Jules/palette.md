## 2026-01-08 - Adding Loading States to Synchronous Forms
**Learning:** Adding a visual loading state (spinner + disabled button) to a synchronous form submission significantly improves perceived performance and prevents double-submission.
**Action:** When implementing this pattern, ensure the loading state is triggered on the 'submit' event (which only fires if HTML5 validation passes) rather than the 'click' event, to avoid locking the UI on invalid forms. Also, remember that for standard page reloads, the state reset happens automatically when the new page loads.

## 2026-01-08 - Linking Descriptions with aria-describedby
**Learning:** Input fields often have helper text in `<span>` tags. These are invisible to screen readers unless programmatically linked.
**Action:** Always add `id` to the helper text span and `aria-describedby="[id]"` to the input field. This is a low-effort, high-impact accessibility win.

## 2026-01-08 - Toggle Buttons Accessibility
**Learning:** Custom buttons used as toggles (like manual/live mode) lack state indication for screen readers.
**Action:** Use `aria-pressed="true/false"` and update it via JS on click. This transforms a generic button into a semantic toggle switch.

## 2026-01-08 - Explicit Input Constraints
**Learning:** Numerical inputs often lack `min`/`max` attributes, allowing invalid data that crashes the backend.
**Action:** Always add `min` and `max` attributes to `input[type="number"]` when the backend expects a specific range (e.g., 0-21 for flags).
