## 2026-01-08 - Adding Loading States to Synchronous Forms
**Learning:** Adding a visual loading state (spinner + disabled button) to a synchronous form submission significantly improves perceived performance and prevents double-submission.
**Action:** When implementing this pattern, ensure the loading state is triggered on the 'submit' event (which only fires if HTML5 validation passes) rather than the 'click' event, to avoid locking the UI on invalid forms. Also, remember that for standard page reloads, the state reset happens automatically when the new page loads.

## 2026-01-08 - Linking Descriptions with aria-describedby
**Learning:** Input fields often have helper text in `<span>` tags. These are invisible to screen readers unless programmatically linked.
**Action:** Always add `id` to the helper text span and `aria-describedby="[id]"` to the input field. This is a low-effort, high-impact accessibility win.

## 2026-01-22 - Toggle Buttons and ARIA State
**Learning:** Buttons that function as toggles (e.g., switching modes) require the `aria-pressed` attribute to communicate their state to screen readers. Visual indication (active class) is not enough.
**Action:** Initialize `aria-pressed="true/false"` on the buttons and ensure the JavaScript handler updates these attributes synchronously with visual state changes.
