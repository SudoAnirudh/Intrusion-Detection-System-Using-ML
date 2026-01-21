## 2026-01-08 - Adding Loading States to Synchronous Forms
**Learning:** Adding a visual loading state (spinner + disabled button) to a synchronous form submission significantly improves perceived performance and prevents double-submission.
**Action:** When implementing this pattern, ensure the loading state is triggered on the 'submit' event (which only fires if HTML5 validation passes) rather than the 'click' event, to avoid locking the UI on invalid forms. Also, remember that for standard page reloads, the state reset happens automatically when the new page loads.

## 2026-01-08 - Linking Descriptions with aria-describedby
**Learning:** Input fields often have helper text in `<span>` tags. These are invisible to screen readers unless programmatically linked.
**Action:** Always add `id` to the helper text span and `aria-describedby="[id]"` to the input field. This is a low-effort, high-impact accessibility win.

## 2026-01-08 - Accessible Toggle Buttons
**Learning:** Custom toggle buttons (like Manual/Live mode switchers) rely on visual cues that screen readers miss.
**Action:** Always add `aria-pressed="true/false"` to these buttons and update the attribute via JavaScript when the state changes.
