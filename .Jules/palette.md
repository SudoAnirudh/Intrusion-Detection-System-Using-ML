## 2024-05-23 - Accessibility Improvements
**Learning:** Legacy Flask templates often miss basic ARIA attributes. Simple additions like `aria-describedby` for helper text and `aria-pressed` for custom toggle buttons significantly improve screen reader experience without requiring structural changes.
**Action:** When auditing forms, always check if helper text is programmatically associated with inputs. For custom button-based toggles, ensure state is communicated via ARIA attributes.
