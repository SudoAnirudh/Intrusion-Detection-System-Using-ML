from playwright.sync_api import sync_playwright

def verify_live_monitor_ux():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("http://127.0.0.1:5000/ids")

        # Click 'Live Monitor' to reveal the panel
        page.get_by_role("button", name="Live Monitor").click()

        # Wait for panel to be visible
        live_panel = page.locator("#live-panel")
        live_panel.wait_for(state="visible")

        # Focus the log terminal to show tabindex functionality
        log_terminal = page.locator("#log-terminal")
        log_terminal.focus()

        # Take screenshot
        screenshot_path = "/home/jules/verification/live_monitor_a11y.png"
        page.screenshot(path=screenshot_path)
        print(f"Screenshot saved to {screenshot_path}")

        browser.close()

if __name__ == "__main__":
    verify_live_monitor_ux()
