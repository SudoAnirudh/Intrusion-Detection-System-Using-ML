import time
import subprocess
import os
import signal
import sys
from playwright.sync_api import sync_playwright

def verify_live_monitor_meter():
    # Start the mock app in the background
    # We use setsid to create a new process group so we can kill the whole tree later
    server_process = subprocess.Popen(
        [sys.executable, "mock_app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )

    # Give the server a moment to start
    time.sleep(3)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()

            # Navigate to the page
            print("Navigating to http://127.0.0.1:5000/ids")
            try:
                page.goto("http://127.0.0.1:5000/ids")
            except Exception as e:
                print(f"Failed to connect to server: {e}")
                return

            # Click 'Live Monitor' to reveal the panel
            print("Clicking 'Live Monitor'...")
            page.get_by_role("button", name="Live Monitor").click()

            # Wait for panel to be visible
            live_panel = page.locator("#live-panel")
            live_panel.wait_for(state="visible")

            # Locate the gauge
            gauge = page.locator("#threat-gauge")

            # Verify initial static attributes
            print("Verifying initial attributes...")
            assert gauge.get_attribute("role") == "meter", "Role should be 'meter'"
            assert gauge.get_attribute("aria-valuemin") == "0", "aria-valuemin should be '0'"
            assert gauge.get_attribute("aria-valuemax") == "100", "aria-valuemax should be '100'"

            # Wait for dynamic update (polling every 3s in app, we wait up to 5s)
            print("Waiting for dynamic update...")

            # We expect aria-valuenow to change from initial "0" to something else
            # mock_app.py returns "Normal", so value will be 5-15 roughly.

            def check_update():
                val_now = gauge.get_attribute("aria-valuenow")
                val_text = gauge.get_attribute("aria-valuetext")
                if val_now and val_now != "0" and val_text and "Low Risk" in val_text:
                    return True
                return False

            # Poll for the update
            updated = False
            for i in range(10): # wait up to 10 seconds
                if check_update():
                    updated = True
                    break
                print(f"Waiting... ({i+1}/10)")
                time.sleep(1)

            if not updated:
                print("Gauge did not update as expected.")
                print("Current valuenow:", gauge.get_attribute("aria-valuenow"))
                print("Current valuetext:", gauge.get_attribute("aria-valuetext"))

            assert updated, "Gauge attributes should update dynamically"

            print("Gauge updated successfully!")
            print(f"aria-valuenow: {gauge.get_attribute('aria-valuenow')}")
            print(f"aria-valuetext: {gauge.get_attribute('aria-valuetext')}")

            # Take screenshot
            screenshot_path = "/home/jules/verification/live_monitor_meter.png"
            page.screenshot(path=screenshot_path)
            print(f"Screenshot saved to {screenshot_path}")

            browser.close()

    finally:
        # Kill the server process group
        try:
            os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass

if __name__ == "__main__":
    verify_live_monitor_meter()
