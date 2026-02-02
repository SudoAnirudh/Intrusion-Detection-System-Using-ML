import time
import subprocess
import os
import signal
from playwright.sync_api import sync_playwright

def verify_gauge():
    # Start the mock app
    # Using preexec_fn=os.setsid to create a new process group so we can kill the whole tree
    process = subprocess.Popen(
        ["python", "mock_app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )

    print("Starting mock app...")
    # Wait for the server to start
    time.sleep(5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            print("Navigating to /ids...")
            try:
                page.goto("http://127.0.0.1:5000/ids")
            except Exception as e:
                print(f"Failed to load page: {e}")
                stdout, stderr = process.communicate()
                print(f"Server stdout: {stdout.decode()}")
                print(f"Server stderr: {stderr.decode()}")
                raise e

            # Check initial state
            gauge = page.locator("#threat-gauge")
            print("Checking initial state...")
            assert gauge.get_attribute("role") == "meter"
            assert gauge.get_attribute("aria-valuemin") == "0"
            assert gauge.get_attribute("aria-valuemax") == "100"
            assert gauge.get_attribute("aria-valuenow") == "0"

            # Click Live Monitor button
            # Note: The button has text "Live Monitor"
            print("Starting Live Monitor...")
            page.click("button:has-text('Live Monitor')")

            # Wait for update (the interval is 3 seconds)
            print("Waiting for gauge update...")
            # We wait for aria-valuenow to NOT be 0
            page.wait_for_function("document.getElementById('threat-gauge').getAttribute('aria-valuenow') !== '0'", timeout=10000)

            valuenow = gauge.get_attribute("aria-valuenow")
            valuetext = gauge.get_attribute("aria-valuetext")

            print(f"Updated valuenow: {valuenow}")
            print(f"Updated valuetext: {valuetext}")

            assert valuenow is not None
            assert valuetext is not None
            assert valuenow != "0"
            assert "Risk Concentration" in valuetext

            # Take screenshot
            os.makedirs("/home/jules/verification", exist_ok=True)
            screenshot_path = "/home/jules/verification/gauge_verification.png"
            page.screenshot(path=screenshot_path)
            print(f"Screenshot saved to {screenshot_path}")

            print("Verification successful!")

    finally:
        # Kill the mock app
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)

if __name__ == "__main__":
    verify_gauge()
