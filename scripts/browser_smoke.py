from __future__ import annotations

import argparse
import re
from io import BytesIO
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MaskGate Playground browser smoke test")
    parser.add_argument("--url", default="http://127.0.0.1:8080/playground")
    parser.add_argument("--screenshot", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    console_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.on(
            "console",
            lambda message: (
                console_errors.append(message.text) if message.type == "error" else None
            ),
        )
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        page.goto(args.url, wait_until="networkidle")

        page.get_by_role("heading", name="Inspect every request before it leaves.").wait_for()
        page.get_by_role("heading", name="What I send").wait_for()
        page.get_by_role("heading", name="What happens next").wait_for()

        page.get_by_role("button", name="load English example").click()
        page.get_by_role("button", name="send request").click()
        page.get_by_text("Preview only. No provider key is configured", exact=False).wait_for()
        outbound = page.locator(".readout pre").first.text_content() or ""
        assert "billing@example.org" not in outbound
        assert re.search(r"<MG:[A-Z2-7]{26}>", outbound)

        page.locator(".file-tool summary").click()
        image_bytes = BytesIO()
        Image.new("RGB", (160, 80), "white").save(image_bytes, format="PNG")
        page.locator("#privacy-file").set_input_files(
            {
                "name": "browser-smoke.png",
                "mimeType": "image/png",
                "buffer": image_bytes.getvalue(),
            }
        )
        page.get_by_role("button", name="sanitize", exact=True).click()
        page.get_by_role("link", name="download browser-smoke.masked.png").wait_for(timeout=30_000)

        if args.screenshot:
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(args.screenshot), full_page=True)
        browser.close()

    assert not console_errors, f"Browser console errors: {console_errors}"
    print("Playground browser smoke passed")


if __name__ == "__main__":
    main()
