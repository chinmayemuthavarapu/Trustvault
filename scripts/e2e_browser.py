"""End-to-end through the real UI with a real browser: upload, share, download,
revoke while the grantee's page is still open, and check the refusal is recorded.

Optional (needs `pip install playwright && playwright install chromium`):
    python -m scripts.seed --reset && flask --app wsgi run --port 8765 &
    python scripts/e2e_browser.py              # or TV_E2E_URL=https://your-deployment/ (fresh seed data)
"""
import os
import tempfile
from playwright.sync_api import sync_playwright

OUT = tempfile.mkdtemp(prefix="tv-e2e-") + "/"
BASE = os.environ.get("TV_E2E_URL", "http://127.0.0.1:8765/")
errs = []


def login(ctx, user, pw):
    p = ctx.new_page()
    p.on("pageerror", lambda e: errs.append(f"{user}: {e}"))
    p.goto(BASE)
    p.fill("input[name=username]", user)
    p.fill("input[name=password]", pw)
    p.click("button[type=submit]")
    p.wait_for_selector("text=Documents")
    return p


with sync_playwright() as pw:
    b = pw.chromium.launch()
    olivia = login(b.new_context(viewport={"width": 1360, "height": 900}), "olivia", "Copper-Lantern-42")
    victor = login(b.new_context(viewport={"width": 1360, "height": 900}), "victor", "Silent-Meadow-36")

    # Olivia uploads a document
    olivia.click("text=Upload document")
    olivia.set_input_files("dialog input[type=file]", files=[{"name": "board-minutes.txt", "mimeType": "text/plain",
                                                              "buffer": b"Board minutes: confidential"}])
    olivia.fill("dialog input[name=title]", "Board minutes October")
    olivia.click("dialog button:has-text('Upload')")
    olivia.wait_for_selector("h1:has-text('Board minutes October')")
    doc_url = olivia.url
    print("uploaded:", doc_url)

    # Victor tries it before being given access
    victor.goto(doc_url)
    victor.wait_for_timeout(600)
    print("victor before grant:", victor.locator("strong").first.inner_text())

    # Olivia gives Victor access through the people picker
    olivia.fill("input[aria-label='Person to add']", "vic")
    olivia.click(".lookup li button")
    olivia.click("button:has-text('Give access')")
    olivia.wait_for_selector(".people .who:has-text('Victor Shah')")
    print("granted")

    victor.goto(BASE + "#/documents")
    victor.goto(doc_url)
    victor.wait_for_selector("h1:has-text('Board minutes October')")
    with victor.expect_download() as dl:
        victor.click(".actions button:has-text('Download')")
    path = dl.value.path()
    print("victor downloaded:", open(path, "rb").read())

    # Olivia removes access while Victor's page is still open
    olivia.click(".people button:has-text('Remove')")
    olivia.click("dialog button:has-text('Remove access')")
    olivia.wait_for_timeout(600)
    victor.click(".actions button:has-text('Download')")  # same page, no reload
    victor.wait_for_selector(".toast.error")
    print("victor clicks Download after revoke:", victor.locator(".toast.error").inner_text())
    victor.screenshot(path=OUT + "e2e-victor-refused.png")
    r = victor.request.get(doc_url.replace("#/documents/", "api/documents/") + "/download")
    print("victor download after revoke, same tab/session:", r.status)
    victor.reload()
    victor.wait_for_timeout(700)
    print("victor page after revoke:", victor.locator("strong").first.inner_text())
    olivia.reload()
    olivia.wait_for_timeout(900)
    olivia.screenshot(path=OUT + "e2e-olivia-record.png", full_page=True)

    # Admin sees the refusals
    admin = login(b.new_context(viewport={"width": 1360, "height": 900}), "admin", "Granite-Harbor-71")
    admin.goto(BASE + "#/admin/activity")
    admin.wait_for_timeout(500)
    admin.select_option("select >> nth=1", "denied")
    admin.wait_for_timeout(700)
    admin.screenshot(path=OUT + "e2e-admin-refusals.png")
    b.close()
print("\n".join(errs) or "no page errors")
