"""
tests/test_m8_browser_playwright.py
CryptAudio-Web — Phase M8.3 Real Browser Automation Suite

Executes automated browser verification using Playwright with Google Chrome:
- Initial page loading & theme toggle (#theme-toggle-btn)
- Tab navigation via .nav-link (#dashboard, #embed, #extract, #inspect, #analyze, #about)
- Algorithm cards selection & dynamic parameter controls (.algo-card, #embed-params-panel)
- WAV file upload & client-side validation
- Real-time capacity calculation & debounced backend integration
- Embed button state derivation (disabled until file + message + password are valid)
- End-to-end embedding flow in the browser with file download (#btn-download-stego)
- Extraction tab: auto-detection & explicit extraction (#recovered-message-text)
- Wrong password error notification (toast-container)
- Reset button behavior (data-reset-form)
- Responsive layout across mobile, tablet, and desktop viewports
- Dynamic browser XSS injection attacks against message and filename
"""

from __future__ import annotations

import io
import os
import socket
import tempfile
import threading
import time
import wave
from pathlib import Path
from typing import Generator

import numpy as np
import pytest
import uvicorn
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from app.main import app


def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _create_test_wav_bytes(
    duration_sec: float = 3.0,
    sample_rate: int = 44100,
) -> bytes:
    """Create in-memory PCM WAV bytes."""
    num_samples = int(duration_sec * sample_rate)
    t = np.linspace(0, duration_sec, num_samples, endpoint=False)
    samples = (np.sin(2 * np.pi * 440.0 * t) * 20000.0).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(samples.tobytes())
    return buf.getvalue()


@pytest.fixture(scope="module")
def live_server_url() -> Generator[str, None, None]:
    """Start a live Uvicorn test server in a background thread."""
    port = _find_free_port()
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to bind
    url = f"http://127.0.0.1:{port}"
    max_wait = 10.0
    start = time.time()
    while time.time() - start < max_wait:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Uvicorn test server failed to start within timeout.")

    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def browser() -> Generator[Browser, None, None]:
    """Launch system Google Chrome browser via Playwright."""
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser: Browser) -> Generator[Page, None, None]:
    """Create an isolated browser context and page."""
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    page = context.new_page()
    yield page
    context.close()


# ===========================================================================
# 1. Page Load, Layout, & Theme Navigation
# ===========================================================================

class TestBrowserPageLoadAndUIControls:
    """Verifies page rendering, tabs, theme toggling, and responsive layouts."""

    def test_initial_page_load_and_theme_toggle(self, page: Page, live_server_url: str) -> None:
        """Page loads with correct title, headers, and theme toggle switches dark/light mode."""
        page.goto(live_server_url)

        # Title check
        assert "CryptAudio" in page.title()

        # Check default active view is dashboard
        dashboard_view = page.locator("#view-dashboard")
        assert dashboard_view.is_visible()

        # Check theme toggle button
        theme_btn = page.locator("#theme-toggle-btn")
        assert theme_btn.is_visible()

        # Read initial data-theme on <html>
        html_el = page.locator("html")
        initial_theme = html_el.get_attribute("data-theme") or "light"

        # Click theme toggle
        theme_btn.click()
        page.wait_for_timeout(200)
        toggled_theme = html_el.get_attribute("data-theme")
        assert toggled_theme != initial_theme

        # Toggle back
        theme_btn.click()
        page.wait_for_timeout(200)
        assert html_el.get_attribute("data-theme") == initial_theme

    def test_tab_navigation(self, page: Page, live_server_url: str) -> None:
        """Switching between sidebar navigation links updates active view container properly."""
        page.goto(live_server_url)

        tabs = [
            ("a.nav-link[href='#embed']", "#view-embed"),
            ("a.nav-link[href='#extract']", "#view-extract"),
            ("a.nav-link[href='#inspect']", "#view-inspect"),
            ("a.nav-link[href='#analyze']", "#view-analyze"),
            ("a.nav-link[href='#dashboard']", "#view-dashboard"),
        ]

        for link_selector, view_id in tabs:
            link = page.locator(link_selector)
            link.click()
            page.wait_for_timeout(150)
            view = page.locator(view_id)
            assert view.is_visible(), f"Expected {view_id} to be visible after clicking {link_selector}"

    def test_dashboard_navigation_buttons(self, page: Page, live_server_url: str) -> None:
        """Clicking the feature card navigation buttons on the dashboard redirects to the respective views."""
        page.goto(f"{live_server_url}#dashboard")
        page.wait_for_timeout(200)

        buttons_and_targets = [
            ("button[data-target-view='#embed']", "#view-embed", "#embed"),
            ("button[data-target-view='#extract']", "#view-extract", "#extract"),
            ("button[data-target-view='#inspect']", "#view-inspect", "#inspect"),
            ("button[data-target-view='#analyze']", "#view-analyze", "#analyze"),
        ]

        for btn_selector, view_id, expected_hash in buttons_and_targets:
            # Return to dashboard first
            page.locator("a.nav-link[href='#dashboard']").click()
            page.wait_for_timeout(150)
            assert page.locator("#view-dashboard").is_visible()

            # Click the feature card button
            btn = page.locator(btn_selector)
            btn.click()
            page.wait_for_timeout(150)

            # Verify view is active and visible
            view = page.locator(view_id)
            assert view.is_visible(), f"Expected {view_id} to be visible after clicking {btn_selector}"
            assert expected_hash in page.url

    @pytest.mark.parametrize(
        "width,height",
        [
            (375, 667),   # Mobile
            (768, 1024),  # Tablet
            (1280, 800),  # Desktop
            (1920, 1080), # Full HD Desktop
        ],
    )
    def test_responsive_layout_breakpoints(
        self, page: Page, live_server_url: str, width: int, height: int
    ) -> None:
        """Verify layout renders without horizontal scroll overflow across viewports."""
        page.set_viewport_size({"width": width, "height": height})
        page.goto(live_server_url)
        page.wait_for_load_state("networkidle")

        body_scroll_width = page.evaluate("() => document.body.scrollWidth")
        body_client_width = page.evaluate("() => document.documentElement.clientWidth")
        assert body_scroll_width <= body_client_width + 1, (
            f"Horizontal overflow detected at {width}x{height}: scrollWidth={body_scroll_width}, clientWidth={body_client_width}"
        )


# ===========================================================================
# 2. Algorithm Selection & Dynamic Parameter Controls
# ===========================================================================

class TestBrowserAlgorithmSelectionAndParameters:
    """Verifies algorithm cards, dynamic sliders, and parameter updates."""

    def test_algorithm_cards_toggle_and_parameters_display(self, page: Page, live_server_url: str) -> None:
        """Clicking algorithm cards updates selected state and displays relevant controls."""
        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        card_lsb = page.locator(".algo-card[data-algo='lsb']")
        card_dwt = page.locator(".algo-card[data-algo='dwt_dct_qim']")
        card_echo = page.locator(".algo-card[data-algo='echo']")

        params_panel = page.locator("#embed-params-panel")
        params_dwt = page.locator("#embed-params-dwt")
        params_echo = page.locator("#embed-params-echo")

        # Default is LSB: params hidden
        assert "active" in card_lsb.get_attribute("class")
        assert not params_panel.is_visible()

        # Select DWT-DCT-QIM
        card_dwt.click()
        page.wait_for_timeout(150)
        assert "active" in card_dwt.get_attribute("class")
        assert params_panel.is_visible()
        assert params_dwt.is_visible()
        assert not params_echo.is_visible()

        # Select Echo Hiding
        card_echo.click()
        page.wait_for_timeout(150)
        assert "active" in card_echo.get_attribute("class")
        assert params_panel.is_visible()
        assert not params_dwt.is_visible()
        assert params_echo.is_visible()

        # Return to LSB
        card_lsb.click()
        page.wait_for_timeout(150)
        assert "active" in card_lsb.get_attribute("class")
        assert not params_panel.is_visible()


# ===========================================================================
# 3. Dynamic Capacity & Stale Response Protection
# ===========================================================================

class TestBrowserCapacityAndAsyncGuards:
    """Verifies file upload, capacity calculation, and stale response guards in browser."""

    def test_file_upload_and_authoritative_capacity(
        self, page: Page, live_server_url: str
    ) -> None:
        """Selecting a WAV and typing a message triggers authoritative capacity update."""
        carrier_bytes = _create_test_wav_bytes(duration_sec=2.0)

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # Upload carrier file via file input using in-memory buffer
        file_input = page.locator("#embed-file-input")
        file_input.set_input_files({
            "name": "carrier_browser.wav",
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.wait_for_timeout(600)

        # Verify carrier file preview rendered
        carrier_preview = page.locator("#embed-file-preview")
        assert carrier_preview.is_visible()

        # Type message
        msg_textarea = page.locator("#embed-message-input")
        msg_textarea.fill("Secret Browser Payload 2026")
        page.wait_for_timeout(800)  # Wait for debounced capacity API call

        # Check capacity text and values
        capacity_percent = page.locator("#embed-capacity-percent")
        assert capacity_percent.is_visible()
        assert "%" in capacity_percent.text_content()

        max_cap = page.locator("#embed-cap-max-plaintext")
        assert max_cap.is_visible()
        assert max_cap.text_content() != "—"

        # Embed button should become enabled now that carrier is uploaded, message is typed, and capacity is verified
        embed_btn = page.locator("#btn-embed-submit")
        assert not embed_btn.is_disabled()

        # Clicking submit without entering a password triggers validation toast
        embed_btn.click()
        page.wait_for_timeout(300)
        toast = page.locator("#toast-container .toast-error")
        assert toast.is_visible()
        assert "Passphrase" in toast.text_content()

        # Clearing the message should disable the embed button again
        msg_textarea.fill("")
        page.wait_for_timeout(300)
        assert embed_btn.is_disabled()


# ===========================================================================
# 4. Live End-to-End In-Browser Embedding, File Download & Extraction
# ===========================================================================

class TestBrowserEndToEndEmbeddingAndExtraction:
    """Verifies embedding, download, and extraction flows in the browser."""

    def test_in_browser_embedding_and_extraction(
        self, page: Page, live_server_url: str, tmp_path: Path
    ) -> None:
        """Performs full browser workflow: Embed -> Download Stego -> Extract -> Recover Plaintext."""
        carrier_bytes = _create_test_wav_bytes(duration_sec=3.0)
        secret_message = "Confidential Browser Intelligence 2026! 🚀"
        secret_password = "Super_Secure_Browser_Password_123"

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # 1. Fill Embed form
        page.locator("#embed-file-input").set_input_files({
            "name": "e2e_carrier.wav",
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.locator("#embed-message-input").fill(secret_message)
        page.locator("#embed-password-input").fill(secret_password)
        page.wait_for_timeout(800)

        # 2. Click Embed button
        embed_btn = page.locator("#btn-embed-submit")
        assert not embed_btn.is_disabled()
        embed_btn.click()

        # Wait for results card to appear
        result_card = page.locator("#embed-result-card")
        result_card.wait_for(state="visible", timeout=10000)
        assert result_card.is_visible()

        # Trigger download via #btn-download-stego
        download_btn = page.locator("#btn-download-stego")
        assert download_btn.is_visible()
        with page.expect_download() as download_info:
            download_btn.click()

        download = download_info.value
        stego_download_path = tmp_path / "downloaded_stego.wav"
        download.save_as(str(stego_download_path))
        assert stego_download_path.is_file()
        assert stego_download_path.stat().st_size > 0

        # 3. Switch to Extract Tab
        page.locator("a.nav-link[href='#extract']").click()
        page.wait_for_timeout(300)

        # Upload downloaded stego file
        page.locator("#extract-file-input").set_input_files(str(stego_download_path))
        page.locator("#extract-password-input").fill(secret_password)
        page.wait_for_timeout(300)

        # Click Extract button
        extract_btn = page.locator("#btn-extract-submit")
        extract_btn.click()

        # Wait for recovered message card
        extract_result_card = page.locator("#extract-result-card")
        extract_result_card.wait_for(state="visible", timeout=10000)

        # Verify extracted message matches
        recovered_text_el = page.locator("#recovered-message-text")
        assert recovered_text_el.is_visible()
        assert recovered_text_el.text_content().strip() == secret_message

    def test_wrong_password_displays_error_notification_without_leak(
        self, page: Page, live_server_url: str, tmp_path: Path
    ) -> None:
        """Wrong password in Extract tab displays error notification and leaves message hidden."""
        carrier_bytes = _create_test_wav_bytes(duration_sec=2.0)
        secret_message = "Hidden Corporate Secret 2026"
        correct_password = "Correct_Pass_2026"

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # Embed
        page.locator("#embed-file-input").set_input_files({
            "name": "carrier_wrong_pwd.wav",
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.locator("#embed-message-input").fill(secret_message)
        page.locator("#embed-password-input").fill(correct_password)
        page.wait_for_timeout(800)

        page.locator("#btn-embed-submit").click()
        page.locator("#embed-result-card").wait_for(state="visible", timeout=10000)

        with page.expect_download() as download_info:
            page.locator("#btn-download-stego").click()

        stego_path = tmp_path / "stego_wrong_pwd.wav"
        download_info.value.save_as(str(stego_path))

        # Switch to Extract tab and use wrong password
        page.locator("a.nav-link[href='#extract']").click()
        page.locator("#extract-file-input").set_input_files(str(stego_path))
        page.locator("#extract-password-input").fill("Completely_Wrong_Password")
        page.locator("#btn-extract-submit").click()
        page.wait_for_timeout(1500)

        # Toast notification should appear
        toast_container = page.locator("#toast-container")
        assert toast_container.is_visible()

        # Decrypted message result must NOT be visible
        extract_result_card = page.locator("#extract-result-card")
        assert not extract_result_card.is_visible()

        # Secret message must never exist anywhere in the page DOM
        assert secret_message not in page.content()

    def test_reset_button_clears_form_and_restores_state(
        self, page: Page, live_server_url: str
    ) -> None:
        """Clicking Reset button clears inputs and restores default state."""
        carrier_bytes = _create_test_wav_bytes(duration_sec=1.0)

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # Fill inputs
        page.locator("#embed-file-input").set_input_files({
            "name": "reset_carrier.wav",
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.locator("#embed-message-input").fill("Message to reset")
        page.locator("#embed-password-input").fill("Password123")
        page.wait_for_timeout(500)

        # Click Reset button
        reset_btn = page.locator("button[data-reset-form='form-embed']")
        reset_btn.click()
        page.wait_for_timeout(300)

        # Inputs should be empty
        assert page.locator("#embed-message-input").input_value() == ""
        assert page.locator("#embed-password-input").input_value() == ""
        assert page.locator("#btn-embed-submit").is_disabled()


# ===========================================================================
# 5. Live Browser XSS Testing (Execution Prevention)
# ===========================================================================

class TestBrowserCrossSiteScripting:
    """
    Executes live browser-based XSS injection attacks against user-controlled
    messages, filenames, and parameters to verify executable HTML/JS prevention.
    """

    def test_xss_in_message_renders_safely_as_text_in_browser(
        self, page: Page, live_server_url: str, tmp_path: Path
    ) -> None:
        """
        An XSS payload embedded in stego audio and extracted in the browser
        must be rendered strictly as text and NEVER executed by the browser engine.
        """
        carrier_bytes = _create_test_wav_bytes(duration_sec=3.0)

        # Malicious XSS vectors
        xss_payload = (
            "<script>window.__xss_flag = true;</script>"
            "<img src='invalid' onerror='window.__img_xss_flag = true;'>"
            "<svg onload='window.__svg_xss_flag = true;'>"
        )
        pwd = "XSS_Test_Password_2026"

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # Embed malicious payload
        page.locator("#embed-file-input").set_input_files({
            "name": "xss_carrier.wav",
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.locator("#embed-message-input").fill(xss_payload)
        page.locator("#embed-password-input").fill(pwd)
        page.wait_for_timeout(800)

        page.locator("#btn-embed-submit").click()
        page.locator("#embed-result-card").wait_for(state="visible", timeout=10000)

        with page.expect_download() as download_info:
            page.locator("#btn-download-stego").click()

        stego_path = tmp_path / "stego_xss.wav"
        download_info.value.save_as(str(stego_path))

        # Switch to Extract tab
        page.locator("a.nav-link[href='#extract']").click()
        page.locator("#extract-file-input").set_input_files(str(stego_path))
        page.locator("#extract-password-input").fill(pwd)
        page.locator("#btn-extract-submit").click()

        page.locator("#extract-result-card").wait_for(state="visible", timeout=10000)

        # Verify extracted text box displays the literal characters
        result_el = page.locator("#recovered-message-text")
        assert result_el.is_visible()
        assert "<script>" in result_el.text_content()

        # CRITICAL XSS EXECUTION ASSERTIONS:
        # None of the injected scripts must have executed in the JavaScript context
        assert page.evaluate("() => window.__xss_flag") is None
        assert page.evaluate("() => window.__img_xss_flag") is None
        assert page.evaluate("() => window.__svg_xss_flag") is None

    def test_xss_in_carrier_filename_renders_safely_in_browser(
        self, page: Page, live_server_url: str
    ) -> None:
        """
        A carrier WAV whose filename contains HTML / JS tags must not execute when
        rendered in the carrier inspection card.
        """
        carrier_bytes = _create_test_wav_bytes(duration_sec=1.0)
        malicious_filename = "carrier_<img src=x onerror=window.__filename_xss=true>.wav"

        page.goto(live_server_url + "/#embed")
        page.wait_for_timeout(200)

        # Upload using Playwright in-memory buffer with virtual filename
        page.locator("#embed-file-input").set_input_files({
            "name": malicious_filename,
            "mimeType": "audio/wav",
            "buffer": carrier_bytes,
        })
        page.wait_for_timeout(600)

        # Verify file preview is visible
        preview = page.locator("#embed-file-preview")
        assert preview.is_visible()

        # CRITICAL: window.__filename_xss must NOT be set
        assert page.evaluate("() => window.__filename_xss") is None
