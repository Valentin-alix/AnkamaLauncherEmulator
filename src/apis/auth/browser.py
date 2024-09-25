from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import re

from curl_cffi import requests


def getStateFromBrowser(session: requests.Session, code_challenge: str, client_id: str):
    url = (
        "https://auth.ankama.com/login/ankama?code_challenge="
        + str(code_challenge)
        + "&redirect_uri=zaap://login&client_id="
        + client_id
        + "&direct=true&origin_tracker=https://www.ankama-launcher.com/launcher"
    )
    response = session.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    a_tag = soup.find(
        "a",
        href=True,
        string=lambda text: text and "Create an Account" in text,  # type: ignore
    )
    href = a_tag["href"] if a_tag else None  # type: ignore
    match = re.search(r"state%3D([^&]+)", href)  # type: ignore
    refererState = match.group(1) if match else None
    result = soup.find("input", {"name": "state"})["value"]  # type: ignore
    return result + "@" + refererState  # type: ignore


def get_code_from_browser(refererState, login: str, password: str) -> str:
    url = (
        "https://auth.ankama.com/login/ankama/form?origin_tracker=https://www.ankama-launcher.com/launcher&redirect_uri=https://auth.ankama.com/login-authorized?state%3D"
        + refererState
    )
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    page.goto(url)
    page.fill("input#ankama-login", login)
    page.wait_for_timeout(150)
    page.fill("input#ankama-password", password)
    page.wait_for_timeout(150)
    page.click("button[type='submit']")
    page.wait_for_timeout(150)
    response = page.content()
    print("response_content : " + response)
    pattern = r"zaap://login\?code=([A-Za-z0-9\-_]+)"
    match = re.search(pattern, response)
    result = match.group(1)  # type: ignore
    return result
