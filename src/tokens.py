from pathlib import Path
import random
import hashlib
import base64
import json
from bs4 import BeautifulSoup
from curl_cffi import requests
import shutil
import re
import os
from playwright.sync_api import sync_playwright

# RE by SuperJudeFruit


def getZaapVersion(getVersionFromLauncher):
    if getVersionFromLauncher:
        # Create tmp dir
        tmpPath = "tmp"
        os.makedirs(tmpPath, exist_ok=True)

        # Extract launcher on tmp dir
        print(Path(tmpPath).absolute())
        os.system(
            f'asar extract "{os.path.join(os.getenv('programfiles', ''), 'Ankama', 'Ankama Launcher','resources', 'app.asar')}" "{Path(tmpPath).absolute()}"'
        )

        # Find launcher version
        zaapVersion = "none"
        with open(os.path.join(tmpPath, "package.json")) as jsonFile:
            disctJson = json.load(jsonFile)
            zaapVersion = disctJson.get("version")

        # Remove tmp folder
        shutil.rmtree(tmpPath)

        if zaapVersion == "none":
            zaapVersion = "3.12.19"
        return zaapVersion
    else:
        return "3.12.19"


def generate_code_verifier():
    ### Native method from Ankama launcher
    e = int(85 * random.random() + 43)
    t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    n = ""
    for r in range(e):
        n += t[int(random.random() * len(t))]
    return n


def create_code_challenge(e):
    ### Native method from Ankama launcher
    hash_object = hashlib.sha256(e.encode())
    hash_digest = hash_object.digest()
    base64_encoded = base64.urlsafe_b64encode(hash_digest).decode("utf-8")
    code_challenge = base64_encoded.rstrip("=").replace("+", "-").replace("/", "_")
    return code_challenge


def getStateFromBrowser(session, codeChallenge, clientId):
    url = (
        "https://auth.ankama.com/login/ankama?code_challenge="
        + str(codeChallenge)
        + "&redirect_uri=zaap://login&client_id="
        + clientId
        + "&direct=true&origin_tracker=https://www.ankama-launcher.com/launcher"
    )
    response = session.get(url)
    # print("response_content : " + response.content.decode('utf-8'))
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


def getCodeFromBrowser(state, refererState, login, password):
    url = (
        "https://auth.ankama.com/login/ankama/form?origin_tracker=https://www.ankama-launcher.com/launcher&redirect_uri=https://auth.ankama.com/login-authorized?state%3D"
        + refererState
    )
    payload = "state=" + str(state) + "&login=" + login + "&password=" + password
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
    }
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


def getApiKey(session, code, clientId, codeVerifier, zaapVersion):
    url = "https://auth.ankama.com/token"
    payload = (
        "grant_type=authorization_code&code="
        + str(code)
        + "&redirect_uri=zaap://login&client_id="
        + clientId
        + "&code_verifier="
        + str(codeVerifier)
    )
    headers = {
        "User-Agent": "Zaap " + zaapVersion,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    response = session.post(url, headers=headers, data=payload)
    print(response.content)
    disctJson = json.loads(response.content.decode("utf-8"))

    access_token = disctJson.get("access_token")
    refresh_token = disctJson.get("refresh_token")
    return access_token


def get_token(login: str, password: str) -> str:
    codeVerifier = generate_code_verifier()
    print("codeVerifier : " + codeVerifier)
    codeChallenge = create_code_challenge(codeVerifier)
    print("codeChallenge : " + codeChallenge)

    clientId = "102"
    zaapVersion = getZaapVersion(True)
    print("zaap version : " + zaapVersion)

    session = requests.Session(impersonate="chrome")
    state = getStateFromBrowser(session, codeChallenge, clientId)
    stateSplitted = state.split("@")
    print("state : " + stateSplitted[0])
    print("refererState : " + stateSplitted[1])
    code = getCodeFromBrowser(stateSplitted[0], stateSplitted[1], login, password)
    print("code : " + code)
    apiKey = getApiKey(session, code, clientId, codeVerifier, zaapVersion)
    print("apiKey : " + apiKey)
    return apiKey


if __name__ == "__main__":
    token = get_token("ezrealeu44700_1@outlook.com", "7jO3cGjEN4pRY2")
    response = f"auth_getGameToken {token}\0"
    print(response)
