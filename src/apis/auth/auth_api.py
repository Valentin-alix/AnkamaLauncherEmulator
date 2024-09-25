import json
from pathlib import Path
import sys
import curl_cffi
import curl_cffi.requests


sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from src.apis.auth.browser import get_code_from_browser, getStateFromBrowser
from src.apis.auth.urls import AUTH_TOKEN_URL
from src.apis.auth.utils import (
    ZAAP_VERSION,
    create_code_challenge,
    generate_code_verifier,
)


class AuthApi:
    def get_api_key(self, client_id: str, login: str, password: str) -> str:
        # TODO Get token from json if available

        codeVerifier = generate_code_verifier()
        print("codeVerifier : " + codeVerifier)
        codeChallenge = create_code_challenge(codeVerifier)
        print("codeChallenge : " + codeChallenge)

        zaapVersion = ZAAP_VERSION
        print("zaap version : " + zaapVersion)

        session = curl_cffi.requests.Session(impersonate="chrome")
        state = getStateFromBrowser(session, codeChallenge, client_id)
        stateSplitted = state.split("@")
        print("state : " + stateSplitted[0])
        print("refererState : " + stateSplitted[1])
        code = get_code_from_browser(stateSplitted[1], login, password)
        print("code : " + code)

        payload = (
            "grant_type=authorization_code&code="
            + str(code)
            + "&redirect_uri=zaap://login&client_id="
            + client_id
            + "&code_verifier="
            + str(codeVerifier)
        )
        headers = {
            "User-Agent": "Zaap " + zaapVersion,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = session.post(AUTH_TOKEN_URL, headers=headers, data=payload)
        disctJson = json.loads(response.content.decode("utf-8"))

        access_token = disctJson.get("access_token")
        refresh_token = disctJson.get("refresh_token")
        return access_token


if __name__ == "__main__":
    auth_api = AuthApi()
    api_key = auth_api.get_api_key(
        "102", "ezrealeu44700_1@outlook.com", "7jO3cGjEN4pRY2"
    )
    print(api_key)
