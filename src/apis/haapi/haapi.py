from pathlib import Path
import sys
from typing import Any
import requests

sys.path.append(str(Path(__file__).parent.parent.parent.parent))


from src.apis.auth.utils import ZAAP_VERSION
from src.apis.haapi.urls import (
    ANKAMA_ACCOUNT_CREATE_TOKEN,
    ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY,
)


class Haapi:
    def sign_on_with_api_key(self, gameId: int, apiKey: str) -> dict[str, Any]:
        """get users infos"""
        url = ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY
        response = requests.post(
            url,
            json={"game": gameId},
            headers={"APIKEY": apiKey, "content-type": "text/plain;charset=UTF-8"},
        )
        body = response.json()
        return body

    def create_token(self, hash: str, apiKey: str) -> str:
        # https://haapi.ankama.com/json/Ankama/v5/Account/CreateToken?game=1&certificate_id=407269037&certificate_hash=4c4ab1b3684623f7
        """create gameToken based on parameters"""
        url = ANKAMA_ACCOUNT_CREATE_TOKEN
        params = {"game": 1, "certificate_hash": "", "certificate_id": ""}
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "apikey": apiKey,
            "If-None-Match": "null",
            "User-Agent": f"Zaap {ZAAP_VERSION}",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "empty",
            "Accept-Language": "fr",
        }
        response = requests.get(url, params=params, headers=headers)
        print(response.content)
        body = response.json()
        print(body)
        return body


if __name__ == "__main__":
    haapi = Haapi()
    res = haapi.sign_on_with_api_key(102, "b863b45d-3941-42ca-bffd-9e22db98f36c")
    print(res)
