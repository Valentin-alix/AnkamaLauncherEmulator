from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any
import requests

from src.decrypter.crypto_helper import CryptoHelper
from src.interfaces.deciphered_cert import DecipheredCertifDatas

sys.path.append(str(Path(__file__).parent.parent.parent.parent))


from src.haapi.urls import (
    ANKAMA_ACCOUNT_CREATE_TOKEN,
    ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY,
)
from src.haapi.zaap_version import ZAAP_VERSION


@dataclass
class Haapi:
    api_key: str

    def __post_init__(self):
        self.zaap_session = requests.Session()
        self.zaap_headers = {
            "apikey": self.api_key,
            "if-none-match": "null",
            "user-Agent": f"Zaap {ZAAP_VERSION}",
            "accept": "*/*",
            "accept-encoding": "gzip,deflate",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "accept-language": "fr",
        }
        self.zaap_session.headers.update(self.zaap_headers)

    def signOnWithApiKey(self, game_id: int) -> dict[str, Any]:
        """get users infos"""
        url = ANKAMA_ACCOUNT_SIGN_ON_WITH_API_KEY

        response = self.zaap_session.post(url, json={"game": game_id})
        response.raise_for_status()
        body = response.json()
        return body

    def createToken(self, game_id: int, certif: DecipheredCertifDatas) -> str:
        # https://haapi.ankama.com/json/Ankama/v5/Account/CreateToken?game=1&certificate_id=407269037&certificate_hash=4c4ab1b3684623f7
        """create gameToken based on parameters"""
        url = ANKAMA_ACCOUNT_CREATE_TOKEN
        params = {
            "game": game_id,
            "certificate_id": certif["id"],
            "certificate_hash": CryptoHelper.generateHashFromCertif(certif),
        }
        response = self.zaap_session.get(url, params=params)
        response.raise_for_status()
        body = response.json()
        return body["token"]


if __name__ == "__main__":
    haapi = Haapi("b863b45d-3941-42ca-bffd-9e22db98f36c")
    res = haapi.signOnWithApiKey(102)
    print(res)
