from datetime import datetime
import json
from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.interfaces.account_game_info import AccountGameInfo

from dateutil.parser import isoparse
from dataclasses import dataclass, field


@dataclass
class AnkamaLauncherHandler:
    infos_by_hash: dict[str, AccountGameInfo] = field(
        init=False, default_factory=lambda: {}
    )

    def connect(
        self, gameName: str, releaseName: str, instanceId: int, hash: str
    ) -> str:
        return hash

    def userInfo_get(self, hash: str) -> str:
        user_infos = self.infos_by_hash[hash].haapi.signOnWithApiKey(
            int(self.infos_by_hash[hash].game_id)
        )
        sent_from_official_launcher = isoparse(user_infos["game"]["added_date"])
        {
            "id": 181213928,
            "type": "ANKAMA",
            "login": "ezrealeu44700_2@outlook.com",
            "nickname": "ezrealeuTwo",
            "firstname": "A*****",
            "lastname": "V*****",
            "nicknameWithTag": "ezrealeuTwo#2379",
            "tag": 2379,
            "security": ["SHIELD"],
            "addedDate": "2024-08-17T14:07:55+02:00",
            "locked": "0",
            "parentEmailStatus": None,
            "avatar": "https://avatar.ankama.com/users/181213928.png",
            "isGuest": False,
            "isErrored": False,
            "needRefresh": False,
            "active": True,
            "gameList": [
                {
                    "isFreeToPlay": False,
                    "isFormerSubscriber": False,
                    "isSubscribed": True,
                    "totalPlayTime": 2981065,
                    "endOfSubscribe": "2025-02-19T18:39:05+01:00",
                    "id": 1,
                }
            ],
        }
        expected = {
            "id": user_infos["account"],
            "type": "ANKAMA",
            "login": user_infos["account"]["login"],
            "nickname": user_infos["account"]["nickname"],
            "firstname": user_infos["account"]["firstname"],
            "lastname": user_infos["account"]["lastname"],
            "nicknameWithTag": f"{user_infos['account']['nickname']}#{user_infos['account']['tag']}",
            "tag": user_infos["account"]["tag"],
            "security": user_infos["account"]["security"],
            "addedDate": user_infos["account"]["added_date"],
            "locked": user_infos["account"]["locked"],
            "parentEmailStatus": user_infos["account"]["parent_email_status"],
            "avatar": user_infos["account"]["avatar_url"],
            "isGuest": False,
            "isErrored": False,
            "needRefresh": False,
            "active": user_infos["account"]["is_otp_active"],
            "gameList": [
                {
                    "isFreeToPlay": False,
                    "isFormerSubscriber": False,
                    "isSubscribed": user_infos["game"]["subscribed"],
                    "totalPlayTime": user_infos["game"]["total_time_elapsed"],
                    "endOfSubscribe": user_infos["game"]["expiration_date"],
                    "id": 1,
                }
            ],
        }
        return json.dumps(expected)

    def settings_get(self, hash: str, key: str) -> str:
        match key:
            case "autoConnectType":
                return '"2"'
            case "language":
                return '"fr"'
            case "connectionPort":
                return '"5555"'
        raise NotImplementedError

    def auth_getGameToken(self, hash: str, gameId: int) -> str:
        certificate_datas = CryptoHelper.getStoredCertificate(
            self.infos_by_hash[hash].login
        )["certificate"]
        res = self.infos_by_hash[hash].haapi.createToken(gameId, certificate_datas)
        return res

    def updater_isUpdateAvailable(self, gameSession: str):
        return False

    def zaapMustUpdate_get(self, gameSession: str) -> bool:
        return False
