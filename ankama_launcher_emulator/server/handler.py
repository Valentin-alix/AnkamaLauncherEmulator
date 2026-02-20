import json
import logging
from dataclasses import dataclass, field
from threading import Timer

from ankama_launcher_emulator.decrypter.crypto_helper import (
    CryptoHelper,
)
from ankama_launcher_emulator.haapi.haapi import (
    get_account_info_by_login,
)
from ankama_launcher_emulator.interfaces.account_game_info import (
    AccountGameInfo,
)
from ankama_launcher_emulator.utils.internet import (
    retry_internet,
)

logger = logging.getLogger()


@dataclass
class AnkamaLauncherHandler:
    infos_by_hash: dict[str, AccountGameInfo] = field(
        init=False, default_factory=lambda: {}
    )
    _timer: list[Timer] = field(init=False, default_factory=list)

    @retry_internet
    def connect(
        self, gameName: str, releaseName: str, instanceId: int, hash: str
    ) -> str:
        return hash

    @retry_internet
    def userInfo_get(self, hash: str) -> str:
        account_info = get_account_info_by_login(self.infos_by_hash[hash].haapi.login)
        if account_info is not None:
            return json.dumps(account_info)
        raise ValueError("<!> Account info not found in settings !")

    @retry_internet
    def settings_get(self, hash: str, key: str) -> str:
        match key:
            case "autoConnectType":
                return '"2"'
            case "language":
                return '"fr"'
            case "connectionPort":
                return '"5555"'
        raise NotImplementedError

    @retry_internet
    def auth_getGameToken(self, hash: str, gameId: int) -> str:
        certificate_datas = CryptoHelper.getStoredCertificate(
            self.infos_by_hash[hash].login
        )["certificate"]
        return self.infos_by_hash[hash].haapi.createToken(gameId, certificate_datas)

    @retry_internet
    def updater_isUpdateAvailable(self, gameSession: str):
        return False

    @retry_internet
    def zaapMustUpdate_get(self, gameSession: str) -> bool:
        return False
