from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.interfaces.account_game_info import AccountGameInfo


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
        return str(user_infos)

    def settings_get(self, hash: str, key: str) -> str:
        match key:
            case "autoConnectType":
                return '"1"'
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

    def zaapMustUpdate_get(self, gameSession: str) -> bool:
        return False
