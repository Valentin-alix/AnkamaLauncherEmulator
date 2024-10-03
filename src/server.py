from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import sys
from threading import Thread
from time import sleep
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


sys.path.append(str(Path(__file__).parent.parent))

from src.decrypter.crypto_helper import CryptoHelper
from src.haapi.haapi import Haapi
from src.consts import DOFUS_PATH
from src.gen_zaap.zaap import ZaapService
from src.interfaces.account_game_info import AccountGameInfo
from src.utils import generate_random_hash

GAME_ID_BY_NAME: dict[str, str] = {"dofus": "102"}


@dataclass
class AnkamaLauncherHandler:
    instance_id: int = field(init=False, default=0)
    infos_by_hash: dict[str, AccountGameInfo] = field(
        init=False, default_factory=lambda: {}
    )

    def launch_dofus(self, login: str):
        game_name = "dofus"
        game_id = GAME_ID_BY_NAME[game_name]
        hash = generate_random_hash()
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.infos_by_hash[hash] = AccountGameInfo(
            login, game_id, api_key, Haapi(api_key)
        )

        subprocess.Popen(
            [
                DOFUS_PATH,
                "--port=26116",
                f"--gameName={game_name}",
                "--gameRelease=main",
                f"--instanceId={self.instance_id}",
                f"--hash={hash}",
                "--canLogin=true",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
        )

    def connect(
        self, gameName: str, releaseName: str, instanceId: int, hash: str
    ) -> str:
        return hash

    def userInfo_get(self, hash: str) -> str:
        user_infos = self.infos_by_hash[hash].haapi.signOnWithApiKey(
            int(self.infos_by_hash[hash].gameId)
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


def launch_ankama_launcher() -> tuple[AnkamaLauncherHandler, TServer.TSimpleServer]:
    handler = AnkamaLauncherHandler()
    processor = ZaapService.Processor(handler)

    transport = TSocket.TServerSocket(host="localhost", port=26116)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    return handler, server


def main():
    handler, server = launch_ankama_launcher()
    print("Starting ankama launcher server")
    thread = Thread(target=server.serve, daemon=True)
    thread.start()

    handler.launch_dofus("ezrealeu44700_1@outlook.com")
    print("Launch dofus game")

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
