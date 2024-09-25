from pathlib import Path
import subprocess
import sys
from threading import Thread
from time import sleep
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


sys.path.append(str(Path(__file__).parent.parent))

from src.consts import DOFUS_PATH
from src.apis.auth.auth_api import AuthApi
from src.apis.haapi.haapi import Haapi
from src.gen_zaap.zaap import ZaapService
from src.models.account_game_info import AccountGameInfo
from src.utils import generate_hash

GAME_ID_BY_NAME: dict[str, str] = {"dofus": "102"}


class AnkamaLauncherHandler:
    def __init__(self, haapi: Haapi, auth_api: AuthApi) -> None:
        self.haapi = haapi
        self.auth_api = auth_api
        self.instance_id: int = 0
        self.infos_by_hash: dict[str, AccountGameInfo] = {}

    def launch_dofus(self, login: str, password: str):
        game_name = "dofus"
        game_id = GAME_ID_BY_NAME[game_name]
        hash = generate_hash()
        self.instance_id += 1
        api_key = self.auth_api.get_api_key(game_id, login, password)

        self.infos_by_hash[hash] = AccountGameInfo(login, password, game_id, api_key)

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
        user_infos = self.haapi.sign_on_with_api_key(
            int(self.infos_by_hash[hash].gameId), self.infos_by_hash[hash].api_key
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
        res = self.haapi.create_token(hash, self.infos_by_hash[hash].api_key)
        print(res)
        return str(res)

    def zaapMustUpdate_get(self, gameSession: str) -> bool:
        return False


def launch_ankama_launcher() -> tuple[AnkamaLauncherHandler, TServer.TSimpleServer]:
    haapi = Haapi()
    auth_api = AuthApi()
    handler = AnkamaLauncherHandler(haapi, auth_api)
    processor = ZaapService.Processor(handler)

    transport = TSocket.TServerSocket(host="localhost", port=26116)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    return handler, server


def main():
    handler, server = launch_ankama_launcher()
    print("Starting the server...")
    thread = Thread(target=server.serve)
    thread.start()
    sleep(1)
    print("Launch dofus game")
    handler.launch_dofus("ezrealeu44700_1@outlook.com", "7jO3cGjEN4pRY2")
    thread.join()


if __name__ == "__main__":
    main()
