from pathlib import Path
import subprocess
import sys
from threading import Thread
from time import sleep
import uuid
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


sys.path.append(str(Path(__file__).parent.parent))
from src.tokens import get_token
from src.consts import DOFUS_PATH
from src.gen_zaap.zaap import ZaapService


class AnkamaLauncherHandler:
    def __init__(self) -> None:
        self.tokens_by_login: dict[str, str] = {}
        self.curr_login: str | None = None
        self.curr_password: str | None = None

    def launch_dofus(self, login: str, password: str):
        self.curr_login = login
        self.curr_password = password
        if not self.tokens_by_login.get(login):
            self.tokens_by_login[login] = get_token(login, password)
        subprocess.Popen(
            [
                DOFUS_PATH,
                "--port=26116",
                "--gameName=dofus",
                "--gameRelease=main",
                "--instanceId=1",
                f"--hash={uuid.uuid4()}",
                "--canLogin=true",
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
        )

    def connect(
        self, gameName: str, releaseName: str, instanceId: int, hash: str
    ) -> str:
        match gameName:
            case "dofus":
                return "102"
        raise NotImplementedError

    def userInfo_get(self, gameSession: str) -> str:
        assert self.curr_login is not None
        return self.curr_login

    def settings_get(self, gameSession: str, key: str) -> str:
        match key:
            case "autoConnectType":
                return "1"
            case "language":
                return "fr"
            case "connectionPort":
                return "5555"
        raise NotImplementedError

    def auth_getGameToken(self, gameSession: str, gameId: int) -> str:
        assert self.curr_login is not None and self.curr_password is not None
        return self.tokens_by_login[self.curr_login]

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
    print("Starting the server...")
    thread = Thread(target=server.serve)
    thread.start()
    sleep(1)
    print("Launch dofus game")
    handler.launch_dofus("ezrealeu44700_1@outlook.com", "7jO3cGjEN4pRY2")
    thread.join()


if __name__ == "__main__":
    main()
