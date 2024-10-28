import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, Thread
from time import sleep

from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport

from ankama_launcher_emulator.interfaces.game_name_enum import GameNameEnum

sys.path.append(str(Path(__file__).parent.parent.parent))
from ankama_launcher_emulator.consts import GAME_ID_BY_NAME, DOFUS_BETA, DOFUS_PATH
from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.haapi.haapi import Haapi
from ankama_launcher_emulator.interfaces.account_game_info import AccountGameInfo
from ankama_launcher_emulator.server.handler import AnkamaLauncherHandler
from ankama_launcher_emulator.gen_zaap.zaap import ZaapService


@dataclass
class AnkamaLauncherServer:
    handler: AnkamaLauncherHandler
    instance_id: int = field(init=False, default=0)
    _lock_launch_game: Lock = field(init=False, default_factory=Lock)

    def start(self):
        processor = ZaapService.Processor(self.handler)
        transport = TSocket.TServerSocket(host="localhost", port=26116)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        thread = Thread(target=server.serve, daemon=True)
        thread.start()

    def launch_dofus(self, login: str):
        print(f"Launch dofus game {login}")
        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login, GAME_ID_BY_NAME[GameNameEnum.DOFUS], api_key, Haapi(api_key)
        )
        Thread(target=lambda: self._launch_dofus_exe(random_hash), daemon=True).start()

    def _launch_dofus_exe(self, random_hash: str):
        command = [
            DOFUS_PATH,
            "--port=26116",
            f"--gameName={GameNameEnum.DOFUS}",
            "--gameRelease=main",
            f"--instanceId={self.instance_id}",
            f"--hash={random_hash}",
            "--canLogin=true",
        ]
        self._launch_exe(command)

    def _launch_dofus_beta_exe(self, random_hash: str):
        # FIXME
        command = [
            DOFUS_BETA,
            "--port",
            "26116",
            "--gameName",
            GameNameEnum.DOFUS,
            "--gameRelease",
            "beta",
            "--instanceId",
            f"{self.instance_id}",
            "--hash",
            random_hash,
            "--canLogin",
            "true",
            "-logFile",
            "C:\\Users\\valen\\AppData\\Roaming\\zaap\\gamesLogs\\dofus-beta/dofus.log"
            "--langCode",
            "fr",
            "--autoConnectType",
            "1",
            "--connectionPort",
            "5555",
            "--configUrl",
            "https://dofus2.cdn.ankama.com/config/beta_windows.json",
        ]
        self._launch_exe(command)

    def _launch_exe(self, command: list[str]):
        with self._lock_launch_game:
            subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr, text=True)
            sleep(1)


def main():
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    server.launch_dofus("ezrealeu44700_1@outlook.com")
    # server.launch_dofus("ezrealeu44700_2@outlook.com")

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
