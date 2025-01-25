import subprocess
import sys
from typing import Any
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, Thread
from time import sleep
import nt
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport


sys.path.append(str(Path(__file__).parent.parent.parent))
from ankama_launcher_emulator.interfaces.game_name_enum import GameNameEnum
from ankama_launcher_emulator.consts import (
    DOFUS_PATH,
    OFFICIAL_CONFIG_URL,
)
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
    _server_thread: Thread | None = None
    _dofus_threads: list[Thread] = field(init=False, default_factory=list)

    def start(self):
        processor = ZaapService.Processor(self.handler)
        transport = TSocket.TServerSocket(host="0.0.0.0", port=26116)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        Thread(target=server.serve, daemon=True).start()

    def launch_dofus(self, login: str):
        print(f"Launch dofus game {login}")
        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]
        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login=login,
            game_id=102,
            api_key=api_key,
            haapi=Haapi(api_key),
        )
        Thread(target=lambda: self._launch_dofus_exe(random_hash), daemon=True).start()

    def _launch_dofus_exe(
        self,
        random_hash: str,
        config_url: str = OFFICIAL_CONFIG_URL,
    ):
        log_path = (
            r"C:\Users\valen\AppData\Roaming\zaap\gamesLogs\dofus-dofus3/dofus.log"
        )
        command = [
            "Dofus.exe",
            "--port",
            "26116",
            "--gameName",
            GameNameEnum.DOFUS.value,
            "--gameRelease",
            "dofus3",
            "--instanceId",
            str(self.instance_id),
            "--hash",
            random_hash,
            "--canLogin",
            "true",
            "-logFile",
            log_path,
            "--langCode",
            "fr",
            "--autoConnectType",
            "2",
            "--connectionPort",
            "5555",
            "--configUrl",
            config_url,
        ]
        env = {
            "ZAAP_CAN_AUTH": "true",
            "ZAAP_GAME": GameNameEnum.DOFUS.value,
            "ZAAP_HASH": random_hash,
            "ZAAP_INSTANCE_ID": str(self.instance_id),
            "ZAAP_LOGS_PATH": log_path,
            "ZAAP_PORT": "26116",
            "ZAAP_RELEASE": "dofus3",
        }

        self._launch_exe(command, env)

    def _launch_exe(self, command: list[str], env: dict[str, Any]):
        with self._lock_launch_game:
            subprocess.Popen(
                command,
                cwd=Path(DOFUS_PATH).parent,
                env=nt.environ.copy()
                | env,  # original env (without converting to uppercase) + custom zaap env
                start_new_session=True,
                shell=True,
            )
            sleep(1)


def main():
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    # server.launch_dofus("ezrealeu44700_1+s1@outlook.com")
    server.launch_dofus("ezrealeu44700_2@outlook.com")

    while True:
        sleep(1)


if __name__ == "__main__":
    # ./Ankama\ Launcher.exe --inspect --remote-debugging-port=8315
    main()
