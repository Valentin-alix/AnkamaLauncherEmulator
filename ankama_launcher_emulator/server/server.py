from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import sys
from threading import Lock, Thread
from time import sleep
import uuid
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


sys.path.append(str(Path(__file__).parent.parent.parent))
from ankama_launcher_emulator.consts import DOFUS_PATH, GAME_ID_BY_NAME
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
        def _launch_dofus_exe(game_name: str, hash: str):
            with self._lock_launch_game:
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
                sleep(1)

        print(f"Launch dofus game {login}")
        game_name = "dofus"
        game_id = GAME_ID_BY_NAME[game_name]
        hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[hash] = AccountGameInfo(
            login, game_id, api_key, Haapi(api_key)
        )
        Thread(target=lambda: _launch_dofus_exe(game_name, hash), daemon=True).start()


def main():
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    server.launch_dofus("ezrealeu44700_1@outlook.com")
    server.launch_dofus("ezrealeu44700_2@outlook.com")

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
