import os
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from signal import SIGTERM
from threading import Thread
from time import sleep
from typing import Any

from psutil import process_iter
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport

from AnkamaLauncherEmulator.ankama_launcher_emulator.proxy.proxy_listener import (
    ProxyListener,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.redirect import (
    run_proxy_config_in_thread,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.server.pending_tracker import (
    PendingConnectionTracker,
)

sys.path.append(str(Path(__file__).parent.parent.parent))

from AnkamaLauncherEmulator.ankama_launcher_emulator.consts import (
    DOFUS_PATH,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.decrypter.crypto_helper import (
    CryptoHelper,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.gen_zaap.zaap import ZaapService
from AnkamaLauncherEmulator.ankama_launcher_emulator.haapi.haapi import Haapi
from AnkamaLauncherEmulator.ankama_launcher_emulator.interfaces.account_game_info import (
    AccountGameInfo,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.interfaces.game_name_enum import (
    GameNameEnum,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.server.handler import (
    AnkamaLauncherHandler,
)

LAUNCHER_PORT = 26116


@dataclass
class AnkamaLauncherServer:
    handler: AnkamaLauncherHandler
    instance_id: int = field(init=False, default=0)
    _server_thread: Thread | None = None
    _dofus_threads: list[Thread] = field(init=False, default_factory=list)
    _source_ip: str | None = field(init=False, default=None)
    _proxy_url: str | None = field(init=False, default=None)
    _proxy_listener: ProxyListener | None = field(init=False, default=None)

    def start(
        self,
        source_ip: str | None = None,
        proxy_listener: ProxyListener | None = None,
        proxy_url: str | None = None,
    ):
        """start the ankama launcher emulator

        Args:
            source_ip (str | None, optional): the local ip, useful to bind to a specific network interface. Defaults to None.
            proxy_url (str | None, optional): HTTP proxy URL (format: http://user:pass@host:port). Defaults to None.
        """
        self._source_ip = source_ip
        self._proxy_url = proxy_url
        self._proxy_listener = proxy_listener

        if self._proxy_listener:
            self._proxy_listener.start(interface_ip=source_ip)
            run_proxy_config_in_thread(
                on_config_intercepted=PendingConnectionTracker().register_connection
            )

        for proc in process_iter():
            if proc.pid == 0:
                continue
            for conns in proc.net_connections(kind="inet"):
                if conns.laddr.port == LAUNCHER_PORT:
                    proc.send_signal(SIGTERM)

        processor = ZaapService.Processor(self.handler)
        transport = TSocket.TServerSocket(host="0.0.0.0", port=LAUNCHER_PORT)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        Thread(target=server.serve, daemon=True).start()

    def launch_dofus(self, login: str) -> int:
        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login=login,
            game_id=102,
            api_key=api_key,
            haapi=Haapi(
                api_key,
                source_ip=self._source_ip,
                login=login,
                proxy_url=self._proxy_url,
            ),
        )

        pid = self._launch_dofus_exe(random_hash)

        if self._proxy_listener:
            PendingConnectionTracker().register_launch()

        return pid

    def _launch_dofus_exe(self, random_hash: str) -> int:
        log_path = os.path.join(
            os.environ["LOCALAPPDATA"],
            "Roaming",
            "zaap",
            "gamesLogs",
            "dofus-dofus3",
            "dofus.log",
        )
        command = [
            DOFUS_PATH,
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

        return self._launch_exe(command, env)

    def _launch_exe(self, command: list[str], env: dict[str, Any]) -> int:
        process = subprocess.Popen(
            command,
            env=os.environ.copy()
            | env,  # original env (without converting to uppercase) + custom zaap env
            start_new_session=True,
        )
        return process.pid


def main():
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    server.launch_dofus("pcserv_blibli_12_2@outlook.fr")

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
