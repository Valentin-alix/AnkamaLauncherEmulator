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
    SOCKS5_HOST,
    SOCKS5_PASSWORD,
    SOCKS5_PORT,
    SOCKS5_USERNAME,
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

    def start(self):
        run_proxy_config_in_thread(
            get_next_port=PendingConnectionTracker().pop_next_port
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

    def launch_dofus(
        self,
        login: str,
        proxy_listener: ProxyListener | None = None,
        proxy_url: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login=login,
            game_id=102,
            api_key=api_key,
            haapi=Haapi(api_key, source_ip=source_ip, login=login, proxy_url=proxy_url),
        )

        connection_port: int | None = None
        if proxy_listener is not None:
            connection_port = proxy_listener.start(port=0, interface_ip=source_ip)

        PendingConnectionTracker().register_launch(port=connection_port)
        return self._launch_dofus_exe(random_hash, connection_port=connection_port)

    def _launch_dofus_exe(
        self, random_hash: str, connection_port: int | None = None
    ) -> int:
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
        ]
        if connection_port is not None:
            command += ["--connectionPort", str(connection_port)]

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

    proxy_listener = ProxyListener(
        socks5_host=SOCKS5_HOST,
        socks5_port=SOCKS5_PORT,
        socks5_username=SOCKS5_USERNAME,
        socks5_password=SOCKS5_PASSWORD,
    )
    server.launch_dofus(
        "pcserv_blibli_12_2@outlook.fr",
        proxy_listener=proxy_listener,
        proxy_url="http://090de9c7b643e2e1:x0JriSUK@185.162.130.85:10000",
    )

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
