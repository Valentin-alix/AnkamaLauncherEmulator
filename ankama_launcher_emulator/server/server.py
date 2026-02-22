import json
import logging
import os
import socket
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from random import randint
from signal import SIGTERM
from threading import Thread
from typing import Any

import frida
from psutil import process_iter
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport

from ankama_launcher_emulator.proxy.proxy_listener import (
    ProxyListener,
)
from ankama_launcher_emulator.proxy.retro_proxy import RetroServer
from ankama_launcher_emulator.redirect import (
    run_proxy_config_in_thread,
)
from ankama_launcher_emulator.server.pending_tracker import (
    PendingConnectionTracker,
)
from ankama_launcher_emulator.utils.proxy import get_info_by_proxy_url

sys.path.append(str(Path(__file__).parent.parent.parent))

from ankama_launcher_emulator.consts import (
    DOFUS_PATH,
    RETRO_PATH,
)
from ankama_launcher_emulator.decrypter.crypto_helper import (
    CryptoHelper,
)
from ankama_launcher_emulator.gen_zaap.zaap import ZaapService
from ankama_launcher_emulator.haapi.haapi import Haapi
from ankama_launcher_emulator.interfaces.account_game_info import (
    AccountGameInfo,
)
from ankama_launcher_emulator.interfaces.game_name_enum import (
    GameNameEnum,
)
from ankama_launcher_emulator.server.handler import (
    AnkamaLauncherHandler,
)

LAUNCHER_PORT = 26116

RETRO_CDN = json.dumps(socket.gethostbyname_ex("dofusretro.cdn.ankama.com")[2])


logger = logging.getLogger()


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
        logger.info(f"Thrift server listening on port {LAUNCHER_PORT}")

    def launch_dofus(
        self,
        login: str,
        proxy_listener: ProxyListener,
        proxy_url: str | None = None,
        interface_ip: str | None = None,
    ) -> int:
        logger.info(f"Launching {login} on dofus 3")
        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login=login,
            game_id=102,
            api_key=api_key,
            haapi=Haapi(
                api_key, interface_ip=interface_ip, login=login, proxy_url=proxy_url
            ),
        )

        connection_port = proxy_listener.start(port=0, interface_ip=interface_ip)

        PendingConnectionTracker().register_launch(port=connection_port)
        return self._launch_dofus_exe(random_hash, connection_port=connection_port)

    def _launch_dofus_exe(self, random_hash: str, connection_port: int) -> int:
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
            str(connection_port),
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

    def launch_retro(
        self,
        login: str,
        proxy_url: str | None = None,
        interface_ip: str | None = None,
    ) -> int:
        logger.info(f"Launching {login} on retro")

        port = randint(57000, 63000)

        if proxy_url:
            parsed = get_info_by_proxy_url(proxy_url)
            retro_server = RetroServer(
                self.handler,
                port,
                interface_ip,
                parsed.hostname,
                parsed.port,
                parsed.username,
                parsed.password,
            )
        else:
            retro_server = RetroServer(self.handler, port, interface_ip)

        retro_server.start()

        random_hash = str(uuid.uuid4())
        self.instance_id += 1

        api_key = CryptoHelper.getStoredApiKey(login)["apikey"]["key"]

        self.handler.infos_by_hash[random_hash] = AccountGameInfo(
            login=login,
            game_id=101,
            api_key=api_key,
            haapi=Haapi(
                api_key, interface_ip=interface_ip, login=login, proxy_url=proxy_url
            ),
        )

        return self._launch_retro_exe(random_hash, port)

    def _launch_retro_exe(self, random_hash: str, port: int) -> int:
        log_path = os.path.join(os.environ["APPDATA"], "zaap", "gamesLogs", "retro")

        command: list[str | bytes] = [
            RETRO_PATH,
            f"--port={str(LAUNCHER_PORT)}",
            f"--gameName={GameNameEnum.RETRO.value}",
            "--gameRelease=main",
            f"--instanceId={str(self.instance_id)}",
            f"--gameInstanceKey={random_hash}",
        ]

        logger.info(command)

        env = {
            "ZAAP_CAN_AUTH": "true",
            "ZAAP_GAME": GameNameEnum.RETRO.value,
            "ZAAP_HASH": random_hash,
            "ZAAP_INSTANCE_ID": str(self.instance_id),
            "ZAAP_LOGS_PATH": log_path,
            "ZAAP_PORT": str(LAUNCHER_PORT),
            "ZAAP_RELEASE": "main",
        }

        pid = frida.spawn(program=command, env=env)

        self.load_frida_script(pid, port, resume=True)

        return pid

    def load_frida_script(self, pid: int, port: int, resume: bool = False):
        session = frida.attach(pid)
        script = session.create_script(self.get_source(port))

        def on_message(message, _data):
            if message.get("type") == "send":
                child_pid = message["payload"]
                logger.info(
                    f"Processus enfant détecté, injection Frida sur PID {child_pid}"
                )
                self.load_frida_script(child_pid, port, resume=False)

        script.on("message", on_message)
        script.load()
        if resume:
            frida.resume(pid)

    def _launch_exe(self, command: list[str] | str, env: dict[str, Any]) -> int:
        process = subprocess.Popen(
            command,
            env=os.environ.copy() | env,
            start_new_session=True,
            cwd=os.path.dirname(command[0]),
        )
        return process.pid

    def get_source(self, port: int) -> str:
        frida_script = f"""
        try{{
            var connect_p = Module.getExportByName(null, 'connect');
            var send_p = Module.getExportByName(null, 'send');
            var socket_send = new NativeFunction(send_p, 'int', ['int', 'pointer', 'int', 'int']);
            var recv_p = Module.getExportByName(null, 'recv');
            var socket_recv = new NativeFunction(recv_p, 'int', ['int', 'pointer', 'int', 'int']);

            Interceptor.attach(connect_p, {{
                onEnter: function (args) {{
                    this.sockfd = args[0];
                    var sockaddr_p = args[1];
                    this.port = 256 * sockaddr_p.add(2).readU8() + sockaddr_p.add(3).readU8();
                    this.addr = "";
                    for (var i = 0; i < 4; i++) {{
                        this.addr += sockaddr_p.add(4 + i).readU8(4);
                        if (i < 3) this.addr += '.';
                    }}
                    if({RETRO_CDN}.includes(this.addr)) return;
                    var newport = {port};
                    sockaddr_p.add(2).writeByteArray([Math.floor(newport / 256), newport % 256]);
                    sockaddr_p.add(4).writeByteArray([127, 0, 0, 1]);
                    this.shouldSend = true;
                }},
                onLeave: function (retval) {{
                    var connect_request = "CONNECT " + this.addr + ":" + this.port + " HTTP/1.0 ";
                    var buf_send = Memory.allocUtf8String(connect_request);
                    this.shouldSend && socket_send(this.sockfd.toInt32(), buf_send, connect_request.length, 0);
                }}
            }});

            Interceptor.attach(Module.getExportByName(null, 'CreateProcessW'), {{
                onEnter: (args) => {{
                    const command = Memory.readUtf16String(args[0]);
                    const type = Memory.readUtf16String(args[1]);
                    if (!command) {{
                        if (type.includes("network") || type.includes("plugins")) this.pid = args[9];
                    }}
                }},
                onLeave: () => {{
                    if (this.pid) {{
                        send(parseInt(this.pid.add(Process.pointerSize * 2).readInt()));
                        delete this.pid;
                    }}
                }}
            }});
        }}
        catch(e){{
            console.log("ERREUR: " + e.message);
        }}
        """
        return frida_script
