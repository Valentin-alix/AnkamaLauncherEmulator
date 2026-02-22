import json
import logging
import os
import socket

import frida

from ankama_launcher_emulator.consts import LAUNCHER_PORT, RETRO_PATH
from ankama_launcher_emulator.interfaces.game_name_enum import GameNameEnum

RETRO_CDN = json.dumps(socket.gethostbyname_ex("dofusretro.cdn.ankama.com")[2])


logger = logging.getLogger()


def launch_retro_exe(instance_id: int, random_hash: str, port: int) -> int:
    log_path = os.path.join(os.environ["APPDATA"], "zaap", "gamesLogs", "retro")

    command: list[str | bytes] = [
        RETRO_PATH,
        f"--port={str(LAUNCHER_PORT)}",
        f"--gameName={GameNameEnum.RETRO.value}",
        "--gameRelease=main",
        f"--instanceId={str(instance_id)}",
        f"--gameInstanceKey={random_hash}",
    ]

    logger.info(command)

    env = {
        "ZAAP_CAN_AUTH": "true",
        "ZAAP_GAME": GameNameEnum.RETRO.value,
        "ZAAP_HASH": random_hash,
        "ZAAP_INSTANCE_ID": str(instance_id),
        "ZAAP_LOGS_PATH": log_path,
        "ZAAP_PORT": str(LAUNCHER_PORT),
        "ZAAP_RELEASE": "main",
    }

    pid = frida.spawn(program=command, env=env)

    load_frida_script(pid, port, resume=True)

    return pid


def load_frida_script(pid: int, port: int, resume: bool = False):
    session = frida.attach(pid)
    script = session.create_script(get_source(port))

    def on_message(message, _data):
        if message.get("type") == "send":
            child_pid = message["payload"]
            logger.info(
                f"Processus enfant détecté, injection Frida sur PID {child_pid}"
            )
            load_frida_script(child_pid, port, resume=False)

    script.on("message", on_message)
    script.load()
    if resume:
        frida.resume(pid)


def get_source(port: int) -> str:
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
