import asyncio
import json
import threading
import winreg
from collections.abc import Callable
from dataclasses import dataclass, field

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

from ankama_launcher_emulator.consts import BASE_CONFIG_URL


def set_proxy(
    enable=True,
    proxy="127.0.0.1:8080",
    exceptions="https://api.openai.com",
):
    """
    Configure le proxy Windows pour l'utilisateur courant.
    enable : True pour activer, False pour désactiver
    proxy : adresse:port du proxy
    exceptions : liste des adresses à exclure, séparées par ';'
    """
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, exceptions)
    print(f"[PROXY] {'activé' if enable else 'désactivé'}")


@dataclass
class ChangeDofusConfig:
    dump_master: DumpMaster
    on_config_intercepted: Callable[[], None] | None = field(default=None)

    async def response(self, flow: http.HTTPFlow):
        if (
            (flow.request.pretty_url == BASE_CONFIG_URL)
            and flow.response
            and flow.response.content
        ):
            datas = json.loads(flow.response.content)
            datas["connectionHosts"] = ["JMBouftou:localhost:5555"]
            flow.response.content = json.dumps(datas).encode()
            print("[PROXY] Config interceptée et modifiée")

            if self.on_config_intercepted:
                self.on_config_intercepted()


async def start_proxy_dofus_config(
    with_logs: bool = False,
    on_config_intercepted: Callable[[], None] | None = None,
):
    opts = options.Options(listen_host="127.0.0.1", listen_port=8080)
    dump_master = DumpMaster(opts, with_termlog=with_logs, with_dumper=with_logs)

    addon = ChangeDofusConfig(dump_master, on_config_intercepted)
    dump_master.addons.add(addon)

    try:
        print("[PROXY] Running MITM HTTP")
        await dump_master.run()
    except KeyboardInterrupt:
        dump_master.shutdown()


def run_proxy_config_in_thread(
    with_logs: bool = False,
    on_config_intercepted: Callable[[], None] | None = None,
) -> threading.Thread:
    thread = threading.Thread(
        target=lambda: asyncio.run(
            start_proxy_dofus_config(with_logs, on_config_intercepted)
        ),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == "__main__":
    thread = run_proxy_config_in_thread(True)
    thread.join()
