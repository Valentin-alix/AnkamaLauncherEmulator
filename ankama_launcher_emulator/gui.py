from urllib.parse import urlparse

from nicegui import ui

from AnkamaLauncherEmulator.ankama_launcher_emulator.decrypter.crypto_helper import (
    CryptoHelper,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.internet_utils import (
    get_available_network_interfaces,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.proxy.proxy_listener import (
    ProxyListener,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.server.handler import (
    AnkamaLauncherHandler,
)
from AnkamaLauncherEmulator.ankama_launcher_emulator.server.server import (
    AnkamaLauncherServer,
)


def _validation_proxy_url(proxy_url: str | None):
    if not proxy_url:
        return True
    parsed = urlparse(proxy_url)
    return parsed.scheme == "socks5"


def _build_proxy_listener(proxy_url: str | None) -> tuple[ProxyListener, str | None]:
    if not proxy_url:
        return ProxyListener(), None
    parsed = urlparse(proxy_url)
    if parsed.scheme == "socks5":
        return ProxyListener(
            socks5_host=parsed.hostname,
            socks5_port=parsed.port,
            socks5_username=parsed.username or None,
            socks5_password=parsed.password or None,
        ), None
    else:
        raise ValueError("Invalid proxy url")


def run_gui() -> None:
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    accounts = CryptoHelper.getStoredApiKeys()
    interfaces = get_available_network_interfaces()

    all_interface = {"Empty": None} | interfaces
    all_interface = {value: key for key, value in all_interface.items()}

    @ui.page("/")
    def index():
        ui.label("Ankama Launcher").classes("text-2xl font-bold mb-4")

        if not accounts:
            ui.label("No stored accounts found.").classes("text-red-500")
            return

        for account in accounts:
            login = account["apikey"]["login"]

            with ui.card().classes("w-full mb-1"):
                with ui.row().classes("gap-4 w-full"):
                    ui.label(login).classes("font-mono flex-1")

                    ip_select = ui.select(
                        options=all_interface,
                        label="Local interface",
                    ).classes("w-56")

                    proxy_input = ui.input(
                        label="Proxy URL (socks5://user:pass@host:port)",
                        placeholder="socks5://user:pass@host:port",
                        validation={"Proxy URL not valid": _validation_proxy_url},
                    ).classes("w-128")

                    def make_launch_handler(
                        _login: str,
                        _ip_select: ui.select,
                        _proxy_input: ui.input,
                    ):
                        def on_launch():
                            source_ip: str | None = _ip_select.value or None
                            raw_proxy = _proxy_input.value.strip() or None
                            proxy_listener, proxy_url = _build_proxy_listener(raw_proxy)
                            server.launch_dofus(
                                _login,
                                proxy_listener=proxy_listener,
                                proxy_url=proxy_url,
                                source_ip=source_ip,
                            )
                            ui.notify(f"Launched {_login}", type="positive")

                        return on_launch

                    ui.button(
                        "Launch",
                        on_click=make_launch_handler(login, ip_select, proxy_input),
                    ).classes("bg-blue-600 text-white")

    ui.run(title="Ankama Launcher", port=8081, reload=False, dark=True)


if __name__ in {"__main__", "__mp_main__"}:
    run_gui()
