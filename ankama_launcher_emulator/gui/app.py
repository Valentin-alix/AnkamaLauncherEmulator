from nicegui import ui

from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.gui.account_card import (
    build_account_card,
    make_game_handler,
)
from ankama_launcher_emulator.server.handler import AnkamaLauncherHandler
from ankama_launcher_emulator.server.server import AnkamaLauncherServer
from ankama_launcher_emulator.utils.internet import get_available_network_interfaces
from ankama_launcher_emulator.utils.proxy import build_proxy_listener


def run_gui() -> None:
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    accounts = CryptoHelper.getStoredApiKeys()
    interfaces = get_available_network_interfaces()
    all_interface = {v: k for k, v in ({"Empty": None} | interfaces).items()}

    @ui.page("/")
    def index():  # pyright: ignore[reportUnusedFunction]
        ui.label("Ankama Launcher").classes("text-2xl font-bold mb-4")

        if not accounts:
            ui.label("No stored accounts found.").classes("text-red-500")
            return

        for account in accounts:
            login = account["apikey"]["login"]
            dofus_btn, retro_btn, ip_select, proxy_input = build_account_card(
                login, all_interface
            )

            def launch_dofus(
                interface_ip: str, proxy_url: str | None, _login: str = login
            ):
                proxy_listener, proxy_url = build_proxy_listener(proxy_url)
                server.launch_dofus(
                    _login,
                    proxy_listener=proxy_listener,
                    proxy_url=proxy_url,
                    interface_ip=interface_ip,
                )

            def launch_retro(
                interface_ip: str, proxy_url: str | None, _login: str = login
            ):
                server.launch_retro(
                    _login, proxy_url=proxy_url, interface_ip=interface_ip
                )

            dofus_btn.on_click(
                make_game_handler(
                    login, ip_select, proxy_input, "Dofus 3", launch_dofus
                )
            )
            retro_btn.on_click(
                make_game_handler(login, ip_select, proxy_input, "Retro", launch_retro)
            )

    ui.run(title="Ankama Launcher", port=8081, reload=False, dark=True)
