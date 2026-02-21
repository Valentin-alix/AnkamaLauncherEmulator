from types import SimpleNamespace

import psutil
from nicegui import ui

from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.gui.account_card import (
    build_account_card,
    make_game_handler,
)
from ankama_launcher_emulator.gui.ui_helpers import set_btn_state, update_card_border
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

    launched_dofus_pids: dict[str, int] = {}
    launched_retro_pids: dict[str, int] = {}
    states: dict[str, SimpleNamespace] = {
        account["apikey"]["login"]: SimpleNamespace(
            dofus_running=False, retro_running=False
        )
        for account in accounts
    }

    @ui.page("/")
    def index():  # pyright: ignore[reportUnusedFunction]
        ui.label("Ankama Launcher").classes("text-2xl font-bold mb-4")

        if not accounts:
            ui.label("No stored accounts found.").classes("text-red-500")
            return

        cards: dict[str, ui.card] = {}
        dofus_btns: dict[str, ui.button] = {}
        retro_btns: dict[str, ui.button] = {}

        for account in accounts:
            login = account["apikey"]["login"]
            card, dofus_btn, retro_btn, ip_select, proxy_input = build_account_card(
                login, all_interface
            )
            cards[login] = card
            dofus_btns[login] = dofus_btn
            retro_btns[login] = retro_btn

            state = states[login]

            def launch_dofus(source_ip, raw_proxy, _login=login):
                proxy_listener, proxy_url = build_proxy_listener(raw_proxy)
                return server.launch_dofus(
                    _login,
                    proxy_listener=proxy_listener,
                    proxy_url=proxy_url,
                    source_ip=source_ip,
                )

            def launch_retro(source_ip, raw_proxy, _login=login):
                return server.launch_retro(
                    _login, proxy_url=raw_proxy, source_ip=source_ip
                )

            dofus_btn.on_click(
                make_game_handler(
                    login,
                    state,
                    card,
                    dofus_btn,
                    ip_select,
                    proxy_input,
                    launched_dofus_pids,
                    "dofus_running",
                    "Dofus 3",
                    "blue-600",
                    launch_dofus,
                )
            )
            retro_btn.on_click(
                make_game_handler(
                    login,
                    state,
                    card,
                    retro_btn,
                    ip_select,
                    proxy_input,
                    launched_retro_pids,
                    "retro_running",
                    "Retro",
                    "amber-600",
                    launch_retro,
                )
            )

        def _check_game_processes(
            pids: dict[str, int],
            running_attr: str,
            btn_map: dict[str, ui.button],
            label: str,
            color: str,
        ) -> None:
            for login, pid in list(pids.items()):
                if not psutil.pid_exists(pid):
                    del pids[login]
                    setattr(states[login], running_attr, False)
                    set_btn_state(btn_map[login], label, color, running=False)
                    update_card_border(states[login], cards[login])
                    ui.notify(f"{label} ({login}) stopped", type="warning")

        def check_processes() -> None:
            _check_game_processes(
                launched_dofus_pids, "dofus_running", dofus_btns, "Dofus 3", "blue-600"
            )
            print(launched_retro_pids)
            print(retro_btns)
            _check_game_processes(
                launched_retro_pids, "retro_running", retro_btns, "Retro", "amber-600"
            )

        ui.timer(2.0, check_processes)

    ui.run(title="Ankama Launcher", port=8081, reload=False, dark=True)
