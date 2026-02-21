from types import SimpleNamespace
from typing import Callable

import psutil
from nicegui import ui

from ankama_launcher_emulator.gui.ui_helpers import set_btn_state, update_card_border
from ankama_launcher_emulator.utils.proxy import validation_proxy_url


def make_game_handler(
    login: str,
    state: SimpleNamespace,
    card: ui.card,
    btn: ui.button,
    ip_select: ui.select,
    proxy_input: ui.input,
    pids: dict[str, int],
    running_attr: str,
    label: str,
    color: str,
    do_launch: Callable,
):
    def on_click():
        if getattr(state, running_attr):
            pid = pids.pop(login, None)
            if pid and psutil.pid_exists(pid):
                psutil.Process(pid).terminate()
            setattr(state, running_attr, False)
            set_btn_state(btn, label, color, running=False)
            update_card_border(state, card)
        else:
            setattr(state, running_attr, True)
            set_btn_state(btn, label, color, running=True)
            update_card_border(state, card)
            source_ip = ip_select.value or None
            raw_proxy = proxy_input.value.strip() or None
            pid = do_launch(source_ip, raw_proxy)
            pids[login] = pid
            ui.notify(f"Launched {label} for {login}", type="positive")

    return on_click


def build_account_card(
    login: str,
    all_interface: dict,
) -> tuple[ui.card, ui.button, ui.button, ui.select, ui.input]:
    card = ui.card().classes("w-full mb-1 border-l-4 border-gray-600")
    with card:
        with ui.row().classes("items-center gap-4 w-full"):
            ui.label(login).classes("font-mono flex-1")
            ip_select = ui.select(
                options=all_interface, label="Local interface"
            ).classes("w-56")
            proxy_input = ui.input(
                label="Proxy URL (socks5://user:pass@host:port)",
                validation={"Proxy URL not valid": validation_proxy_url},
            ).classes("w-128")
            dofus_btn = ui.button("Dofus 3").classes("bg-blue-600 text-white w-24")
            retro_btn = ui.button("Retro").classes("bg-amber-600 text-white w-24")
    return card, dofus_btn, retro_btn, ip_select, proxy_input
