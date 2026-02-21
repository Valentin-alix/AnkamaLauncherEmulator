from typing import Callable

from nicegui import ui

from ankama_launcher_emulator.utils.proxy import validation_proxy_url


def make_game_handler(
    login: str,
    ip_select: ui.select,
    proxy_input: ui.input,
    label: str,
    do_launch: Callable,
):
    def on_click():
        source_ip = ip_select.value or None
        raw_proxy = proxy_input.value.strip() or None
        try:
            do_launch(source_ip, raw_proxy)
            ui.notify(f"Launched {label} for {login}", type="positive")
        except Exception as e:
            ui.notify(f"Failed to launch {label} for {login}: {e}", type="negative")

    return on_click


def build_account_card(
    login: str,
    all_interface: dict,
) -> tuple[ui.button, ui.button, ui.select, ui.input]:
    with ui.card().classes("w-full mb-1"):
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
    return dofus_btn, retro_btn, ip_select, proxy_input
