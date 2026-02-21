from types import SimpleNamespace

from nicegui import ui


def update_card_border(state: SimpleNamespace, card: ui.card) -> None:
    if state.dofus_running or state.retro_running:
        card.classes(add="border-green-500", remove="border-gray-600")
    else:
        card.classes(add="border-gray-600", remove="border-green-500")


def set_btn_state(btn: ui.button, label: str, color: str, *, running: bool) -> None:
    if running:
        btn.set_text("Stop")
        btn.classes(add="bg-red-600", remove=f"bg-{color}")
    else:
        btn.set_text(label)
        btn.classes(add=f"bg-{color}", remove="bg-red-600")
