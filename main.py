import logging

from ankama_launcher_emulator.gui import run_gui

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

if __name__ in {"__main__", "__mp_main__"}:
    run_gui()
