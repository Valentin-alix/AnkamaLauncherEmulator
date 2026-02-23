import sys
from pathlib import Path
from typing import Callable, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    InfoBar,
    InfoBarPosition,
    Theme,
    TitleLabel,
    setTheme,
)

from ankama_launcher_emulator.decrypter.crypto_helper import CryptoHelper
from ankama_launcher_emulator.gui.account_card import AccountCard
from ankama_launcher_emulator.gui.consts import DOFUS_3_TITLE, DOFUS_RETRO_TITLE
from ankama_launcher_emulator.gui.game_selector_card import GameSelectorCard
from ankama_launcher_emulator.gui.utils import run_in_background
from ankama_launcher_emulator.server.handler import AnkamaLauncherHandler
from ankama_launcher_emulator.server.server import AnkamaLauncherServer
from ankama_launcher_emulator.utils.internet import get_available_network_interfaces
from ankama_launcher_emulator.utils.proxy import build_proxy_listener

_RESOURCES = Path(__file__).parent.parent.parent / "resources"


class MainWindow(QMainWindow):
    def __init__(
        self, server: AnkamaLauncherServer, accounts: list, all_interface: dict
    ):
        super().__init__()
        self._server = server
        self._setup_ui(accounts, all_interface)

    def _setup_ui(self, accounts: list, all_interface: dict) -> None:
        self.setWindowTitle("Ankama Launcher")
        self.setMinimumWidth(800)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        if not accounts:
            label = BodyLabel("No stored accounts found.")
            label.setStyleSheet("color: #ef4444;")
            layout.addWidget(label)
            return

        self._dofus_selector = GameSelectorCard(
            DOFUS_3_TITLE, _RESOURCES / "Dofus3.png", True
        )
        self._retro_selector = GameSelectorCard(
            DOFUS_RETRO_TITLE, _RESOURCES / "DofusRetro.png", False
        )
        self._dofus_selector.clicked.connect(lambda: self._select_game(is_dofus_3=True))
        self._retro_selector.clicked.connect(
            lambda: self._select_game(is_dofus_3=False)
        )

        selector_row = QHBoxLayout()
        selector_row.setSpacing(12)
        selector_row.addWidget(self._dofus_selector)
        selector_row.addWidget(self._retro_selector)
        layout.addLayout(selector_row)

        self._title_label = TitleLabel(DOFUS_3_TITLE)
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._title_label)

        self._stack = QStackedWidget()
        self._dofus_page = self._make_game_page(
            accounts, all_interface, self._launch_dofus
        )
        self._retro_page = self._make_game_page(
            accounts, all_interface, self._launch_retro
        )
        self._stack.addWidget(self._dofus_page)
        self._stack.addWidget(self._retro_page)
        layout.addWidget(self._stack)

    def _select_game(self, is_dofus_3: bool) -> None:
        self._title_label.setText(DOFUS_3_TITLE if is_dofus_3 else DOFUS_RETRO_TITLE)
        self._dofus_selector.set_active(is_dofus_3)
        self._retro_selector.set_active(not is_dofus_3)
        self._stack.setCurrentWidget(
            self._dofus_page if is_dofus_3 else self._retro_page
        )

    def _make_game_page(
        self,
        accounts: list,
        all_interface: dict,
        launch: Callable[[str, str | None, str | None], str],
    ) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(8)

        for account in accounts:
            login = account["apikey"]["login"]
            card = AccountCard(login, all_interface, page)
            card.launch_requested.connect(
                self._make_launch_handler(launch, login, card)
            )
            card.error_occurred.connect(self._show_error)
            layout.addWidget(card)

        layout.addStretch()
        return page

    def _make_launch_handler(
        self,
        launch: Callable[[str, str | None, str | None], str],
        login: str,
        card: AccountCard,
    ) -> Callable[[object, object], None]:
        def handler(iface: object, proxy: object) -> None:
            def on_success(result: object) -> None:
                self._show_success(str(result))
                card.set_launch_enabled(True)

            def on_error(err: object) -> None:
                self._show_error(str(err))
                card.set_launch_enabled(True)

            run_in_background(
                lambda: launch(
                    login,
                    cast(str | None, iface),
                    cast(str | None, proxy),
                ),
                on_success=on_success,
                on_error=on_error,
                parent=self,
            )

        return handler

    def _launch_dofus(
        self, login: str, interface_ip: str | None, proxy_url: str | None
    ) -> str:
        proxy_listener, proxy_url = build_proxy_listener(proxy_url)
        self._server.launch_dofus(
            login,
            proxy_listener=proxy_listener,
            proxy_url=proxy_url,
            interface_ip=interface_ip,
        )
        return f"Dofus 3 lancé pour {login}"

    def _launch_retro(
        self, login: str, interface_ip: str | None, proxy_url: str | None
    ) -> str:
        self._server.launch_retro(login, proxy_url=proxy_url, interface_ip=interface_ip)
        return f"Rétro lancé pour {login}"

    def _show_success(self, msg: str) -> None:
        InfoBar.success(
            "", msg, duration=3000, position=InfoBarPosition.TOP_RIGHT, parent=self
        )

    def _show_error(self, msg: str) -> None:
        InfoBar.error(
            "", msg, duration=3000, position=InfoBarPosition.TOP_RIGHT, parent=self
        )


def run_gui() -> None:
    handler = AnkamaLauncherHandler()
    server = AnkamaLauncherServer(handler)
    server.start()

    accounts = CryptoHelper.getStoredApiKeys()
    interfaces = get_available_network_interfaces()
    all_interface = {value: key for key, value in ({"Auto": None} | interfaces).items()}

    app = QApplication(sys.argv)
    setTheme(Theme.DARK)

    window = MainWindow(server, accounts, all_interface)
    window.show()
    sys.exit(app.exec())
