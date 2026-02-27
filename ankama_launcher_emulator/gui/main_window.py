import re
from typing import Callable, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    InfoBar,
    InfoBarPosition,
    ProgressBar,
    TitleLabel,
)

from ankama_launcher_emulator.consts import (
    CYTRUS_INSTALLED,
    DOFUS_INSTALLED,
    RESOURCES,
    RETRO_INSTALLED,
    ZAAP_PATH,
)
from ankama_launcher_emulator.gui.account_card import AccountCard
from ankama_launcher_emulator.gui.consts import (
    DOFUS_3_TITLE,
    DOFUS_RETRO_TITLE,
    ORANGE_HEXA,
    RED_HEXA,
)
from ankama_launcher_emulator.gui.game_selector_card import GameSelectorCard
from ankama_launcher_emulator.gui.star_dialog import (
    StarBar,
    has_shown_star_repo,
)
from ankama_launcher_emulator.gui.utils import run_in_background
from ankama_launcher_emulator.server.server import AnkamaLauncherServer
from ankama_launcher_emulator.utils.proxy import build_proxy_listener


class MainWindow(QMainWindow):
    def __init__(
        self,
        server: AnkamaLauncherServer,
        accounts: list,
        all_interface: dict[str, tuple[str, str]],
    ):
        super().__init__()
        self._server = server
        self._setup_ui(accounts, all_interface)

    def _setup_ui(self, accounts: list, all_interface: dict) -> None:
        self.setWindowTitle("Ankama Launcher")
        self.setMinimumWidth(800)
        self.resize(950, 600)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        if not has_shown_star_repo():
            layout.addWidget(StarBar())

        if not accounts:
            label = BodyLabel(
                f"No account found.\n"
                f"Check that ankama launcher is installed et have logged account.\n"
                f"Expected path : {ZAAP_PATH}/keydata/"
            )
            label.setStyleSheet(f"color: {RED_HEXA};")
            label.setWordWrap(True)
            layout.addWidget(label)
            return

        self._dofus_selector = GameSelectorCard(
            DOFUS_3_TITLE, RESOURCES / "Dofus3.png", False, available=DOFUS_INSTALLED
        )
        self._retro_selector = GameSelectorCard(
            DOFUS_RETRO_TITLE,
            RESOURCES / "DofusRetro.png",
            False,
            available=RETRO_INSTALLED,
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

        if not CYTRUS_INSTALLED:
            cytrus_warning = BodyLabel(
                "cytrus-v6 is not installed. Auto-update will not work.\n"
                "Install it with: npm install -g cytrus-v6"
            )
            cytrus_warning.setStyleSheet(f"color: {ORANGE_HEXA};")
            cytrus_warning.setWordWrap(True)
            layout.addWidget(cytrus_warning)

        self._title_label = TitleLabel(DOFUS_3_TITLE)
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._title_label)

        self._stack = QStackedWidget()
        self._dofus_page = (
            self._make_game_page(accounts, all_interface, self._launch_dofus)
            if DOFUS_INSTALLED
            else self._make_unavailable_page(DOFUS_3_TITLE)
        )
        self._retro_page = (
            self._make_game_page(accounts, all_interface, self._launch_retro)
            if RETRO_INSTALLED
            else self._make_unavailable_page(DOFUS_RETRO_TITLE)
        )
        self._stack.addWidget(self._dofus_page)
        self._stack.addWidget(self._retro_page)
        layout.addWidget(self._stack)

        self._select_game(DOFUS_INSTALLED or not RETRO_INSTALLED)

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
        launch: Callable,
    ) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 4, 0, 0)
        page_layout.setSpacing(4)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        step_re = re.compile(r"(\d+)\s*/\s*(\d+)")

        download_banner = QWidget()
        banner_layout = QVBoxLayout(download_banner)
        banner_layout.setContentsMargins(0, 6, 0, 4)
        banner_layout.setSpacing(4)
        download_title = BodyLabel("Game is not up to date, downloading update...")
        download_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        banner_layout.addWidget(download_title)
        progress_bar = ProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        banner_layout.addWidget(progress_bar)
        progress_label = CaptionLabel("")
        progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        banner_layout.addWidget(progress_label)
        download_banner.setVisible(False)

        cards: list[AccountCard] = []

        def set_panel_status(text: str) -> None:
            if not text:
                download_banner.setVisible(False)
                progress_bar.setRange(0, 100)
                progress_bar.setValue(0)
                for card in cards:
                    card.set_launch_enabled(True)
                return
            was_hidden = not download_banner.isVisible()
            download_banner.setVisible(True)
            progress_label.setText(text)
            if was_hidden:
                for card in cards:
                    card.set_launch_enabled(False)
            match = step_re.search(text)
            if match:
                current, total = int(match.group(1)), int(match.group(2))
                if total > 0:
                    progress_bar.setRange(0, total)
                    progress_bar.setValue(current)

        for account in accounts:
            login = account["apikey"]["login"]
            card = AccountCard(login, all_interface, container)
            cards.append(card)
            card.launch_requested.connect(
                self._make_launch_handler(launch, login, card, set_panel_status)
            )
            card.error_occurred.connect(self._show_error)
            layout.addWidget(card)

        layout.addStretch()
        scroll.setWidget(container)
        page_layout.addWidget(download_banner)
        page_layout.addWidget(scroll, 1)
        return page

    def _make_unavailable_page(self, game_title: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        label = BodyLabel(
            f"{game_title} client not found.\n"
            f"Install game via Ankama launcher then relaunch application."
        )
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        label.setStyleSheet(f"color: {RED_HEXA};")
        layout.addWidget(label)
        return page

    def _make_launch_handler(
        self,
        launch: Callable,
        login: str,
        card: AccountCard,
        set_panel_status: Callable[[str], None],
    ) -> Callable[[object, object], None]:
        def handler(iface: object, proxy: object) -> None:
            def on_success(result: object) -> None:
                self._show_success(f"Game launch for {login}")
                set_panel_status("")
                card.set_running(int(result))  # type: ignore[arg-type]

            def on_error(err: object) -> None:
                self._show_error(str(err))
                set_panel_status("")
                card.set_launch_enabled(True)

            run_in_background(
                lambda on_progress: launch(
                    login,
                    cast(str | None, iface),
                    cast(str | None, proxy),
                    on_progress=on_progress,
                ),
                on_success=on_success,
                on_error=on_error,
                on_progress=set_panel_status,
                parent=self,
            )

        return handler

    def _launch_dofus(
        self,
        login: str,
        interface_ip: str | None,
        proxy_url: str | None,
        on_progress: Callable[[str], None] | None = None,
    ) -> int:
        proxy_listener, proxy_url = build_proxy_listener(proxy_url)
        return self._server.launch_dofus(
            login,
            proxy_listener=proxy_listener,
            proxy_url=proxy_url,
            interface_ip=interface_ip,
            on_progress=on_progress,
        )

    def _launch_retro(
        self,
        login: str,
        interface_ip: str | None,
        proxy_url: str | None,
        on_progress: Callable[[str], None] | None = None,
    ) -> int:
        return self._server.launch_retro(
            login,
            proxy_url=proxy_url,
            interface_ip=interface_ip,
            on_progress=on_progress,
        )

    def _show_success(self, msg: str) -> None:
        InfoBar.success(
            "", msg, duration=3000, position=InfoBarPosition.TOP_RIGHT, parent=self
        )

    def _show_error(self, msg: str) -> None:
        InfoBar.error(
            "", msg, duration=6000, position=InfoBarPosition.TOP_RIGHT, parent=self
        )
