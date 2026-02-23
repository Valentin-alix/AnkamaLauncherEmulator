from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout
from qfluentwidgets import BodyLabel, CardWidget, ComboBox, LineEdit, PrimaryPushButton

from ankama_launcher_emulator.utils.proxy import validation_proxy_url


class AccountCard(CardWidget):
    launch_requested = pyqtSignal(
        object, object
    )  # (interface_ip: str | None, proxy_url: str | None)
    error_occurred = pyqtSignal(str)

    def __init__(self, login: str, all_interface: dict, parent=None):
        super().__init__(parent)
        self.login = login
        self._setup_ui(all_interface)

    def _setup_ui(self, all_interface: dict) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        layout.addWidget(BodyLabel(self.login), 1)

        self._ip_combo = ComboBox()
        self._ip_combo.setFixedWidth(150)
        for ip_value, display_name in all_interface.items():
            self._ip_combo.addItem(display_name, ip_value)
        layout.addWidget(self._ip_combo)

        self._proxy_input = LineEdit()
        self._proxy_input.setPlaceholderText("Proxy (socks5://user:pass@host:port)")
        self._proxy_input.setFixedWidth(300)
        layout.addWidget(self._proxy_input)

        self._launch_btn = PrimaryPushButton("Launch")
        self._launch_btn.setFixedWidth(100)
        self._launch_btn.clicked.connect(self._on_launch_clicked)
        layout.addWidget(self._launch_btn)

    def _on_launch_clicked(self) -> None:
        interface_ip = self._ip_combo.currentData() or None
        proxy_url = self._proxy_input.text().strip() or None

        if proxy_url and not validation_proxy_url(proxy_url):
            self.error_occurred.emit("Invalid proxy url")
            return

        self._launch_btn.setDisabled(True)
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._launch_btn.setDisabled(False))
        timer.start(3000)

        self.launch_requested.emit(interface_ip, proxy_url)
