from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QMouseEvent, QPixmap
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel

COLOR = QColor("#00470E")
COLOR_ACTIVE = COLOR.lighter(200).name()
COLOR_INACTIVE = COLOR.darker(200).name()


class GameSelectorCard(QFrame):
    clicked = pyqtSignal()

    def __init__(self, title: str, logo_path: Path, is_active: bool, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(72)
        self._setup_ui(title, logo_path)
        self.set_active(is_active)

    def _setup_ui(self, title: str, logo_path: Path) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        logo = QLabel()
        pixmap = QPixmap(str(logo_path)).scaled(
            48,
            48,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        logo.setPixmap(pixmap)
        logo.setFixedSize(48, 48)
        layout.addWidget(logo)

        self._title_label = QLabel(title)
        self._title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        layout.addWidget(self._title_label, 1)

    def set_active(self, active: bool) -> None:
        bg = COLOR_ACTIVE if active else COLOR_INACTIVE
        self.setStyleSheet(
            f"GameSelectorCard {{ background-color: {bg}; border-radius: 8px; }}"
        )

    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        if a0 is not None and a0.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(a0)
