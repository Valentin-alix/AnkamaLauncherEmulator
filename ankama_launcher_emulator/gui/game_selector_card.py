from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QMouseEvent, QPixmap
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel

COLOR = QColor("#00470E")


class GameSelectorCard(QFrame):
    clicked = pyqtSignal()

    def __init__(self, title: str, logo_path: Path, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(72)
        self._setup_ui(title, logo_path)
        self.set_active(False)

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
        if active:
            color = COLOR.lighter(200)
            self.setStyleSheet(
                f"""
                GameSelectorCard {{
                    background-color: {color.name()};
                    border-radius: 8px;
                }}
                """
            )
            self._title_label.setStyleSheet("color: white")
        else:
            color = COLOR.darker(200)
            self.setStyleSheet(
                f"""
                GameSelectorCard {{
                    background-color: {color.name()};
                    border-radius: 8px;
                }}
                """
            )
            self._title_label.setStyleSheet("color: white;")

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
