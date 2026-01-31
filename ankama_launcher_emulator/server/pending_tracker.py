import threading
from dataclasses import dataclass, field

from AnkamaLauncherEmulator.ankama_launcher_emulator.redirect import set_proxy


@dataclass
class PendingConnectionTracker:
    """
    Thread-safe tracker for pending Dofus connections.
    Manages proxy state based on pending connection count.

    - Enables proxy when first instance launches
    - Disables proxy when last instance's config is intercepted
    """

    _pending_count: int = field(init=False, default=0)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def register_launch(self):
        with self._lock:
            was_zero = self._pending_count == 0
            self._pending_count += 1

            if was_zero:
                print("[PROXY] Premier lancement, activation proxy")
                set_proxy(True)
            else:
                print(f"[PROXY] Lancement enregistré, {self._pending_count} en attente")

    def register_connection(self):
        with self._lock:
            if self._pending_count > 0:
                self._pending_count -= 1
                print(f"[PROXY] Config interceptée, {self._pending_count} en attente")
                if self._pending_count == 0:
                    print("[PROXY] Dernier client connecté, désactivation proxy")
                    set_proxy(False)

    def get_pending_count(self) -> int:
        with self._lock:
            return self._pending_count


_tracker: PendingConnectionTracker | None = None
_tracker_lock = threading.Lock()


def get_tracker() -> PendingConnectionTracker:
    global _tracker
    with _tracker_lock:
        if _tracker is None:
            _tracker = PendingConnectionTracker()
        return _tracker
