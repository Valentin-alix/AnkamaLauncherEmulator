import threading
from dataclasses import dataclass, field

from ankama_launcher_emulator.redirect import set_proxy


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
        """
        Register a new launch. Enables proxy if this is the first pending connection.
        """
        with self._lock:
            was_zero = self._pending_count == 0
            self._pending_count += 1

            if was_zero:
                print("[PROXY] Premier lancement, activation proxy")
                set_proxy(True)
            else:
                print(f"[PROXY] Lancement enregistré, {self._pending_count} en attente")

    def register_connection(self):
        """
        Register that a config has been intercepted. Disables proxy if no more pending.
        Called by mitmproxy callback when dofus3.json is intercepted.
        """
        with self._lock:
            if self._pending_count > 0:
                self._pending_count -= 1

                if self._pending_count == 0:
                    print("[PROXY] Dernier client connecté, désactivation proxy")
                    # set_proxy(False)
                else:
                    print(
                        f"[PROXY] Config interceptée, {self._pending_count} en attente"
                    )

    def get_pending_count(self) -> int:
        """Return the current number of pending connections."""
        with self._lock:
            return self._pending_count


_tracker: PendingConnectionTracker | None = None
_tracker_lock = threading.Lock()


def get_tracker() -> PendingConnectionTracker:
    """
    Get or create the global PendingConnectionTracker singleton.
    """
    global _tracker
    with _tracker_lock:
        if _tracker is None:
            _tracker = PendingConnectionTracker()
        return _tracker


def register_connection_after_func(func):
    def wrapper(*args, **kwargs):
        res = func(*args, **kwargs)
        tracker = get_tracker()
        tracker.register_connection()
        return res

    return wrapper
