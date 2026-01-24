import threading
from dataclasses import dataclass, field
from time import sleep, time
from typing import Optional

from ankama_launcher_emulator.internet_utils import set_proxy


@dataclass
class PendingConnectionTracker:
    """
    Thread-safe tracker for pending Dofus connections.
    Manages proxy state based on pending connection count.

    - Enables proxy when first instance launches
    - Disables proxy when last instance connects
    - Optionally times out stale connections
    """

    timeout_seconds: Optional[float] = 120.0

    _pending_hashes: dict[str, float] = field(init=False, default_factory=dict)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)
    _cleanup_thread: Optional[threading.Thread] = field(init=False, default=None)
    _running: bool = field(init=False, default=False)

    def start_cleanup_thread(self):
        """Start background thread to clean up timed-out connections."""
        if self.timeout_seconds is None:
            return
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def stop_cleanup_thread(self):
        """Stop the background cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

    def _cleanup_loop(self):
        """Background loop to check for and remove timed-out connections."""
        while self._running:
            sleep(10)
            self._cleanup_stale_connections()

    def _cleanup_stale_connections(self):
        """Remove connections that have exceeded the timeout."""
        if self.timeout_seconds is None:
            return

        current_time = time()
        with self._lock:
            stale_hashes = [
                h
                for h, launch_time in self._pending_hashes.items()
                if current_time - launch_time > self.timeout_seconds
            ]
            for h in stale_hashes:
                print(f"[PROXY] Timing out stale connection: {h[:8]}...")
                del self._pending_hashes[h]

            if stale_hashes and len(self._pending_hashes) == 0:
                print("[PROXY] All pending connections timed out, disabling proxy")
                set_proxy(False)

    def register_launch(self, hash: str):
        """
        Register a new launch. Enables proxy if this is the first pending connection.
        """
        with self._lock:
            was_empty = len(self._pending_hashes) == 0
            self._pending_hashes[hash] = time()

            if was_empty:
                print("[PROXY] First launch registered, enabling proxy")
                set_proxy(True)
            else:
                print(f"[PROXY] Launch registered, {len(self._pending_hashes)} pending")

    def register_connection(self, hash: str):
        """
        Register that a connection has completed. Disables proxy if no more pending.
        """
        with self._lock:
            if hash in self._pending_hashes:
                del self._pending_hashes[hash]
                remaining = len(self._pending_hashes)

                if remaining == 0:
                    print("[PROXY] Last connection completed, disabling proxy")
                    set_proxy(False)
                else:
                    print(f"[PROXY] Connection completed, {remaining} still pending")

    def get_pending_count(self) -> int:
        """Return the current number of pending connections."""
        with self._lock:
            return len(self._pending_hashes)


_tracker: Optional[PendingConnectionTracker] = None
_tracker_lock = threading.Lock()


def get_tracker(timeout_seconds: Optional[float] = 120.0) -> PendingConnectionTracker:
    """
    Get or create the global PendingConnectionTracker singleton.
    """
    global _tracker
    with _tracker_lock:
        if _tracker is None:
            _tracker = PendingConnectionTracker(timeout_seconds=timeout_seconds)
            _tracker.start_cleanup_thread()
        return _tracker
