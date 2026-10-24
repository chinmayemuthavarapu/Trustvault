"""Small in-process sliding-window rate limiter.

The app runs as ONE process (gunicorn --workers 1 --threads N), so an
in-memory limiter is consistent. Login lockout is stored in the database
instead (login_attempts), so it survives restarts.
"""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float = 60.0) -> bool:
        """Record a hit. Returns False if the key is over its limit."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 50_000:   # bound memory under a flood of distinct keys
                for k in [k for k, v in self._hits.items() if not v][:10_000]:
                    del self._hits[k]
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()
