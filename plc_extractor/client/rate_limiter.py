"""
PLC Communication Rate Limiter
Prevents network packet storms and protects the PLC internal scan cycle budget.
"""

import time
import threading


class PLCRateLimiter:
    """
    Precision Token-Bucket Rate Limiter using monotonic timing.
    Guarantees communication requests never exceed the specified requests/sec budget.
    """

    def __init__(self, max_requests_per_second: float = 50.0):
        self.max_rate = max(1.0, float(max_requests_per_second))
        self.capacity = self.max_rate
        self.tokens = self.capacity
        self.fill_rate = self.max_rate
        self.last_update = time.perf_counter()
        self._lock = threading.Lock()

    def acquire(self, blocking: bool = True) -> bool:
        """Acquires permission to send a read request to the PLC."""
        with self._lock:
            while True:
                now = time.perf_counter()
                elapsed = now - self.last_update
                self.last_update = now

                # Add generated tokens
                self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

                if not blocking:
                    return False

                # Calculate required sleep time to get 1 token
                needed = 1.0 - self.tokens
                sleep_time = needed / self.fill_rate
                time.sleep(max(0.001, sleep_time))
