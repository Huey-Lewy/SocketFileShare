# analysis/performance_eval.py
# Collects data rates, transfer times, and response times for performance analysis.

import time
import threading

#### Simple Timer ####
def timed():
    """Return a function that yields elapsed seconds when called."""
    start = time.perf_counter()
    def end():
        return time.perf_counter() - start
    return end

#### Metric Recorder ####
class PerfRecorder:
    """
    Thread-safe, in-memory performance data recorder.

    Records per entry:
      - operation: 'upload' | 'download' | 'auth' | 'dir' | 'delete' | 'subfolder'
      - bytes: int (0 for non-transfer ops)
      - seconds: float
      - rate_MBps: float or None
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._records = []

    def record_transfer(self, *, operation, bytes_count, seconds):
        """
        Record an upload or download measurement.

        Parameters:
            operation (str): Operation name ('upload' or 'download')
            bytes_count (int): Bytes transferred
            seconds (float): Duration in seconds
        """
        rate = (bytes_count / (1024 * 1024)) / seconds if seconds > 0 else None
        with self._lock:
            self._records.append({
                "operation": operation,
                "bytes": int(bytes_count),
                "seconds": float(seconds),
                "rate_MBps": float(rate) if rate is not None else None,
            })
        # Placeholder: integrate with client/server upload/download timings.

    def record_response(self, *, operation, seconds):
        """
        Record a non-transfer operation (e.g., auth, dir, delete, subfolder).

        Parameters:
            operation (str): Operation name
            seconds (float): Duration in seconds
        """
        with self._lock:
            self._records.append({
                "operation": operation,
                "bytes": 0,
                "seconds": float(seconds),
                "rate_MBps": None,
            })
        # Placeholder: integrate with command response timing on client side.

    def snapshot(self):
        """Return a copy of all stored records for offline review."""
        with self._lock:
            return list(self._records)
