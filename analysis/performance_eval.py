# analysis/performance_eval.py
# Collects data rates, transfer times, and response times for performance analysis.

import time         # high-resolution timing
import threading    # thread-safe metrics
import json         # JSON metrics export
import csv          # CSV metrics export

#### Simple Timer ####
def timed():
    """
    Return a function that yields elapsed seconds when called.

    Usage:
        timer = timed()
        ... do work ...
        elapsed = timer()
    """
    start = time.perf_counter()

    def end():
        return time.perf_counter() - start

    return end

#### Metric Recorder ####
class PerfRecorder:
    """
    Thread-safe, in-memory performance data recorder.

    Each record has:
      - operation: 'upload' | 'download' | 'auth' | 'dir' | 'delete' | 'subfolder' | 'session' | 'server_uptime'
      - bytes: int (0 for non-transfer ops)
      - seconds: float
      - rate_MBps: float or None
      - source: 'server' or 'client' (or any label you pass)
      - timestamp: float (UNIX seconds since epoch)
      - meta: optional dict with extra context
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._records = []

    def _add_record(self, record):
        """
        Append a record in a thread-safe way.
        """
        with self._lock:
            self._records.append(record)

    def record_transfer(self, *, operation, bytes_count, seconds, source="server", meta=None):
        """
        Record an upload or download measurement.

        Parameters:
            operation   (str): Operation name ('upload' or 'download')
            bytes_count (int): Bytes transferred
            seconds   (float): Duration in seconds
            source     (str): Label for origin, e.g. 'server' or 'client'
            meta       (dict|None): Optional extra info (e.g., filename)
        """
        # Avoid division by zero for tiny or failed transfers.
        rate = (bytes_count / (1024 * 1024)) / seconds if seconds > 0 else None

        record = {
            "operation": operation,
            "bytes": int(bytes_count),
            "seconds": float(seconds),
            "rate_MBps": float(rate) if rate is not None else None,
            "source": source,
            "timestamp": time.time(),
        }

        if meta is not None:
            # Placeholder: attach extra labels such as filenames or peer address.
            record["meta"] = dict(meta)

        # Placeholder: integrate with client/server upload/download timings.
        self._add_record(record)

    def record_response(self, *, operation, seconds, source="server", meta=None):
        """
        Record a non-transfer operation (e.g., auth, dir, delete, subfolder, session, server_uptime).

        Parameters:
            operation (str): Operation name
            seconds (float): Duration in seconds
            source   (str): Label for origin, e.g. 'server' or 'client'
            meta     (dict|None): Optional extra info (e.g., command name)
        """
        record = {
            "operation": operation,
            "bytes": 0,
            "seconds": float(seconds),
            "rate_MBps": None,
            "source": source,
            "timestamp": time.time(),
        }

        if meta is not None:
            # Placeholder: add extra context for this measurement.
            record["meta"] = dict(meta)

        # Placeholder: integrate with command response timing on client side.
        self._add_record(record)

    def snapshot(self):
        """
        Return a copy of all stored records for offline review.

        Returns:
            list[dict]: List of metric records.
        """
        with self._lock:
            return list(self._records)

    def clear(self):
        """
        Remove all stored records.
        """
        with self._lock:
            self._records.clear()

    def to_json(self, filepath):
        """
        Write current metrics to a JSON file.

        Parameters:
            filepath (str): Path to JSON file to write.
        """
        data = self.snapshot()
        with open(filepath, "w", encoding="utf-8") as f:
            # Placeholder: adjust indent or structure if you want a smaller file.
            json.dump(data, f, indent=2)

    def to_csv(self, filepath):
        """
        Write current metrics to a CSV file.

        Parameters:
            filepath (str): Path to CSV file to write.
        """
        data = self.snapshot()
        # If there are no records yet, still create a header row with common fields.
        if not data:
            fieldnames = ["operation", "bytes", "seconds", "rate_MBps", "source", "timestamp", "meta"]
        else:
            # Collect union of keys across all records.
            fieldnames = set()
            for rec in data:
                fieldnames.update(rec.keys())
            fieldnames = list(fieldnames)

        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in data:
                writer.writerow(rec)
