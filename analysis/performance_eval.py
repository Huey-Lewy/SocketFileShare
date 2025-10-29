# analysis/performance_eval.py
# Collects data rates, transfer times, response times, and other performance metrics for analysis.

import time

def timed():
    start = time.perf_counter()
    def end():
        return time.perf_counter() - start
    return end
