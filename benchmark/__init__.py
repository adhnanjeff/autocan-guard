"""
Standard CAN intrusion-detection benchmark package.

Integrates three public, journal-grade datasets into AutoCAN Guard so the
detection pipeline can be evaluated on standard data:

  * CAR-Hacking Dataset (HCRL)          -> benchmark.loaders.car_hacking
  * CAN-intrusion Dataset / OTIDS (HCRL) -> benchmark.loaders.otids
  * CAN-FD Intrusion Dataset (HCRL)     -> benchmark.loaders.can_fd

This package is intentionally self-contained and does NOT modify the existing
runtime pipeline (can_listener, trust/policy/ips engines). It reads raw dataset
files, extracts CAN-IDS features, trains/evaluates a model, and reports
precision, recall, accuracy, F1, latency and throughput.
"""

from .can_frame import CanFrame

__all__ = ["CanFrame"]
