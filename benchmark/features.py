"""Streaming feature extractor for CAN intrusion-detection benchmarking.

``CanFeatureExtractor`` converts a stream of ``benchmark.can_frame.CanFrame``
objects into fixed-length, dimension-stable numeric feature vectors suitable
for training/evaluating a classifier. Features combine per-message signals
(inter-arrival time, payload entropy, byte-level deltas) with per-CAN-ID
sliding-window statistics (bus load, ID novelty), which is the standard
feature family used across CAN-IDS literature (CAR-Hacking, OTIDS, CAN-FD).

The extractor is a streaming/stateful object: frames MUST be fed in timestamp
order via repeated calls to :meth:`extract`, or in one shot via
:meth:`extract_batch`. It never raises on the first frame (or on empty
payloads) -- it returns sensible defaults (typically ``0.0``) until enough
history has accumulated. All outputs are float64 and guaranteed finite (any
NaN/Inf is defensively replaced with ``0.0``).
"""

from __future__ import annotations

import math
from collections import deque
from typing import Deque, Dict, Tuple

import numpy as np

from benchmark.can_frame import CanFrame

# Standard 11-bit CAN arbitration ID max value.
_STD_ID_MAX = 0x7FF
# CAN-FD extended 29-bit arbitration ID max value.
_EXT_ID_MAX = 0x1FFFFFFF


class CanFeatureExtractor:
    """Streaming, per-CAN-ID feature extractor.

    Maintains streaming state keyed by ``can_id`` (last timestamp, running
    mean inter-arrival time, last payload) plus a global last-timestamp and a
    sliding-time-window deque of ``(timestamp, can_id)`` pairs used for bus
    load / novelty style features.

    Attributes:
        feature_names: Ordered, stable list of output feature names. The
            array returned by :meth:`extract` always has this length, in
            this order.
    """

    #: Documented, stable feature order. Do not reorder without a version
    #: bump downstream consumers can detect.
    feature_names: list[str] = [
        "iat_same_id",
        "iat_same_id_dev",
        "iat_global",
        "can_id_norm",
        "dlc",
        "payload_entropy",
        "hamming_prev",
        "byte_change_count",
        "id_count_window",
        "total_msgs_window",
        "unique_ids_window",
        "id_novelty",
        "mean_byte",
        "byte_std",
    ]

    def __init__(self, window_sec: float = 0.02) -> None:
        self.window_sec = float(window_sec)
        self.reset()

    def reset(self) -> None:
        """Clear all streaming state (per-ID history, window, seen-ID set)."""
        # Per-can_id: last timestamp seen.
        self._last_ts_by_id: Dict[int, float] = {}
        # Per-can_id: running mean IAT + sample count (Welford-style online mean).
        self._iat_mean_by_id: Dict[int, float] = {}
        self._iat_count_by_id: Dict[int, int] = {}
        # Per-can_id: last payload bytes.
        self._last_payload_by_id: Dict[int, bytes] = {}
        # Set of can_ids ever observed since the last reset.
        self._seen_ids: set[int] = set()
        # Global last timestamp (any id).
        self._last_ts_global: float | None = None
        # Sliding window of (timestamp, can_id) for windowed stats, in arrival order.
        self._window: Deque[Tuple[float, int]] = deque()
        # Running count of each can_id currently inside the window, for O(1)
        # id_count_window lookups instead of rescanning the deque each time.
        self._window_id_counts: Dict[int, int] = {}

    # -- internal helpers ----------------------------------------------------

    @staticmethod
    def _safe(value: float) -> float:
        """Replace NaN/Inf with 0.0; otherwise return value as float64."""
        if value is None:
            return 0.0
        if math.isnan(value) or math.isinf(value):
            return 0.0
        return float(value)

    def _evict_expired(self, now: float) -> None:
        """Drop window entries older than ``window_sec`` relative to ``now``."""
        window = self._window
        counts = self._window_id_counts
        cutoff = now - self.window_sec
        while window and window[0][0] < cutoff:
            _, old_id = window.popleft()
            new_count = counts.get(old_id, 0) - 1
            if new_count <= 0:
                counts.pop(old_id, None)
            else:
                counts[old_id] = new_count

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Base-2 Shannon entropy over byte-value frequencies. 0.0 if empty."""
        n = len(data)
        if n == 0:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / n
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

    @staticmethod
    def _hamming_distance(a: bytes, b: bytes) -> int:
        """Bit-level Hamming distance between two byte strings, over min length."""
        n = min(len(a), len(b))
        if n == 0:
            return 0
        dist = 0
        for i in range(n):
            dist += bin(a[i] ^ b[i]).count("1")
        return dist

    @staticmethod
    def _byte_change_count(a: bytes, b: bytes) -> int:
        """Number of differing byte positions, over min length."""
        n = min(len(a), len(b))
        if n == 0:
            return 0
        return sum(1 for i in range(n) if a[i] != b[i])

    # -- public API ------------------------------------------------------------

    def extract(self, frame: CanFrame) -> np.ndarray:
        """Extract the feature vector for one frame, updating streaming state.

        Frames must be fed in timestamp order (sliding window + per-id running
        stats depend on it). Never raises -- returns 0.0 defaults when history
        is insufficient (e.g. the very first frame of a given id).
        """
        ts = float(frame.timestamp)
        can_id = int(frame.can_id)
        dlc = float(frame.dlc)
        data = frame.data if frame.data is not None else b""

        # --- iat_same_id / iat_same_id_dev ---
        last_ts_same_id = self._last_ts_by_id.get(can_id)
        if last_ts_same_id is None:
            iat_same_id = 0.0
            iat_same_id_dev = 0.0
        else:
            iat_same_id = ts - last_ts_same_id
            count = self._iat_count_by_id.get(can_id, 0)
            if count > 0:
                running_mean = self._iat_mean_by_id.get(can_id, 0.0)
                iat_same_id_dev = abs(iat_same_id - running_mean)
            else:
                iat_same_id_dev = 0.0

        # Update running mean IAT for this id (online mean).
        if last_ts_same_id is not None:
            prev_count = self._iat_count_by_id.get(can_id, 0)
            prev_mean = self._iat_mean_by_id.get(can_id, 0.0)
            new_count = prev_count + 1
            new_mean = prev_mean + (iat_same_id - prev_mean) / new_count
            self._iat_count_by_id[can_id] = new_count
            self._iat_mean_by_id[can_id] = new_mean

        # --- iat_global ---
        if self._last_ts_global is None:
            iat_global = 0.0
        else:
            iat_global = ts - self._last_ts_global

        # --- can_id_norm ---
        if can_id > _STD_ID_MAX:
            can_id_norm = can_id / _EXT_ID_MAX
        else:
            can_id_norm = can_id / _STD_ID_MAX
        can_id_norm = min(max(can_id_norm, 0.0), 1.0)

        # --- payload_entropy ---
        payload_entropy = self._shannon_entropy(data)

        # --- hamming_prev / byte_change_count ---
        last_payload = self._last_payload_by_id.get(can_id)
        if last_payload is None:
            hamming_prev = 0.0
            byte_change_count = 0.0
        else:
            hamming_prev = float(self._hamming_distance(data, last_payload))
            byte_change_count = float(self._byte_change_count(data, last_payload))

        # --- mean_byte / byte_std ---
        if len(data) > 0:
            arr = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
            mean_byte = float(np.mean(arr))
            byte_std = float(np.std(arr))
        else:
            mean_byte = 0.0
            byte_std = 0.0

        # --- id_novelty ---
        id_novelty = 0.0 if can_id in self._seen_ids else 1.0

        # --- sliding window stats (evict stale entries, then include this frame) ---
        self._evict_expired(ts)
        self._window.append((ts, can_id))
        self._window_id_counts[can_id] = self._window_id_counts.get(can_id, 0) + 1

        id_count_window = float(self._window_id_counts.get(can_id, 0))
        total_msgs_window = float(len(self._window))
        unique_ids_window = float(len(self._window_id_counts))

        # --- commit state updates for next call ---
        self._last_ts_by_id[can_id] = ts
        self._last_ts_global = ts
        self._last_payload_by_id[can_id] = bytes(data)
        self._seen_ids.add(can_id)

        values = [
            iat_same_id,
            iat_same_id_dev,
            iat_global,
            can_id_norm,
            dlc,
            payload_entropy,
            hamming_prev,
            byte_change_count,
            id_count_window,
            total_msgs_window,
            unique_ids_window,
            id_novelty,
            mean_byte,
            byte_std,
        ]
        safe_values = [self._safe(v) for v in values]
        return np.asarray(safe_values, dtype=np.float64)

    def extract_batch(self, frames: list[CanFrame]) -> np.ndarray:
        """Extract features for a full ordered sequence of frames.

        Resets streaming state first, then calls :meth:`extract` per frame in
        order. Returns an ``(N, F)`` float64 matrix.
        """
        self.reset()
        n = len(frames)
        f = len(self.feature_names)
        out = np.zeros((n, f), dtype=np.float64)
        for i, frame in enumerate(frames):
            out[i] = self.extract(frame)
        return out


class PaperFeatureExtractor:
    """Compact 5-feature extractor matching the paper's feature vector.

    The paper specifies five vehicle-state features: *vehicle speed*,
    *steering angle*, *acceleration*, *inter-message interval* and *payload
    variation*. Raw CAN dumps (CAR-Hacking / OTIDS / CAN-FD) do NOT carry
    decoded physical signals (speed/steering/acceleration) per arbitration ID,
    so on these datasets those three are represented by the standard,
    directly-computable raw-CAN equivalents, while the other two map exactly:

      1. ``can_id``            - arbitration ID (identifies the source ECU /
                                 which physical signal a frame carries; the
                                 stand-in for speed/steering/acceleration on
                                 raw traffic).
      2. ``dlc``               - data length code.
      3. ``payload_entropy``   - payload randomness (captures fuzzing /
                                 abnormal payloads).
      4. ``inter_message_interval`` - time since the previous frame of the same
                                 ID (paper: "inter-message interval" - exact).
      5. ``payload_variation`` - number of changed bytes vs the previous
                                 same-ID payload (paper: "payload variation" -
                                 exact).

    Values are left un-scaled here; the benchmark runner applies a
    StandardScaler fit on the training split ("normalized features"). Same
    streaming/ordering contract as :class:`CanFeatureExtractor`.
    """

    feature_names: list[str] = [
        "can_id",
        "dlc",
        "payload_entropy",
        "inter_message_interval",
        "payload_variation",
    ]

    def __init__(self, window_sec: float = 0.02) -> None:
        # window_sec accepted for interface compatibility (unused here).
        self.window_sec = float(window_sec)
        self.reset()

    def reset(self) -> None:
        self._last_ts_by_id: Dict[int, float] = {}
        self._last_payload_by_id: Dict[int, bytes] = {}

    def extract(self, frame: CanFrame) -> np.ndarray:
        ts = float(frame.timestamp)
        can_id = int(frame.can_id)
        data = frame.data if frame.data is not None else b""

        last_ts = self._last_ts_by_id.get(can_id)
        imi = 0.0 if last_ts is None else (ts - last_ts)

        last_payload = self._last_payload_by_id.get(can_id)
        payload_variation = (
            0.0 if last_payload is None
            else float(CanFeatureExtractor._byte_change_count(data, last_payload))
        )

        payload_entropy = CanFeatureExtractor._shannon_entropy(data)

        self._last_ts_by_id[can_id] = ts
        self._last_payload_by_id[can_id] = bytes(data)

        values = [
            float(can_id),
            float(frame.dlc),
            payload_entropy,
            imi,
            payload_variation,
        ]
        return np.asarray([CanFeatureExtractor._safe(v) for v in values], dtype=np.float64)

    def extract_batch(self, frames: list[CanFrame]) -> np.ndarray:
        self.reset()
        out = np.zeros((len(frames), len(self.feature_names)), dtype=np.float64)
        for i, frame in enumerate(frames):
            out[i] = self.extract(frame)
        return out
