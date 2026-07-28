"""Shared CAN frame data contract for the benchmark package.

Every dataset loader normalizes raw records into a list/stream of ``CanFrame``
objects. Feature extraction, model training and evaluation all consume this one
type, so the three datasets become interchangeable downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Canonical attack-type tags used across all loaders. ``normal`` means benign.
ATTACK_TYPES = (
    "normal",
    "dos",          # CAR-Hacking DoS, OTIDS DoS
    "fuzzy",        # CAR-Hacking Fuzzy, OTIDS Fuzzy, CAN-FD Fuzzing
    "gear",         # CAR-Hacking gear spoofing
    "rpm",          # CAR-Hacking RPM spoofing
    "spoofing",     # generic spoofing
    "impersonation",# OTIDS impersonation
    "flooding",     # CAN-FD flooding
    "malfunction",  # CAN-FD malfunction
)


@dataclass
class CanFrame:
    """A single normalized CAN / CAN-FD frame.

    Attributes:
        timestamp: Capture time in seconds (float). Monotonic within a file.
        can_id:    Arbitration ID as an integer (parse hex -> int).
        dlc:       Data length code. 0..8 for CAN, 0..64 for CAN-FD.
        data:      Payload bytes. Length should equal ``dlc`` (loaders pad with
                   0x00 or truncate to keep this invariant).
        label:     Ground-truth label. 0 = normal/benign, 1 = attack/injected.
        attack_type: One of ``ATTACK_TYPES``. ``normal`` when ``label == 0``.
        is_remote: True for CAN remote-transmission-request frames (OTIDS uses
                   remote frames; most datasets are data frames -> False).
        raw:       Optional original source line, kept for debugging only.
    """

    timestamp: float
    can_id: int
    dlc: int
    data: bytes = b""
    label: int = 0
    attack_type: str = "normal"
    is_remote: bool = False
    raw: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        # Keep the payload/dlc invariant so feature code can rely on it.
        if not isinstance(self.data, (bytes, bytearray)):
            raise TypeError("CanFrame.data must be bytes")
        self.data = bytes(self.data)
        if self.label not in (0, 1):
            raise ValueError(f"label must be 0 or 1, got {self.label!r}")
        if self.attack_type not in ATTACK_TYPES:
            raise ValueError(f"unknown attack_type: {self.attack_type!r}")

    @property
    def id_hex(self) -> str:
        return f"{self.can_id:03x}"
