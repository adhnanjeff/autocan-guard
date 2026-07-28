"""Loader for the OTIDS / CAN-intrusion Dataset (HCRL, ocslab.hksecurity.net).

Line format (whitespace-separated, irregular spacing, NO label column)::

    Timestamp:  1479121434.850202  ID: 0153  000  DLC: 8  00 00 00 00 00 00 00 00

Fields:
  * ``Timestamp:`` -> float capture time in seconds.
  * ``ID:`` -> arbitration ID in hex.
  * the token right after the ID (``000``/``100``) is a frame-type/remote flag.
    ``100`` (or a trailing ``R``/remote marker) => ``is_remote=True``;
    ``000`` => data frame.
  * ``DLC:`` -> data-byte count.
  * then ``DLC`` hex byte tokens.

DERIVED LABELING (this dataset ships WITHOUT ground truth)
----------------------------------------------------------
OTIDS provides no per-row attack flag, so labels here are *derived* from the
HCRL documentation, not authoritative. We combine two documented signals from
``benchmark.config``:

  * ``OTIDS_INJECTED_IDS[attack_type]`` — the arbitration ID the attack injects:
        - DoS            -> {0x000}  (flood of highest-priority 0x000 frames)
        - Impersonation  -> {0x164}  (forged 0x164 frames)
        - Fuzzy          -> None     (random IDs; no fixed injected ID)
  * ``OTIDS_ATTACK_START_SEC`` (~250 s) — the coarse "under attack" window; the
    early part of each capture is treated as attack-free.

Convention applied:
  * If the injected-ID set is not None (DoS, Impersonation): a frame is attack
    (label 1) iff its CAN ID is in that set. This is the documented convention;
    those IDs do not occur benignly in normal traffic.
  * If the injected-ID set is None (Fuzzy): fall back to TIME-WINDOW labeling —
    a frame is attack (label 1) iff
    ``(timestamp - first_timestamp_in_file) >= OTIDS_ATTACK_START_SEC``.
  * ``attack_type='attack_free'`` (or ``None``): every row is label 0.

These labels are heuristic and clearly documented as such so downstream reports
can cite the method honestly.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

from .. import config
from ..can_frame import CanFrame
from .base import BaseLoader

# Map the attack_type kwarg onto an ATTACK_TYPES tag for injected rows.
_ATTACK_TAG = {
    "dos": "dos",
    "impersonation": "impersonation",
    "fuzzy": "fuzzy",
}
# Treated as fully benign.
_ATTACK_FREE = {"attack_free", None}

# Robust regex: whitespace is irregular so we anchor on the keyword tokens.
# The frame-type/remote flag token between ID and DLC (``000``/``100``) is
# optional — some OTIDS dumps omit it (``ID: 0153  DLC: 8 ...``). The literal
# ``DLC:`` anchor keeps the optional flag group unambiguous.
_LINE_RE = re.compile(
    r"Timestamp:\s*(?P<ts>[0-9]+\.?[0-9]*)\s+"
    r"ID:\s*(?P<id>[0-9A-Fa-f]+)\s+"
    r"(?:(?P<flag>[0-9A-Fa-f]{3}|R)\s+)?"
    r"DLC:\s*(?P<dlc>\d+)\s*"
    r"(?P<data>[0-9A-Fa-f\s]*)$"
)


def _to_int(token: str, base: int = 16) -> Optional[int]:
    try:
        return int(token, base)
    except (ValueError, TypeError):
        return None


def _fit_data(raw: bytes, dlc: int) -> bytes:
    if len(raw) < dlc:
        return raw + b"\x00" * (dlc - len(raw))
    return raw[:dlc]


class OtidsLoader(BaseLoader):
    """Parse one OTIDS text log; derive labels per the module docstring."""

    def __init__(self, path: str, attack_type: Optional[str] = None,
                 max_frames: Optional[int] = None) -> None:
        super().__init__(path, attack_type, max_frames)
        valid = set(_ATTACK_TAG) | {"attack_free"}
        if attack_type is not None and attack_type not in valid:
            raise ValueError(
                f"attack_type must be one of {sorted(valid)} or None, "
                f"got {attack_type!r}"
            )

    def iter_frames(self) -> Iterator[CanFrame]:
        attack_type = self.attack_type
        is_attack_free = attack_type in _ATTACK_FREE

        # Injected-ID set for this attack (may be None -> time-window fallback).
        injected_ids = None
        if not is_attack_free:
            injected_ids = config.OTIDS_INJECTED_IDS.get(attack_type)

        atype_tag = _ATTACK_TAG.get(attack_type, "normal")

        first_ts: Optional[float] = None

        with open(self.path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                m = _LINE_RE.search(stripped)
                if not m:
                    continue

                ts = self._parse_float(m.group("ts"))
                can_id = _to_int(m.group("id"), 16)
                dlc = _to_int(m.group("dlc"), 10)
                if ts is None or can_id is None or dlc is None:
                    continue
                if not (0 <= dlc <= 8):
                    continue

                if first_ts is None:
                    first_ts = ts

                flag = m.group("flag")
                is_remote = flag is not None and (flag == "100" or flag.upper() == "R")

                data = self._parse_data_bytes(m.group("data").split())
                data = _fit_data(data, dlc)

                # --- derive label ---
                label = 0
                if not is_attack_free:
                    if injected_ids is not None:
                        # DoS / Impersonation: match on injected arbitration ID.
                        if can_id in injected_ids:
                            label = 1
                    else:
                        # Fuzzy: time-window labeling.
                        if (ts - first_ts) >= config.OTIDS_ATTACK_START_SEC:
                            label = 1

                atype = atype_tag if label == 1 else "normal"

                yield CanFrame(
                    timestamp=ts,
                    can_id=can_id,
                    dlc=dlc,
                    data=data,
                    label=label,
                    attack_type=atype,
                    is_remote=is_remote,
                    raw=stripped,
                )

    @staticmethod
    def _parse_float(token: str) -> Optional[float]:
        try:
            return float(token)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_data_bytes(tokens) -> bytes:
        out = bytearray()
        for tok in tokens:
            val = _to_int(tok, 16)
            if val is None or not (0 <= val <= 0xFF):
                continue
            out.append(val)
        return bytes(out)
