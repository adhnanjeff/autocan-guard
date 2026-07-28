"""Loader for the CAN-FD Intrusion Dataset (HCRL, ocslab.hksecurity.net).

CSV format, same variable-DLC layout as CAR-Hacking but CAN-FD allows up to 64
data bytes, so a row can carry many data columns::

    Timestamp, Arbitration ID (hex), DLC (0..64), Data[0], ..., Data[DLC-1], Label

Because ``DLC`` varies, the ground-truth ``Label`` is the LAST token on the
line, never a fixed column. ``T`` marks an injected/attack frame (label 1);
``R`` marks a normal frame (label 0). The data bytes are ``tokens[3 : 3+DLC]``.

``attack_type`` is one of ``flooding``/``fuzzing``/``malfunction`` and tags the
injected rows; benign rows (Label ``R``) are tagged ``normal``.
"""

from __future__ import annotations

from typing import Iterator, Optional

from ..can_frame import CanFrame
from .base import BaseLoader

# Accept both "fuzzing" (HCRL's CAN-FD term) and "fuzzy" (the canonical
# ATTACK_TYPES tag used across datasets and emitted by the CLI's filename
# inference) so callers can pass either without an integration mismatch.
_VALID_ATTACK_TYPES = {"flooding", "fuzzing", "fuzzy", "malfunction"}
# Map the accepted kwargs onto canonical ATTACK_TYPES tags (can_frame.ATTACK_TYPES
# uses "fuzzy" for the fuzzing attack across all datasets; "flooding"/"malfunction"
# pass through unchanged).
_ATTACK_TAG = {"flooding": "flooding", "fuzzing": "fuzzy", "fuzzy": "fuzzy",
               "malfunction": "malfunction"}
_MAX_DLC = 64  # CAN-FD


def _to_int(token: str, base: int = 16) -> Optional[int]:
    try:
        return int(token, base)
    except (ValueError, TypeError):
        return None


def _fit_data(raw: bytes, dlc: int) -> bytes:
    """Pad with 0x00 / truncate so ``len(data) == dlc`` (contract invariant)."""
    if len(raw) < dlc:
        return raw + b"\x00" * (dlc - len(raw))
    return raw[:dlc]


class CanFdLoader(BaseLoader):
    """Parse one CAN-FD Intrusion Dataset CSV file (carries a T/R label)."""

    def __init__(self, path: str, attack_type: Optional[str] = None,
                 max_frames: Optional[int] = None) -> None:
        super().__init__(path, attack_type, max_frames)
        if attack_type is not None and attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(
                f"attack_type must be one of {sorted(_VALID_ATTACK_TYPES)} "
                f"or None, got {attack_type!r}"
            )

    def iter_frames(self) -> Iterator[CanFrame]:
        attack_tag = _ATTACK_TAG.get(self.attack_type, "flooding")
        with open(self.path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                tokens = [t.strip() for t in line.split(",")]
                if len(tokens) < 4:
                    continue

                # Header row (non-numeric timestamp) -> skip.
                ts = self._parse_float(tokens[0])
                if ts is None:
                    continue

                can_id = _to_int(tokens[1], 16)
                dlc = _to_int(tokens[2], 10)
                if can_id is None or dlc is None or not (0 <= dlc <= _MAX_DLC):
                    continue

                flag = tokens[-1].upper()
                data_tokens = tokens[3:3 + dlc]
                data = self._parse_data_bytes(data_tokens)
                data = _fit_data(data, dlc)

                if flag == "T":
                    label, atype = 1, attack_tag
                else:  # 'R' or anything else -> normal
                    label, atype = 0, "normal"

                yield CanFrame(
                    timestamp=ts,
                    can_id=can_id,
                    dlc=dlc,
                    data=data,
                    label=label,
                    attack_type=atype,
                    is_remote=False,
                    raw=line,
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
