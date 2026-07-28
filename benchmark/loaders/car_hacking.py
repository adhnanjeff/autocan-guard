"""Loader for the CAR-Hacking Dataset (HCRL, ocslab.hksecurity.net).

Two on-disk formats are handled:

1. Attack captures (``DoS_dataset.csv``, ``Fuzzy_dataset.csv``,
   ``gear_dataset.csv``, ``RPM_dataset.csv``) — comma-separated with a
   per-row ground-truth flag::

       Timestamp, CAN ID, DLC, DATA[0], ..., DATA[DLC-1], Flag

   The number of columns varies row-to-row because ``DLC`` (the data-byte
   count) varies. The ground-truth ``Flag`` is therefore the LAST token on
   the line, never a fixed column index. ``T`` marks an injected/attack
   frame (label 1); ``R`` marks a normal frame (label 0). The data bytes are
   ``tokens[3 : 3 + DLC]``. Example rows::

       1478198376.389427,0316,8,05,21,68,09,21,21,00,6f,R
       1478198379.128627,0002,2,00,00,R
       1478198376.391062,0260,8,19,21,22,30,08,8e,6d,3a,T

2. Attack-free capture (``normal_run_data.txt``) — the whole log is benign
   and ships in the OTIDS-style text format::

       Timestamp:  1479121434.850202  ID: 0153  000  DLC: 8  00 00 ... 00

   When a ``.txt`` file is passed, the loader auto-detects this text format
   and parses every row as label 0.

``attack_type`` is one of ``dos``/``fuzzy``/``gear``/``rpm`` and is applied to
injected rows (Flag ``T``); benign rows (Flag ``R``) are tagged ``normal``.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

from ..can_frame import CanFrame
from .base import BaseLoader

# Attack-type kwargs that map onto ATTACK_TYPES for the CAR-Hacking captures.
_VALID_ATTACK_TYPES = {"dos", "fuzzy", "gear", "rpm"}

# OTIDS-style text line (used by normal_run_data.txt). Whitespace is irregular,
# so match tokens by keyword rather than fixed columns.
_TEXT_LINE_RE = re.compile(
    r"Timestamp:\s*(?P<ts>[0-9]+\.?[0-9]*)\s+"
    r"ID:\s*(?P<id>[0-9A-Fa-f]+)\s+"
    r"(?P<flag>\S+)\s+"
    r"DLC:\s*(?P<dlc>\d+)\s*"
    r"(?P<data>[0-9A-Fa-f\s]*)$"
)


def _to_int(token: str, base: int = 16) -> Optional[int]:
    """Parse ``token`` as an int in ``base``; return None on garbage."""
    try:
        return int(token, base)
    except (ValueError, TypeError):
        return None


def _fit_data(raw: bytes, dlc: int) -> bytes:
    """Pad with 0x00 / truncate so ``len(data) == dlc`` (contract invariant)."""
    if len(raw) < dlc:
        return raw + b"\x00" * (dlc - len(raw))
    return raw[:dlc]


class CarHackingLoader(BaseLoader):
    """Parse one CAR-Hacking file (CSV attack capture or text normal log)."""

    def __init__(self, path: str, attack_type: Optional[str] = None,
                 max_frames: Optional[int] = None) -> None:
        super().__init__(path, attack_type, max_frames)
        if attack_type is not None and attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(
                f"attack_type must be one of {sorted(_VALID_ATTACK_TYPES)} "
                f"or None, got {attack_type!r}"
            )

    # -- format detection -----------------------------------------------------
    def _is_text_format(self) -> bool:
        """True for the OTIDS-style attack-free capture (``.txt`` with 'ID:')."""
        if self.path.lower().endswith(".txt"):
            return True
        # Content sniff: first non-empty line contains the 'Timestamp:' token.
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        return "Timestamp:" in line and "ID:" in line
        except OSError:
            return False
        return False

    # -- public API -----------------------------------------------------------
    def iter_frames(self) -> Iterator[CanFrame]:
        if self._is_text_format():
            yield from self._iter_text_frames()
        else:
            yield from self._iter_csv_frames()

    # -- CSV attack captures --------------------------------------------------
    def _iter_csv_frames(self) -> Iterator[CanFrame]:
        attack_tag = self.attack_type or "dos"
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
                if can_id is None or dlc is None or not (0 <= dlc <= 8):
                    continue

                flag = tokens[-1].upper()
                data_tokens = tokens[3:3 + dlc]
                data = self._parse_data_bytes(data_tokens)
                data = _fit_data(data, dlc)

                if flag == "T":
                    label, atype = 1, attack_tag
                else:  # 'R' or anything else -> treat as normal
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

    # -- OTIDS-style text normal log ------------------------------------------
    def _iter_text_frames(self) -> Iterator[CanFrame]:
        with open(self.path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.rstrip("\n")
                stripped = line.strip()
                if not stripped:
                    continue
                m = _TEXT_LINE_RE.search(stripped)
                if not m:
                    continue

                ts = self._parse_float(m.group("ts"))
                can_id = _to_int(m.group("id"), 16)
                dlc = _to_int(m.group("dlc"), 10)
                if ts is None or can_id is None or dlc is None:
                    continue
                if not (0 <= dlc <= 8):
                    continue

                flag = m.group("flag")
                is_remote = flag == "100" or flag.upper() == "R"

                data = self._parse_data_bytes(m.group("data").split())
                data = _fit_data(data, dlc)

                # normal_run_data.txt is entirely benign.
                yield CanFrame(
                    timestamp=ts,
                    can_id=can_id,
                    dlc=dlc,
                    data=data,
                    label=0,
                    attack_type="normal",
                    is_remote=is_remote,
                    raw=stripped,
                )

    # -- helpers --------------------------------------------------------------
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
