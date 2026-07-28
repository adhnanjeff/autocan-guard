"""Configuration for the standard CAN dataset benchmark.

Central place for dataset locations, injected-ID maps (used to label OTIDS,
which ships without a ground-truth column) and default evaluation parameters.
Override ``DATA_ROOT`` with the env var ``CAN_BENCHMARK_DATA`` to point at the
directory where you extracted the downloaded HCRL datasets.
"""

from __future__ import annotations

import os

# Root directory that contains the three extracted datasets. Each dataset lives
# in its own subdirectory (see benchmark/README.md for the expected layout).
DATA_ROOT = os.environ.get(
    "CAN_BENCHMARK_DATA",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "datasets_raw"),
)

# Where evaluation reports/graphs for the standard datasets are written.
REPORT_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "evaluation_reports",
    "standard_datasets",
)

# --- OTIDS labeling (no ground-truth column in the raw files) ----------------
# HCRL documents the injected arbitration IDs and a coarse attack time window.
# We label a frame as attack (1) when it matches the injected ID for that file
# AND falls in the under-attack window. Documented as imprecise upstream; the
# loader records this so the report can cite the labeling method honestly.
OTIDS_INJECTED_IDS = {
    "dos": {0x000},          # DoS: flood of 0x000 (highest priority) messages
    "impersonation": {0x164},# Impersonation: forged 0x164 frames
    "fuzzy": None,           # Fuzzy: random IDs -> fall back to time-window labeling
}
# Seconds from file start before which traffic is treated as attack-free.
OTIDS_ATTACK_START_SEC = 250.0

# --- CAN-FD injected IDs (files DO carry a T/R label; these are for reference/
#     per-attack breakdown and sanity checks) ---------------------------------
CANFD_INJECTED_IDS = {
    "flooding": {0x000},
    "malfunction": {0x125},
    "fuzzing": None,
}

# --- Default evaluation parameters -------------------------------------------
DEFAULT_TEST_SIZE = 0.30       # stratified hold-out fraction
DEFAULT_RANDOM_STATE = 42
DEFAULT_WINDOW_SEC = 0.02      # sliding window for windowed features (20 ms)
# Cap frames per file so a full-dataset run stays tractable; None = use all.
DEFAULT_MAX_FRAMES = None
