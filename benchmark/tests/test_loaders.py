"""Unit tests for the three CAN benchmark dataset loaders.

Runs each loader against the format-accurate fixtures under
``benchmark/fixtures/`` and asserts the contract invariants: non-empty output,
both label classes present in attack captures, variable-DLC parsing with
``len(data) == dlc``, hex->int ID parsing, non-decreasing timestamps, OTIDS
remote-frame parsing, and ``get_loader`` factory dispatch.
"""

from __future__ import annotations

import os

import pytest

from benchmark.can_frame import CanFrame
from benchmark.loaders import get_loader
from benchmark.loaders.base import DatasetName
from benchmark.loaders.car_hacking import CarHackingLoader
from benchmark.loaders.otids import OtidsLoader
from benchmark.loaders.can_fd import CanFdLoader

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")

CH_DOS = os.path.join(FIXTURES, "car_hacking", "DoS_dataset_sample.csv")
CH_FUZZY = os.path.join(FIXTURES, "car_hacking", "Fuzzy_dataset_sample.csv")
CH_NORMAL_TXT = os.path.join(FIXTURES, "car_hacking", "normal_run_data_sample.txt")

OTIDS_DOS = os.path.join(FIXTURES, "otids", "DoS_attack_sample.txt")
OTIDS_IMP = os.path.join(FIXTURES, "otids", "Impersonation_attack_sample.txt")
OTIDS_FUZZY = os.path.join(FIXTURES, "otids", "Fuzzy_attack_sample.txt")
OTIDS_FREE = os.path.join(FIXTURES, "otids", "Attack_free_sample.txt")

FD_FLOOD = os.path.join(FIXTURES, "can_fd", "Flooding_sample.csv")
FD_FUZZ = os.path.join(FIXTURES, "can_fd", "Fuzzing_sample.csv")
FD_MALF = os.path.join(FIXTURES, "can_fd", "Malfunction_sample.csv")


# --- shared invariant helpers ------------------------------------------------
def _assert_frame_invariants(frames):
    assert frames, "loader produced no frames"
    for f in frames:
        assert isinstance(f, CanFrame)
        assert len(f.data) == f.dlc, f"len(data)={len(f.data)} != dlc={f.dlc}"
        assert f.label in (0, 1)
        assert isinstance(f.can_id, int) and f.can_id >= 0
        if f.label == 0:
            assert f.attack_type == "normal"
        else:
            assert f.attack_type != "normal"


def _assert_non_decreasing_timestamps(frames):
    ts = [f.timestamp for f in frames]
    assert ts == sorted(ts), "timestamps are not non-decreasing"


def _labels(frames):
    return {f.label for f in frames}


# ============================ CAR-Hacking ====================================
def test_car_hacking_dos_basic():
    frames = CarHackingLoader(CH_DOS, attack_type="dos").load()
    _assert_frame_invariants(frames)
    _assert_non_decreasing_timestamps(frames)
    # Header row must be skipped (first data timestamp is a real float).
    assert all(f.raw is None or not f.raw.startswith("Timestamp,") for f in frames)
    # Both classes present.
    assert _labels(frames) == {0, 1}
    # Injected frames tagged 'dos'; DoS floods use ID 0x000.
    attack = [f for f in frames if f.label == 1]
    assert attack and all(f.attack_type == "dos" for f in attack)
    assert all(f.can_id == 0x000 for f in attack)


def test_car_hacking_variable_dlc():
    frames = CarHackingLoader(CH_DOS, attack_type="dos").load()
    # Fixture contains benign short-DLC rows (DLC<8). Confirm they parsed and
    # kept the len(data)==dlc invariant.
    short = [f for f in frames if f.dlc < 8]
    assert short, "expected at least one variable/short-DLC row"
    for f in short:
        assert len(f.data) == f.dlc


def test_car_hacking_hex_id_parsing():
    frames = CarHackingLoader(CH_DOS, attack_type="dos").load()
    # 0x018f appears benignly in the fixture; confirm hex->int parse.
    ids = {f.can_id for f in frames}
    assert 0x018F in ids
    assert 0x0000 in ids  # DoS injected ID


def test_car_hacking_fuzzy_both_classes():
    frames = CarHackingLoader(CH_FUZZY, attack_type="fuzzy").load()
    _assert_frame_invariants(frames)
    assert _labels(frames) == {0, 1}
    assert all(f.attack_type == "fuzzy" for f in frames if f.label == 1)


def test_car_hacking_normal_txt_all_benign():
    # A .txt file passed to CarHackingLoader must be auto-detected as the
    # OTIDS-style text format and parsed as all-benign.
    frames = CarHackingLoader(CH_NORMAL_TXT).load()
    _assert_frame_invariants(frames)
    _assert_non_decreasing_timestamps(frames)
    assert _labels(frames) == {0}
    assert all(f.attack_type == "normal" for f in frames)


def test_car_hacking_max_frames():
    frames = CarHackingLoader(CH_DOS, attack_type="dos", max_frames=10).load()
    assert len(frames) == 10


def test_car_hacking_invalid_attack_type():
    with pytest.raises(ValueError):
        CarHackingLoader(CH_DOS, attack_type="bogus")


# ================================ OTIDS ======================================
def test_otids_dos_injected_id_labeling():
    frames = OtidsLoader(OTIDS_DOS, attack_type="dos").load()
    _assert_frame_invariants(frames)
    _assert_non_decreasing_timestamps(frames)
    assert _labels(frames) == {0, 1}
    # DoS: attack iff can_id == 0x000.
    for f in frames:
        if f.can_id == 0x000:
            assert f.label == 1 and f.attack_type == "dos"
        else:
            assert f.label == 0


def test_otids_impersonation_injected_id_and_remote():
    frames = OtidsLoader(OTIDS_IMP, attack_type="impersonation").load()
    _assert_frame_invariants(frames)
    assert _labels(frames) == {0, 1}
    # Impersonation: attack iff can_id == 0x164.
    for f in frames:
        if f.can_id == 0x164:
            assert f.label == 1 and f.attack_type == "impersonation"
        else:
            assert f.label == 0
    # is_remote must be parsed (flag 100 rows exist in the fixture).
    assert any(f.is_remote for f in frames), "expected remote frames (flag 100)"
    assert any(not f.is_remote for f in frames)


def test_otids_fuzzy_time_window_labeling():
    frames = OtidsLoader(OTIDS_FUZZY, attack_type="fuzzy").load()
    _assert_frame_invariants(frames)
    _assert_non_decreasing_timestamps(frames)
    assert _labels(frames) == {0, 1}
    first_ts = frames[0].timestamp
    from benchmark import config
    for f in frames:
        elapsed = f.timestamp - first_ts
        if elapsed >= config.OTIDS_ATTACK_START_SEC:
            assert f.label == 1 and f.attack_type == "fuzzy"
        else:
            assert f.label == 0


def test_otids_attack_free_all_benign():
    frames = OtidsLoader(OTIDS_FREE, attack_type="attack_free").load()
    _assert_frame_invariants(frames)
    assert _labels(frames) == {0}


def test_otids_none_attack_type_all_benign():
    frames = OtidsLoader(OTIDS_DOS, attack_type=None).load()
    assert _labels(frames) == {0}


def test_otids_hex_id_and_dlc_invariant():
    frames = OtidsLoader(OTIDS_DOS, attack_type="dos").load()
    for f in frames:
        assert len(f.data) == f.dlc
    assert 0x000 in {f.can_id for f in frames}


def test_otids_invalid_attack_type():
    with pytest.raises(ValueError):
        OtidsLoader(OTIDS_DOS, attack_type="bogus")


# =============================== CAN-FD ======================================
def test_can_fd_flooding_both_classes():
    frames = CanFdLoader(FD_FLOOD, attack_type="flooding").load()
    _assert_frame_invariants(frames)
    _assert_non_decreasing_timestamps(frames)
    assert _labels(frames) == {0, 1}
    assert all(f.attack_type == "flooding" for f in frames if f.label == 1)


def test_can_fd_large_dlc_parsing():
    # CAN-FD allows DLC up to 64. Confirm a 64-byte frame parses and keeps the
    # len(data)==dlc invariant.
    frames = CanFdLoader(FD_FLOOD, attack_type="flooding").load()
    big = [f for f in frames if f.dlc > 8]
    assert big, "expected CAN-FD frames with DLC > 8"
    assert any(f.dlc == 64 for f in frames), "expected a 64-byte CAN-FD frame"
    for f in big:
        assert len(f.data) == f.dlc


def test_can_fd_fuzzing_and_malfunction():
    # The 'fuzzing' kwarg maps onto the canonical ATTACK_TYPES tag 'fuzzy'
    # (can_frame.ATTACK_TYPES has no 'fuzzing' member).
    for path, atype, tag in [(FD_FUZZ, "fuzzing", "fuzzy"),
                             (FD_MALF, "malfunction", "malfunction")]:
        frames = CanFdLoader(path, attack_type=atype).load()
        _assert_frame_invariants(frames)
        assert _labels(frames) == {0, 1}
        assert all(f.attack_type == tag for f in frames if f.label == 1)


def test_can_fd_invalid_attack_type():
    with pytest.raises(ValueError):
        CanFdLoader(FD_FLOOD, attack_type="bogus")


# ============================ get_loader factory =============================
def test_get_loader_returns_correct_class():
    assert isinstance(
        get_loader(DatasetName.CAR_HACKING, CH_DOS, attack_type="dos"),
        CarHackingLoader,
    )
    assert isinstance(
        get_loader(DatasetName.OTIDS, OTIDS_DOS, attack_type="dos"),
        OtidsLoader,
    )
    assert isinstance(
        get_loader(DatasetName.CAN_FD, FD_FLOOD, attack_type="flooding"),
        CanFdLoader,
    )


def test_get_loader_by_string_name():
    # DatasetName is a str-enum; string values must dispatch too.
    loader = get_loader("car_hacking", CH_DOS, attack_type="dos")
    assert isinstance(loader, CarHackingLoader)
    frames = loader.load()
    assert frames and _labels(frames) == {0, 1}
