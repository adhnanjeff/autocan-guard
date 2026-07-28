"""Unit tests for benchmark.features.CanFeatureExtractor."""

from __future__ import annotations

import numpy as np
import pytest

from benchmark.can_frame import CanFrame
from benchmark.features import CanFeatureExtractor


def make_frame(timestamp, can_id=0x130, dlc=8, data=None, label=0):
    if data is None:
        data = bytes([1, 2, 3, 4, 5, 6, 7, 8][:dlc])
    return CanFrame(timestamp=timestamp, can_id=can_id, dlc=dlc, data=data, label=label)


# ---------------------------------------------------------------------------
# Shape / length tests
# ---------------------------------------------------------------------------

def test_single_frame_output_length():
    extractor = CanFeatureExtractor()
    frame = make_frame(0.0)
    vec = extractor.extract(frame)
    assert isinstance(vec, np.ndarray)
    assert vec.ndim == 1
    assert vec.shape[0] == len(extractor.feature_names)
    assert vec.dtype == np.float64


def test_batch_output_shape():
    extractor = CanFeatureExtractor()
    frames = [make_frame(t * 0.001, can_id=0x100 + (t % 3)) for t in range(20)]
    mat = extractor.extract_batch(frames)
    assert mat.shape == (20, len(extractor.feature_names))
    assert mat.dtype == np.float64


def test_empty_batch():
    extractor = CanFeatureExtractor()
    mat = extractor.extract_batch([])
    assert mat.shape == (0, len(extractor.feature_names))


# ---------------------------------------------------------------------------
# Finiteness / no NaN / Inf
# ---------------------------------------------------------------------------

def test_no_nan_or_inf_various_frames():
    extractor = CanFeatureExtractor()
    frames = [
        make_frame(0.0, can_id=0x000, dlc=0, data=b""),          # first frame, empty payload
        make_frame(0.0001, can_id=0x000, dlc=0, data=b""),        # repeated id, still empty
        make_frame(0.0005, can_id=0x123, dlc=8, data=bytes(range(8))),
        make_frame(0.0006, can_id=0x123, dlc=8, data=bytes(range(8))),  # identical payload -> hamming 0
        make_frame(0.0007, can_id=0x7FF, dlc=8, data=bytes([0xFF] * 8)),  # max std id
        make_frame(0.0008, can_id=0x1FFFFFFF, dlc=8, data=bytes([0x00] * 8)),  # max ext id
        make_frame(1000.0, can_id=0x123, dlc=3, data=bytes([9, 9, 9])),  # big time jump, shorter dlc
    ]
    for frame in frames:
        vec = extractor.extract(frame)
        assert np.all(np.isfinite(vec)), f"non-finite values for frame {frame}: {vec}"


def test_no_nan_or_inf_batch():
    extractor = CanFeatureExtractor()
    frames = [make_frame(t * 0.0003, can_id=0x200 + (t % 5), dlc=t % 9,
                          data=bytes([i % 256 for i in range(t % 9)]))
              for t in range(100)]
    mat = extractor.extract_batch(frames)
    assert np.all(np.isfinite(mat))


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_determinism_extract_batch():
    extractor = CanFeatureExtractor()
    frames = [make_frame(t * 0.002, can_id=0x300 + (t % 4), dlc=8,
                          data=bytes([(t + i) % 256 for i in range(8)]))
              for t in range(50)]
    mat1 = extractor.extract_batch(frames)
    mat2 = extractor.extract_batch(frames)
    np.testing.assert_array_equal(mat1, mat2)


def test_determinism_fresh_extractor_instance():
    frames = [make_frame(t * 0.002, can_id=0x300 + (t % 4), dlc=8,
                          data=bytes([(t + i) % 256 for i in range(8)]))
              for t in range(50)]
    mat1 = CanFeatureExtractor().extract_batch(frames)
    mat2 = CanFeatureExtractor().extract_batch(frames)
    np.testing.assert_array_equal(mat1, mat2)


# ---------------------------------------------------------------------------
# Behavioral: flood vs spaced-out IAT and rising window count
# ---------------------------------------------------------------------------

def test_flood_vs_spaced_iat_relationship():
    idx = CanFeatureExtractor.feature_names.index("iat_same_id")
    win_idx = CanFeatureExtractor.feature_names.index("id_count_window")

    # Rapid flood: timestamps 0.000, 0.001, 0.002, ... same id.
    flood_extractor = CanFeatureExtractor(window_sec=0.02)
    flood_frames = [make_frame(t * 0.001, can_id=0x150) for t in range(10)]
    flood_mat = flood_extractor.extract_batch(flood_frames)
    flood_iats = flood_mat[1:, idx]  # skip first frame (iat defaults to 0.0 regardless)

    # Widely spaced frames: large gaps between the same id.
    spaced_extractor = CanFeatureExtractor(window_sec=0.02)
    spaced_frames = [make_frame(t * 5.0, can_id=0x150) for t in range(10)]
    spaced_mat = spaced_extractor.extract_batch(spaced_frames)
    spaced_iats = spaced_mat[1:, idx]

    assert np.all(flood_iats < spaced_iats), (
        f"flood IATs should be smaller than spaced IATs: {flood_iats} vs {spaced_iats}"
    )
    assert np.mean(flood_iats) < 0.01
    assert np.mean(spaced_iats) >= 5.0 - 1e-9

    # id_count_window should rise across the flood since messages fall inside
    # the same 0.02s sliding window.
    flood_window_counts = flood_mat[:, win_idx]
    assert flood_window_counts[-1] > flood_window_counts[0]
    assert np.all(np.diff(flood_window_counts) >= 0), "window count should be non-decreasing during a flood"

    # For widely spaced frames (5s gaps >> 0.02s window), the window should
    # never accumulate more than the current frame itself.
    spaced_window_counts = spaced_mat[:, win_idx]
    assert np.all(spaced_window_counts == 1.0)


def test_id_count_window_resets_outside_window():
    extractor = CanFeatureExtractor(window_sec=0.01)
    win_idx = CanFeatureExtractor.feature_names.index("id_count_window")
    total_idx = CanFeatureExtractor.feature_names.index("total_msgs_window")

    frames = [
        make_frame(0.000, can_id=0x1),
        make_frame(0.002, can_id=0x1),
        make_frame(0.004, can_id=0x1),
        # Big gap -- earlier frames should be evicted from the window.
        make_frame(1.000, can_id=0x1),
    ]
    mat = extractor.extract_batch(frames)
    assert mat[2, win_idx] == 3.0  # three frames of id 0x1 within 0.01s window
    assert mat[3, win_idx] == 1.0  # window reset after the 1s gap
    assert mat[3, total_idx] == 1.0


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------

def test_reset_clears_state_and_novelty_refires():
    extractor = CanFeatureExtractor()
    novelty_idx = CanFeatureExtractor.feature_names.index("id_novelty")

    frame1 = make_frame(0.0, can_id=0x42)
    vec1 = extractor.extract(frame1)
    assert vec1[novelty_idx] == 1.0

    frame2 = make_frame(0.001, can_id=0x42)
    vec2 = extractor.extract(frame2)
    assert vec2[novelty_idx] == 0.0  # already seen

    extractor.reset()

    frame3 = make_frame(0.0, can_id=0x42)
    vec3 = extractor.extract(frame3)
    assert vec3[novelty_idx] == 1.0  # novelty fires again after reset

    iat_idx = CanFeatureExtractor.feature_names.index("iat_same_id")
    assert vec3[iat_idx] == 0.0  # per-id history was cleared too


# ---------------------------------------------------------------------------
# First-frame / edge-case robustness
# ---------------------------------------------------------------------------

def test_first_frame_never_raises_and_has_sane_defaults():
    extractor = CanFeatureExtractor()
    frame = make_frame(123.456, can_id=0x77, dlc=8)
    vec = extractor.extract(frame)  # should not raise
    names = extractor.feature_names
    assert vec[names.index("iat_same_id")] == 0.0
    assert vec[names.index("iat_same_id_dev")] == 0.0
    assert vec[names.index("iat_global")] == 0.0
    assert vec[names.index("hamming_prev")] == 0.0
    assert vec[names.index("byte_change_count")] == 0.0
    assert vec[names.index("id_novelty")] == 1.0


def test_empty_payload_frame():
    extractor = CanFeatureExtractor()
    frame = make_frame(0.0, dlc=0, data=b"")
    vec = extractor.extract(frame)
    names = extractor.feature_names
    assert vec[names.index("payload_entropy")] == 0.0
    assert vec[names.index("mean_byte")] == 0.0
    assert vec[names.index("byte_std")] == 0.0
    assert np.all(np.isfinite(vec))


def test_can_id_norm_extended_id_clipped_to_unit_interval():
    extractor = CanFeatureExtractor()
    names = extractor.feature_names
    norm_idx = names.index("can_id_norm")

    std_vec = extractor.extract(make_frame(0.0, can_id=0x7FF))
    assert std_vec[norm_idx] == pytest.approx(1.0)

    ext_vec = extractor.extract(make_frame(0.001, can_id=0x1FFFFFFF))
    assert 0.0 <= ext_vec[norm_idx] <= 1.0
    assert ext_vec[norm_idx] == pytest.approx(1.0)


def test_hamming_and_byte_change_identical_vs_different_payload():
    extractor = CanFeatureExtractor()
    names = extractor.feature_names
    hamming_idx = names.index("hamming_prev")
    change_idx = names.index("byte_change_count")

    extractor.extract(make_frame(0.0, can_id=0x10, data=bytes([0, 0, 0, 0])))
    vec_same = extractor.extract(make_frame(0.001, can_id=0x10, data=bytes([0, 0, 0, 0])))
    assert vec_same[hamming_idx] == 0.0
    assert vec_same[change_idx] == 0.0

    vec_diff = extractor.extract(make_frame(0.002, can_id=0x10, data=bytes([0xFF, 0, 0, 0])))
    assert vec_diff[hamming_idx] == 8.0  # all 8 bits differ in the first byte
    assert vec_diff[change_idx] == 1.0   # only first byte differs


def test_feature_names_length_matches_documented_set():
    # Guard against accidental drift between feature_names and extract().
    extractor = CanFeatureExtractor()
    vec = extractor.extract(make_frame(0.0))
    assert len(extractor.feature_names) == len(vec)
    assert len(set(extractor.feature_names)) == len(extractor.feature_names)  # unique names
