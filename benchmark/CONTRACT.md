# Benchmark package — interface contract (DO NOT BREAK)

Fable owns these interfaces. Subagents implement modules against them so the
pieces integrate without drift. Everything consumes one shared type:
`benchmark.can_frame.CanFrame` (already implemented).

```python
@dataclass
class CanFrame:
    timestamp: float      # seconds, monotonic within a file
    can_id: int           # arbitration ID as int
    dlc: int              # 0..8 (CAN) or 0..64 (CAN-FD)
    data: bytes           # len == dlc (loaders enforce)
    label: int            # 0 normal, 1 attack
    attack_type: str      # one of ATTACK_TYPES; "normal" when label==0
    is_remote: bool
    raw: str | None
```

## 1. Loaders (module: `benchmark/loaders/*.py`) — OWNER: loaders subagent

Each concrete loader subclasses `benchmark.loaders.base.BaseLoader` and
implements `iter_frames() -> Iterator[CanFrame]`, yielding frames in timestamp
order. `get_loader(DatasetName, path, **kwargs)` already dispatches to them.

- `CarHackingLoader(path, attack_type=None, max_frames=None)` — parses CSV
  `Timestamp, CAN ID, DLC, DATA[0..DLC-1], Flag`. Variable DLC ⇒ the Flag is the
  LAST field on the line, not a fixed column. `Flag == 'T'` ⇒ label 1, `'R'` ⇒ 0.
  `attack_type` (dos/fuzzy/gear/rpm) tags injected frames; normal file ⇒ all label 0.
- `OtidsLoader(path, attack_type=None, max_frames=None)` — parses text lines
  `Timestamp: <float>   ID: <hex>   <flag 000/100>   DLC: <n>   b0 b1 ...`.
  NO label column: label using `benchmark.config.OTIDS_INJECTED_IDS[attack_type]`
  (injected ID match) AND `OTIDS_ATTACK_START_SEC` time window. `100`/remote ⇒
  `is_remote=True`. Document the labeling method in a module docstring.
- `CanFdLoader(path, attack_type=None, max_frames=None)` — CSV with up to 64
  data bytes and a trailing `T`/`R` label. attack_type in flooding/fuzzing/malfunction.

Provide **format-accurate fixtures** under `benchmark/fixtures/<dataset>/` (a few
hundred lines each, real column layout, mix of normal+attack) and loader unit
tests under `benchmark/tests/test_loaders.py` asserting: frame counts, that
variable-DLC rows parse, correct labels, hex→int ID parsing, timestamp order.

## 2. Feature extractor (module: `benchmark/features.py`) — OWNER: features subagent

Implement:

```python
class CanFeatureExtractor:
    feature_names: list[str]                       # ordered, stable
    def __init__(self, window_sec: float = 0.02): ...
    def reset(self) -> None: ...                    # clear streaming state
    def extract(self, frame: CanFrame) -> np.ndarray:
        # 1-D float array, len == len(feature_names). Uses streaming state, so
        # frames MUST be fed in timestamp order. Never raises on first frame.
    def extract_batch(self, frames: list[CanFrame]) -> np.ndarray:
        # (N, F) matrix; calls reset() then extract() in order.
```

Feature set (message-level + windowed per-ID, standard for CAN IDS):
inter-arrival time to previous same-ID frame; deviation of that IAT from the ID's
running-mean IAT; global inter-arrival (bus load); can_id (normalized); dlc;
payload Shannon entropy; Hamming distance / changed-byte count vs the ID's
previous payload; count of this ID in the sliding window; total msgs in window;
unique IDs in window; ID novelty flag (first time seen). All finite floats
(no NaN/Inf). Keep it dimension-stable across datasets.

Tests in `benchmark/tests/test_features.py`: fixed length output, deterministic,
no NaN/Inf, IAT ~0 for a rapid flood vs large for spaced-out frames.

## 3. Metrics + runner (modules: `benchmark/metrics.py`, `benchmark/benchmark_runner.py`, `run_benchmark.py`) — OWNER: runner subagent

`metrics.py`:
```python
def classification_metrics(y_true, y_pred) -> dict
    # accuracy, precision, recall, f1, specificity, fpr, confusion {tp,tn,fp,fn}
    # (use sklearn.metrics; guard zero-division)
def latency_throughput(per_msg_seconds: list[float]) -> dict
    # mean/median/p95/p99 latency in ms, throughput msgs/sec
def per_attack_breakdown(frames, y_pred) -> dict   # metrics per attack_type
```

`benchmark_runner.py` — `BenchmarkRunner`:
- Takes a `DatasetName`, a mapping of attack_type -> file path (+ normal file),
  loads all frames via `get_loader`, concatenates, sorts by timestamp.
- Extracts features with `CanFeatureExtractor` (feed in order), builds X, y.
- Stratified train/test split (`config.DEFAULT_TEST_SIZE`, `DEFAULT_RANDOM_STATE`).
- Trains a dimension-agnostic ensemble (sklearn RandomForest primary +
  GradientBoosting + IsolationForest). Do NOT reuse anomaly_detector.py
  (that is hardwired to 48-dim steering/speed/brake vectors) — build a small
  local `BenchmarkModel`. Existing runtime code must stay untouched.
- Measures per-message inference latency with time.perf_counter over the test set.
- Writes JSON report + PNG graphs (confusion matrix, per-attack F1 bar,
  latency histogram) to `config.REPORT_ROOT/<dataset>/`.

`run_benchmark.py` (repo root) — CLI:
`python run_benchmark.py --dataset car_hacking --data-dir <dir>` and a
`--fixtures` flag that runs against `benchmark/fixtures/` so the whole pipeline
is verifiable without the multi-GB downloads. Must print the six required
metrics: precision, recall, accuracy, F1, latency, throughput.

End-to-end test `benchmark/tests/test_benchmark_end_to_end.py`: run on fixtures,
assert all six metrics exist and are finite / in valid ranges.

## Ground rules for all subagents
- Only create files inside `benchmark/` (and `run_benchmark.py` at repo root for
  the runner subagent). Do NOT edit any existing project file.
- Pure functions where possible; type hints; module docstrings.
- No network calls, no fabricated results, no hardcoded metric values.
- `python -m pytest benchmark/tests/<your test> -q` must pass before you return.
