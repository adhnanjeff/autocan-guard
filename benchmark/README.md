# Standard CAN Dataset Benchmark

This package evaluates AutoCAN Guard's detection pipeline on three **standard,
publicly-cited** in-vehicle-network intrusion datasets, so results are
defensible for journal publication:

| Dataset | Source | Attacks | Per-frame label? |
|---|---|---|---|
| **CAR-Hacking Dataset** | HCRL, Korea Univ. | DoS, Fuzzy, Gear spoofing, RPM spoofing | Yes (`T`/`R` flag) |
| **CAN-intrusion / OTIDS** | HCRL, Korea Univ. | DoS, Fuzzy, Impersonation | **No** — derived (see below) |
| **CAN-FD Intrusion Dataset** | HCRL, Korea Univ. | Flooding, Fuzzing, Malfunction | Yes (`T`/`R` flag) |

Metrics reported per dataset **and** per attack type: precision, recall,
accuracy, F1, latency (per-message inference, ms) and throughput (msgs/sec).

## 1. Download the datasets (manual — HCRL gates these behind a form/Dropbox)

I cannot redistribute these datasets. Download them from HCRL and extract:

- CAR-Hacking: https://ocslab.hksecurity.net/Datasets/car-hacking-dataset
- OTIDS (CAN-intrusion): https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset
- CAN-FD: https://ocslab.hksecurity.net/Datasets/can-fd-intrusion-dataset

## 2. Place files in this layout

Default root is `<project>/datasets_raw/` (override with env var
`CAN_BENCHMARK_DATA`). Expected filenames (the CLI matches on keywords, so minor
name differences are tolerated):

```
datasets_raw/
├── car_hacking/
│   ├── DoS_dataset.csv
│   ├── Fuzzy_dataset.csv
│   ├── gear_dataset.csv
│   ├── RPM_dataset.csv
│   └── normal_run_data.txt          # attack-free (OTIDS-style text)
├── otids/
│   ├── Attack_free_dataset.txt
│   ├── DoS_attack_dataset.txt
│   ├── Fuzzy_attack_dataset.txt
│   └── Impersonation_attack_dataset.txt
└── can_fd/
    ├── Flooding_dataset.csv
    ├── Fuzzing_dataset.csv
    └── Malfunction_dataset.csv
```

Run `python download_datasets.py` to print these instructions and verify your
layout (it reports which expected files are present/missing).

## 3. Run the benchmark

Verify the whole pipeline WITHOUT the multi-GB downloads (uses format-accurate
fixtures shipped in `benchmark/fixtures/`):

```bash
python run_benchmark.py --dataset car_hacking --fixtures
python run_benchmark.py --dataset otids      --fixtures
python run_benchmark.py --dataset can_fd     --fixtures
```

Run on the real downloaded data:

```bash
python run_benchmark.py --dataset car_hacking --data-dir datasets_raw/car_hacking
python run_benchmark.py --dataset otids      --data-dir datasets_raw/otids
python run_benchmark.py --dataset can_fd     --data-dir datasets_raw/can_fd
# large files: cap frames while iterating, e.g. --max-frames 200000
```

Reports and graphs are written to
`evaluation_reports/standard_datasets/<dataset>/`.

## OTIDS labeling note (important for the paper)

OTIDS ships **without a ground-truth label column**. HCRL documents the injected
arbitration IDs and a coarse time window instead. This benchmark labels OTIDS as:

- **DoS**: attack ⇔ CAN ID `0x000` (the injected flood ID).
- **Impersonation**: attack ⇔ CAN ID `0x164` (the impersonating node's ID).
- **Fuzzy**: injected IDs are random, so labels fall back to the documented
  time window (traffic after ~250 s from file start is treated as under-attack).

This derived labeling is the community convention for OTIDS and is stated
explicitly in `benchmark/loaders/otids.py` and in each generated report so the
methodology is transparent. For per-frame ground truth, prefer the CAR-Hacking
and CAN-FD datasets, which carry an explicit `T`/`R` flag.
