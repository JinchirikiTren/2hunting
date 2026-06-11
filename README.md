# 🔍 Threat Hunter — Automated SOC Log Processing Pipeline

**High-performance ETL pipeline for Security Operations Center (SOC) threat hunting shift logs.**

Processes CSV-exported logs through whitelist-based noise reduction, historical frequency analysis, and structured archival. Designed to handle **100,000+ rows in seconds** via pure Pandas vectorization — zero row iteration.

---

## 📖 Table of Contents

- [Architecture](#-architecture)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Directory Structure](#-directory-structure)
- [Configuration Guide](#-configuration-guide)
- [Usage](#-usage)
- [Pipeline Walkthrough](#-pipeline-walkthrough)
- [Sample Data](#-sample-data)
- [FAQ](#-faq)

---

## 🏗 Architecture

```
                    ┌──────────────────┐
                    │  input_logs/     │   Raw CSV files
                    │  <usecase>.csv   │   (auto-detected delimiter)
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  configs/        │   JSON usecase rules
                    │  usecase_config  │   • dedup_fields
                    │  .json           │   • whitelist_rules (regex)
                    └────────┬─────────┘
                             │
              ┌──────────────▼──────────────┐
              │     threat_hunter.py         │
              │                              │
              │  1. Read CSV  (C engine)     │
              │  2. Whitelist (vectorized)   │
              │  3. Load 5-day history       │
              │  4. GroupBy → Occurrence_Count│
              │  5. Save + Archive           │
              └──────┬──────────┬───────────┘
                     │          │
          ┌──────────▼──┐  ┌───▼───────────┐
          │ processed/  │  │ archive_logs/ │
          │ <YYYYMMDD>/ │  │ <YYYYMMDD>/   │
          │ <HHMMSS>/   │  │ <HHMMSS>/     │
          └─────────────┘  └───────────────┘
```

### Data Flow

1. **Ingest**: CSV files are read with the C engine (`pd.read_csv(engine='c')`) and auto-detected delimiters (comma or tab).
2. **Filter**: Pre-compiled regex patterns are applied as vectorized Pandas masks — rows matching whitelist patterns are dropped as benign noise.
3. **Enrich**: Historical data from the past 5 days (same usecase) is loaded and concatenated. A `groupby().size()` computes `Occurrence_Count` for each unique combination of dedup fields.
4. **Export**: The enriched DataFrame is saved to `processed_logs/<YYYYMMDD>/<HHMMSS>/<original_filename>`. If processed from the default input directory, the original file is moved to `archive_logs/`.

### Timestamp-based Runs

Mỗi lần chạy pipeline sẽ **tự động tạo một thư mục timestamp** (định dạng `HHMMSS`) bên trong thư mục ngày. Điều này đảm bảo:

- **Không ghi đè** — mỗi lần chạy có thư mục riêng, dù chạy nhiều lần trong ngày.
- **Không cần `--shift`** — không cần đặt tên ca, không phụ thuộc vào lịch shift liên tục.
- **Truy vết dễ dàng** — timestamp cho biết chính xác thời điểm chạy.

---

## 📋 Prerequisites & Installation

### Requirements

- **Python** 3.8+
- **pandas** ≥ 1.5.0 (the only third-party dependency)

### Install

```bash
# Clone or navigate to the project directory
cd ToHunt

# Install dependencies
pip install -r requirements.txt
```

### Verify

```bash
python threat_hunter.py --help
```

---

## 📂 Directory Structure

```
ToHunt/
├── threat_hunter.py            # Main pipeline script
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── Samples/                    # Sample CSV files for testing
│   ├── uc1.csv
│   ├── uc2.csv
│   ├── uc3.csv
│   ├── uc6.csv
│   └── uc19.csv
├── configs/
│   └── usecase_config.json     # Usecase definitions (editable)
├── input_logs/                 # Drop incoming CSVs here
│   ├── uc1.csv                 #   Tên file = <usecase_name>.csv
│   ├── uc6.csv
│   └── ...
├── processed_logs/             # Auto-created output tree
│   ├── 20260611/
│   │   ├── 093800/             #   Lần chạy lúc 09:38:00
│   │   │   ├── uc1.csv
│   │   │   └── uc6.csv
│   │   └── 145530_ca1/         #   Lần chạy lúc 14:55:30 (có label "ca1")
│   │       └── uc6.csv
│   └── 20260610/
│       └── ...
└── archive_logs/               # Original files moved here after success
    └── 20260611/
        └── 093800/
            └── uc1.csv
```

### Naming Convention

Input files chỉ cần đặt tên theo: **`<usecase_name>.csv`**

| File | Usecase |
|---|---|
| `uc1.csv` | `uc1` |
| `uc6.csv` | `uc6` |
| `brute_force_ssh.csv` | `brute_force_ssh` |

> Không cần hậu tố shift. Tên file = usecase name trong config.

---

## ⚙️ Configuration Guide

The heart of the pipeline is [configs/usecase_config.json](configs/usecase_config.json). Each usecase entry defines **what to count** and **what to ignore**.

### JSON Schema

```json
{
  "<usecase_name>": {
    "dedup_fields": ["field_a", "field_b", "..."],
    "whitelist_rules": [
      {
        "field": "<column_name>",
        "regex": "<python_regex_pattern>"
      }
    ]
  }
}
```

### Fields

| Key | Type | Description |
|---|---|---|
| `dedup_fields` | `string[]` | Columns used to compute `Occurrence_Count`. Rows with the same combination of these fields across the 5-day window get a higher count. |
| `whitelist_rules` | `object[]` | **Noise filters**. Rows matching **any** rule are **dropped** (removed from the dataset before counting). |
| `whitelist_rules[].field` | `string` | The DataFrame column to evaluate the regex against. |
| `whitelist_rules[].regex` | `string` | Python-compatible regex pattern. Pre-compiled at startup for speed. |

### Example: `uc6` (Service Enumeration)

```json
{
  "uc6": {
    "dedup_fields": ["service_target_file_path"],
    "whitelist_rules": [
      {
        "field": "service_target_name",
        "regex": "^(?:Google Updater|Brother|Kaspersky|Foxit|Microsoft Copilot|TeamViewer|...).*"
      }
    ]
  }
}
```

**What this does:**

1. **Whitelist**: Drops all rows where `service_target_name` matches known legitimate services (Google Updater, Kaspersky, etc.). These are benign noise.
2. **Dedup**: Counts how many times each `service_target_file_path` has appeared across the current file + the past 5 days of processed logs.
3. **Output**: Adds an `Occurrence_Count` column. A count of `1` = first time seen — potential anomaly. Higher counts = frequently observed, likely benign.

### Writing Effective Regex Rules

- **Prefer anchoring**: Use `^...$` to avoid partial matches.
- **Use non-capturing groups**: `(?:...)` instead of `(...)` to avoid pandas warnings.
- **Escape backslashes**: JSON requires `\\` for a literal backslash. A Windows path `C:\Windows\System32\` becomes `^C:\\\\Windows\\\\System32\\\\.*` in JSON.
- **Test your patterns**: Use [regex101.com](https://regex101.com) (Python flavor) before adding rules.
- **Multiple rules per field**: You can add multiple rules for the same field — a row is dropped if **any** match.
- **Invalid regex**: Malformed patterns are logged and skipped (they don't crash the pipeline).

### Adding a New Usecase

1. Add a new key to `configs/usecase_config.json`.
2. Define `dedup_fields` — pick the columns that define a "unique event" for your hunt.
3. Define `whitelist_rules` — identify known-benign patterns to filter.
4. Drop CSV files named `<your_usecase>.csv` into `input_logs/`.
5. Run the pipeline.

---

## 🚀 Usage

### Basic Commands

```bash
# Process all usecases in input_logs/ (today's date, auto timestamp)
python threat_hunter.py

# Process only one usecase
python threat_hunter.py --usecase uc6

# Process for a specific date (looks back 5 days from this date)
python threat_hunter.py --date 20260610

# Process a single CSV file directly
python threat_hunter.py --input_path ./alerts.csv

# Process from a custom directory (no archiving)
python threat_hunter.py --input_path ./custom_logs/

# Add a human-readable label to the run folder (e.g. "ca1", "ca2")
python threat_hunter.py --run_label ca1
# → Output: processed_logs/20260611/145530_ca1/...

# Dry-run: see what would happen without writing files
python threat_hunter.py --dry-run --verbose
```

### Cách chạy với lịch shift không liên tục

Bạn không cần flag `--shift` nữa. Mỗi lần chạy tự động tạo timestamp riêng:

```bash
# Ngày làm 1 ca — chạy 1 lần
python threat_hunter.py

# Ngày làm 2 ca — chạy 2 lần, mỗi lần tự động vào thư mục timestamp riêng
python threat_hunter.py --run_label ca1
python threat_hunter.py --run_label ca2
```

Kết quả:
```
processed_logs/20260611/
├── 083015_ca1/    ← Ca 1, chạy lúc 08:30:15
│   ├── uc1.csv
│   └── uc6.csv
└── 134522_ca2/    ← Ca 2, chạy lúc 13:45:22
    ├── uc1.csv
    └── uc6.csv
```

Historical data (5 ngày) được quét qua **tất cả** thư mục timestamp, không phân biệt ca — đảm bảo `Occurrence_Count` được tính chính xác trên toàn bộ dữ liệu lịch sử.

### CLI Reference

| Flag | Required | Default | Description |
|---|---|---|---|
| `--date` | No | Today | Execution date in `YYYYMMDD`. Historical lookback is relative to this. |
| `--usecase` | No | All | Run only this usecase. Must match a key in the config. |
| `--input_path` | No | `input_logs/` | Path to a CSV file or a directory of CSVs. |
| `--config` | No | `configs/usecase_config.json` | Path to the usecase configuration JSON. |
| `--output_dir` | No | `processed_logs/` | Root directory for processed output. |
| `--archive_dir` | No | `archive_logs/` | Root directory for archived originals. |
| `--run_label` | No | (none) | Optional label appended to timestamp folder (e.g. `ca1` → `145530_ca1`). |
| `--verbose` | No | `false` | Enable DEBUG-level logging. |
| `--dry-run` | No | `false` | Simulate without saving/archiving. |

### Archiving Behavior

| Input Source | Archiving? |
|---|---|
| Default `input_logs/` directory | ✅ Yes — original moved to `archive_logs/<YYYYMMDD>/<HHMMSS>/` |
| Custom `--input_path` (file or directory) | ❌ No — original left in place |

> Nếu file gốc không còn tồn tại (vd: đã bị lần chạy trước archive), script sẽ log WARNING và bỏ qua bước archive — không crash.

---

## 🔬 Pipeline Walkthrough

For each input file, the pipeline executes these steps:

### Step 1 — CSV Ingestion
```python
df = pd.read_csv(file_path, engine="c", low_memory=False)
```
- Uses pandas' fast **C engine** (compiled C parser).
- Auto-detects comma vs. tab delimiter.
- Gracefully handles quoted fields and embedded newlines.

### Step 2 — Whitelist Filtering
```python
for field, pattern in compiled_rules:
    mask = mask | df[field].astype(str).str.contains(pattern, regex=True, na=False)
df = df[~mask]
```
- Regex patterns are **pre-compiled once** at startup via `re.compile()`.
- All filtering uses **vectorized `pd.Series.str.contains()`** — no `iterrows()`, no loops.
- Rows matching **any** whitelist rule are dropped.
- If all rows are dropped, an empty CSV (headers only) is still exported.

### Step 3 — Historical Aggregation
```python
for day in previous_5_days:
    for run_dir in processed_logs/<day>/*:
        for csv in run_dir/<usecase>*.csv:
            frames.append(pd.read_csv(csv)[dedup_fields])
historical = pd.concat(frames)
```
- Scans `processed_logs/` for the same usecase across the past 5 days.
- Walks **all timestamp subdirectories** — không phân biệt shift/ca.
- Reads only the columns needed for deduplication (memory efficient).
- Gracefully handles missing days, empty files, and missing columns.

### Step 4 — Frequency Counting
```python
combined = pd.concat([current[dedup_fields], historical[dedup_fields]])
counts = combined.groupby(dedup_fields).size().reset_index(name="Occurrence_Count")
result = current.merge(counts, on=dedup_fields, how="left")
```
- Concatenates current + historical dedup columns.
- `groupby().size()` produces the frequency table in **one vectorized pass**.
- Left-merge attaches `Occurrence_Count` to the current DataFrame.
- Rows with no historical match get `Occurrence_Count = 1`.

### Step 5 — Output & Archive
```python
df.to_csv(output_path, index=False)
shutil.move(source_path, archive_path)
```
- Processed CSV written to `processed_logs/<YYYYMMDD>/<HHMMSS>/<original_filename>`.
- Original moved to `archive_logs/<YYYYMMDD>/<HHMMSS>/` (default input only).

---

## 📊 Sample Data

The [Samples/](Samples/) directory contains representative CSV files for testing:

| File | Type | Key Fields | Rows |
|---|---|---|---|
| [uc1.csv](Samples/uc1.csv) | EDR/XDR process execution | `file_hash_md5`, `file_internalname`, `source_process_path`, `target_process_path`, `VT_name_match` | ~4 |
| [uc2.csv](Samples/uc2.csv) | EDR DLL loading | `file_hash_md5`, `file_internalname`, `file_path`, `source_process_path` | ~4 |
| [uc3.csv](Samples/uc3.csv) | EDR process lineage | `file_hash_md5`, `source_process_path`, `target_process_path`, `target_commandline` | ~4 |
| [uc6.csv](Samples/uc6.csv) | Service enumeration | `service_target_name`, `target_commandline`, `service_target_file_path` | ~132 |
| [uc19.csv](Samples/uc19.csv) | Network DNS queries | `net_target_host_name`, `source_process_path`, `net_target_host_name_parrent` | ~4 |

### Quick Test

```bash
# Test with sample data (dry-run)
python threat_hunter.py --input_path ./Samples/ --dry-run --verbose

# Process a single sample file
python threat_hunter.py --input_path ./Samples/uc6.csv --verbose
```

---

## ❓ FAQ

### Q: Tôi chạy 2 lần trong cùng một ngày thì có bị ghi đè không?
**Không.** Mỗi lần chạy tự động tạo thư mục timestamp riêng (`093800`, `145530`, ...). Nếu 2 lần chạy trong cùng 1 giây, script sẽ tự động thêm hậu tố `_2`, `_3` để tránh trùng.

### Q: Tôi không muốn đặt tên file theo shift, chỉ theo usecase?
Đúng — đó là cách script hoạt động. File input chỉ cần tên `<usecase>.csv`.

### Q: What happens if a config is missing for a usecase?
The file is **skipped** with a `WARNING` log. All other usecases continue processing.

### Q: What if the whitelist drops 100% of rows?
An empty CSV with column headers is still exported. This is a valid result — "no suspicious events after noise removal."

### Q: What if there is no historical data?
The pipeline proceeds normally. `Occurrence_Count` will be `1` for every row (first occurrence in the window).

### Q: How is the CSV delimiter detected?
The script tries comma (`,`) first. If the resulting DataFrame has fewer than 2 columns, it falls back to tab (`\t`).

### Q: Can I run multiple instances concurrently?
Có. Mỗi lần chạy có timestamp riêng nên không xung đột:

```bash
python threat_hunter.py & python threat_hunter.py --run_label ca2 &
```

### Q: Làm sao để phân biệt output của ca 1 và ca 2?
Dùng `--run_label`:

```bash
python threat_hunter.py --run_label ca1    # → processed_logs/20260611/093800_ca1/
python threat_hunter.py --run_label ca2    # → processed_logs/20260611/145530_ca2/
```

### Q: How do I add a new field to my usecase?
1. Update the `dedup_fields` list in `usecase_config.json`.
2. Add any relevant `whitelist_rules` for the new field.
3. Re-run the pipeline. Historical data will be re-read with the new field.

---

## 📄 License

Internal SOC tooling. All rights reserved.

---

## 🤝 Contributing

1. Follow the existing code style — type hints, docstrings, logging conventions.
2. Never introduce row iteration — all DataFrame operations must be vectorized.
3. Test with `--dry-run --verbose` before submitting changes.
4. Update this README if you add CLI flags or config schema changes.
