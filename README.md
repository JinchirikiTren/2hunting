# 🔍 Threat Hunter — Automated SOC Log Processing Pipeline

**High-performance ETL pipeline for Security Operations Center (SOC) threat hunting logs.**

Processes CSV-exported logs through CSV-based whitelist filtering, historical frequency analysis, and structured archival with analyst feedback loop. Designed to handle **100,000+ rows in seconds** via pure Pandas vectorization — zero row iteration.

---

## 📖 Table of Contents

- [Architecture](#-architecture)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Directory Structure](#-directory-structure)
- [Configuration Guide](#-configuration-guide)
- [Whitelist System](#-whitelist-system)
- [Usage](#-usage)
- [Analyst Feedback Loop](#-analyst-feedback-loop)
- [Pipeline Walkthrough](#-pipeline-walkthrough)
- [Sample Data](#-sample-data)
- [Edge Cases & Graceful Degradation](#-edge-cases--graceful-degradation)
- [FAQ](#-faq)

---

## 🏗 Architecture

```
                    ┌──────────────────┐
                    │  input_logs/     │   Raw CSV files
                    │  <usecase>.csv   │
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
  ┌──────▼──────┐   ┌────────▼────────┐   ┌──────▼──────┐
  │ whitelists/ │   │    configs/     │   │ processed/  │
  │ uc1.csv     │   │ usecase_config  │   │ <history>   │
  │ uc6.csv ... │   │ .json           │   │  past 5 days│
  └──────┬──────┘   └────────┬────────┘   └──────┬──────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │     threat_hunter.py         │
              │                              │
              │  1. Read CSV                 │
              │  2. Whitelist (CSV match)    │
              │  3. Add is_benign column     │
              │  4. Load 5-day history       │
              │  5. GroupBy → Occurrence_Count│
              │  6. Save + Archive           │
              └──────┬──────────┬───────────┘
                     │          │
          ┌──────────▼──┐  ┌───▼───────────┐
          │ processed/  │  │ archive_logs/ │
          │ <YYYYMMDD>/ │  │ <YYYYMMDD>/   │
          │ <HHMMSS>/   │  │ <HHMMSS>/     │
          └──────┬──────┘  └───────────────┘
                 │
                 │  (analyst marks is_benign="x")
                 │
          ┌──────▼──────┐
          │update_white │   Adds marked rows
          │    .py      │   to whitelists/
          └─────────────┘
```

### Data Flow

1. **Ingest**: CSV read with C engine, auto-detected delimiter.
2. **Whitelist**: Compare against `whitelists/<usecase>.csv`. Rows matching any whitelist entry are dropped.
3. **Tag**: `is_benign` column added (empty — analyst fills later).
4. **Enrich**: Historical data from past 5 days loaded. `groupby().size()` computes `Occurrence_Count` (history only, today excluded).
5. **Export**: Saved to `processed_logs/<YYYYMMDD>/<HHMMSS>/<original_filename>`. Original archived.
6. **Feedback**: Analyst marks benign rows → `update_white.py` adds them to whitelist.

---

## 📋 Prerequisites & Installation

### Requirements

- **Python** 3.8+
- **pandas** ≥ 1.5.0

### Install

```bash
cd ToHunt
pip install -r requirements.txt
```

### Verify

```bash
python threat_hunter.py --help
python update_white.py --help
```

---

## 📂 Directory Structure

```
ToHunt/
├── threat_hunter.py            # Main pipeline script
├── update_white.py             # Whitelist updater (analyst feedback)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── Samples/                    # Sample CSV files for testing
│   ├── uc1.csv
│   ├── uc2.csv
│   ├── uc3.csv
│   ├── uc6.csv
│   └── uc19.csv
├── configs/
│   └── usecase_config.json     # Usecase definitions (dedup_fields only)
├── whitelists/                 # Whitelist CSV files (one per usecase)
│   ├── uc1.csv
│   ├── uc2.csv
│   ├── uc3.csv
│   ├── uc6.csv
│   └── uc19.csv
├── input_logs/                 # Drop incoming CSVs here
│   └── <usecase>.csv           #   File name = usecase name
├── processed_logs/             # Auto-created output tree
│   └── <YYYYMMDD>/
│       └── <HHMMSS>/
│           └── <original_filename>
└── archive_logs/               # Original files moved here after success
    └── <YYYYMMDD>/
        └── <HHMMSS>/
            └── <original_filename>
```

---

## ⚙️ Configuration Guide

[configs/usecase_config.json](configs/usecase_config.json) — mỗi usecase chỉ cần định nghĩa `dedup_fields`.

### JSON Schema

```json
{
  "<usecase_name>": {
    "dedup_fields": ["field_a", "field_b", "..."]
  }
}
```

| Key | Type | Description |
|---|---|---|
| `dedup_fields` | `string[]` | Các cột dùng để tính `Occurrence_Count`. Các dòng có cùng tổ hợp giá trị trong 5 ngày qua sẽ có count cao hơn. |

### Ví dụ

```json
{
  "uc1": {
    "dedup_fields": ["target_process_path", "hash_sha256"]
  },
  "uc6": {
    "dedup_fields": ["service_target_file_path"]
  },
  "uc19": {
    "dedup_fields": ["net_target_host_name", "source_process_path"]
  }
}
```

> `whitelist_rules` trong config cũ đã bị **bỏ qua hoàn toàn**. Whitelist giờ dùng file CSV riêng.

### Thêm usecase mới

1. Thêm key mới vào `configs/usecase_config.json` với `dedup_fields`.
2. (Tuỳ chọn) Tạo `whitelists/<usecase>.csv` — nếu chưa có, pipeline vẫn chạy bình thường (0 dòng bị whitelist).
3. Đặt CSV input vào `input_logs/<usecase>.csv`.
4. Chạy pipeline.

---

## 🛡 Whitelist System

Whitelist được định nghĩa bằng file CSV trong thư mục `whitelists/`. Mỗi usecase có một file riêng: `whitelists/<usecase>.csv`.

### Cấu trúc file whitelist

```csv
file_internalname,source_process_path
TrialVerifier.exe,
libxml2.dll,\\ManageEngine\\
,\\Philips Dynalite\\
```

### Cơ chế matching

| Phần tử | Ý nghĩa |
|---|---|
| **Cột** | Tên field trong log CSV. Phải khớp chính xác tên cột. |
| **Giá trị** | Regex pattern. Plain text = exact match. |
| **Ô trống** | Wildcard — bỏ qua field đó cho dòng này. |
| **Trong 1 dòng** | **AND** — tất cả field có giá trị phải khớp. |
| **Giữa các dòng** | **OR** — khớp bất kỳ dòng nào là bị loại khỏi log. |

### Ví dụ matching

Whitelist:
```csv
field_a,field_b
value1,
,pattern2
value3,pattern4
```

| Log row | field_a | field_b | Khớp? | Kết quả |
|---|---|---|---|---|
| A | `value1` | `xyz` | ✅ Dòng 1 (field_b trống → bỏ qua) | **Bị loại** |
| B | `abc` | `pattern2` | ✅ Dòng 2 (field_a trống → bỏ qua) | **Bị loại** |
| C | `value3` | `pattern4` | ✅ Dòng 3 (cả 2 field khớp) | **Bị loại** |
| D | `value1` | `pattern4` | ❌ Chỉ khớp field_a của dòng 1, nhưng không phải cùng 1 dòng | **Giữ lại** |
| E | `other` | `other` | ❌ Không khớp dòng nào | **Giữ lại** |

### Không có file whitelist

Nếu `whitelists/<usecase>.csv` không tồn tại hoặc rỗng → **pipeline vẫn chạy bình thường**, 0 dòng bị loại. Không crash.

---

## 🚀 Usage

### Pipeline chính

```bash
# Process tất cả usecase trong input_logs/
python threat_hunter.py

# Process 1 usecase cụ thể
python threat_hunter.py --usecase uc6

# Process từ file hoặc thư mục tuỳ chỉnh
python threat_hunter.py --input_path ./custom_logs/
python threat_hunter.py --input_path ./alerts.csv

# Gắn nhãn cho lần chạy
python threat_hunter.py --run_label ca1

# Dry-run (xem trước, không ghi file)
python threat_hunter.py --dry-run --verbose
```

### CLI Reference — `threat_hunter.py`

| Flag | Required | Default | Description |
|---|---|---|---|
| `--date` | No | Today | Execution date `YYYYMMDD`. |
| `--usecase` | No | All | Chỉ process usecase này. |
| `--input_path` | No | `input_logs/` | File CSV hoặc thư mục input. |
| `--config` | No | `configs/usecase_config.json` | Path tới config. |
| `--output_dir` | No | `processed_logs/` | Thư mục output gốc. |
| `--archive_dir` | No | `archive_logs/` | Thư mục archive gốc. |
| `--whitelist_dir` | No | `whitelists/` | Thư mục chứa whitelist CSV. |
| `--run_label` | No | (none) | Nhãn cho thư mục timestamp (vd: `ca1` → `145530_ca1`). |
| `--verbose` | No | `false` | DEBUG logging. |
| `--dry-run` | No | `false` | Mô phỏng, không ghi file. |

### Archiving

| Input Source | Archive? |
|---|---|
| Default `input_logs/` | ✅ Yes → `archive_logs/<YYYYMMDD>/<HHMMSS>/` |
| Custom `--input_path` | ❌ No — file gốc giữ nguyên |

---

## 🔄 Analyst Feedback Loop

### Luồng làm việc

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│ Pipeline │ ──→ │ Analyst mở   │ ──→ │ update_white │
│ xuất CSV │     │ CSV, điền "x"│     │ cập nhật     │
│ +is_benign│    │ vào is_benign│     │ whitelist    │
└──────────┘     └──────────────┘     └──────────────┘
                                             │
                                             ▼
                                      ┌──────────────┐
                                      │ Lần chạy sau │
                                      │ tự động bỏ   │
                                      │ qua dòng này │
                                      └──────────────┘
```

### Bước 1: Pipeline xuất CSV có cột `is_benign`

Mỗi dòng output có cột `is_benign` với giá trị rỗng:

| service_target_name | Occurrence_Count | is_benign |
|---|---|---|
| BrYNSvc | 0 | |
| suspicious_svc | 0 | |
| unknown_process | 3 | |

### Bước 2: Analyst đánh dấu dòng benign

Mở CSV trong Excel/text editor, điền `x` vào cột `is_benign`:

| service_target_name | Occurrence_Count | is_benign |
|---|---|---|
| BrYNSvc | 0 | **x** |
| suspicious_svc | 0 | |
| unknown_process | 3 | |

### Bước 3: Cập nhật whitelist

```bash
# Từ 1 thư mục run cụ thể
python update_white.py --log_dir processed_logs/20260616/140528/

# Từ thư mục ngày (quét tất cả run trong ngày)
python update_white.py --log_dir processed_logs/20260616/

# Dry-run
python update_white.py --log_dir processed_logs/20260616/140528/ --dry-run --verbose
```

Kết quả: giá trị `BrYNSvc` được thêm vào `whitelists/uc6.csv` (nếu chưa có).

### CLI Reference — `update_white.py`

| Flag | Required | Default | Description |
|---|---|---|---|
| `--log_dir` | ✅ Yes | — | Thư mục processed log (có thể là run dir hoặc date dir). |
| `--whitelist_dir` | No | `whitelists/` | Thư mục chứa whitelist CSV. |
| `--config` | No | `configs/usecase_config.json` | Path tới config (để biết column mặc định cho whitelist mới). |
| `--verbose` | No | `false` | DEBUG logging. |
| `--dry-run` | No | `false` | Mô phỏng, không ghi file. |

### Cơ chế của `update_white.py`

1. Quét tất cả CSV trong `--log_dir`.
2. Tìm dòng có `is_benign = "x"`.
3. Nhóm theo usecase (từ tên file).
4. Với mỗi usecase, đọc `whitelists/<usecase>.csv` để biết các cột cần extract.
5. Extract giá trị các cột đó từ dòng benign.
6. **Bỏ qua** dòng có tất cả field trống (tránh wildcard match-all).
7. Thêm vào whitelist nếu chưa tồn tại.
8. Nếu whitelist chưa có, tự tạo mới với columns = `dedup_fields` từ config.

---

## 🔬 Pipeline Walkthrough

### Step 1 — CSV Ingestion
```python
df = pd.read_csv(file_path, engine="c", low_memory=False)
```
- C engine parser. Auto-detect comma vs tab.

### Step 2 — Whitelist (CSV-based)
```python
wl_df = pd.read_csv("whitelists/<usecase>.csv")
for _, wl_row in wl_df.iterrows():           # iterate whitelist rows (<1000)
    row_mask = pd.Series(True, index=df.index)
    for field in wl_fields:                   # iterate fields
        if value is not empty:
            row_mask &= df[field].str.contains(value, regex=True)
    drop_mask |= row_mask                     # OR across whitelist rows
df = df[~drop_mask]
```
- Whitelist rows iterated (thường < 1000), nhưng log rows luôn vectorized.
- Giá trị rỗng = wildcard (bỏ qua).
- AND trong cùng 1 dòng, OR giữa các dòng.
- Không có file whitelist → 0 dòng bị loại.

### Step 3 — Add `is_benign`
```python
df["is_benign"] = ""
```
- Cột rỗng để analyst đánh dấu sau. Luôn có trong output.

### Step 4 — Historical Aggregation
```python
for day in find_5_days_with_data(date-1 ... date-30):
    for run_dir in processed_logs/<day>/*:
        for csv in run_dir/<usecase>*.csv:
            frames.append(pd.read_csv(csv)[dedup_fields])
historical = pd.concat(frames)
```
- Scan ngược tối đa 30 ngày, thu thập đủ 5 ngày có data.
- Bỏ qua ngày gap, **không tính ngày hiện tại**.
- Chỉ đọc `dedup_fields` (memory efficient).

### Step 5 — Frequency Counting
```python
counts = historical[dedup_fields].groupby(dedup_fields).size().reset_index(name="Occurrence_Count")
result = current.merge(counts, on=dedup_fields, how="left")
result["Occurrence_Count"] = result["Occurrence_Count"].fillna(0)
```
- **Chỉ đếm từ history**, không tính current.
- `0` = chưa từng thấy trong quá khứ → đáng ngờ.
- `> 0` = đã thấy N lần trong 5 ngày qua.

### Step 6 — Save & Archive
```python
df.to_csv("processed_logs/<YYYYMMDD>/<HHMMSS>/<file>.csv", index=False)
shutil.move(source, "archive_logs/<YYYYMMDD>/<HHMMSS>/<file>.csv")
```
- Mỗi lần chạy = 1 thư mục timestamp riêng → không ghi đè.
- Archive chỉ khi input là `input_logs/` mặc định.

---

## 📊 Sample Data

| File | Type | Key Fields |
|---|---|---|
| [uc1.csv](Samples/uc1.csv) | EDR/XDR process execution | `file_hash_md5`, `source_process_path`, `target_process_path` |
| [uc2.csv](Samples/uc2.csv) | EDR DLL loading | `file_hash_md5`, `file_path`, `source_process_path` |
| [uc3.csv](Samples/uc3.csv) | EDR process lineage | `source_process_path`, `target_commandline` |
| [uc6.csv](Samples/uc6.csv) | Service enumeration | `service_target_name`, `target_commandline` |
| [uc19.csv](Samples/uc19.csv) | Network DNS queries | `net_target_host_name`, `source_process_path` |

### Quick Test

```bash
# Test pipeline
python threat_hunter.py --input_path ./Samples/ --dry-run --verbose

# Test update_white (cần output thật trước)
python threat_hunter.py --input_path ./Samples/uc6.csv
# ... đánh dấu is_benign='x' trong CSV output ...
python update_white.py --log_dir processed_logs/<date>/<timestamp>/ --verbose
```

---

## 🛡 Edge Cases & Graceful Degradation

| Trường hợp | Hành vi |
|---|---|
| **Thiếu file whitelist** | Pipeline chạy bình thường, 0 dòng bị whitelist. Log INFO. |
| **File whitelist rỗng** | Pipeline chạy bình thường, 0 dòng bị whitelist. |
| **Thiếu config usecase** | File đó bị SKIP với WARNING. Các file khác vẫn chạy. |
| **Whitelist field không có trong log** | Field đó bị bỏ qua (WARNING). Các field khác vẫn được so sánh. |
| **dedup_fields không khớp column log** | Occurrence_Count = 0 cho tất cả dòng (ERROR log). |
| **Whitelist xoá 100% dòng** | Xuất CSV rỗng (chỉ có header + is_benign + Occurrence_Count). |
| **Không có historical data** | Occurrence_Count = 0 cho tất cả dòng. |
| **Ngày gap trong history** | Scan tiếp ngày xa hơn đến khi đủ 5 ngày có data hoặc hết 30 ngày. |
| **Regex không hợp lệ trong whitelist** | Tự động escape thành literal string (WARNING). |
| **Regex có capturing group `(...)`** | Vẫn hoạt động đúng (dùng `str.contains`). |

---

## ❓ FAQ

### Q: Tôi không có file whitelist — pipeline có chạy được không?
**Có.** Pipeline chạy bình thường, 0 dòng bị loại bởi whitelist. Tạo file `whitelists/<usecase>.csv` sau nếu cần.

### Q: Làm sao để thêm entry vào whitelist?
Có 2 cách:
1. **Tự động**: Đánh dấu `is_benign="x"` trong CSV output → chạy `update_white.py`.
2. **Thủ công**: Mở `whitelists/<usecase>.csv` và thêm dòng mới.

### Q: Whitelist có phân biệt exact match và regex không?
Mọi giá trị trong whitelist đều được coi là regex. `TrialVerifier.exe` là regex khớp chính xác `TrialVerifier.exe`. `Brother.*` khớp mọi chuỗi bắt đầu bằng `Brother`.

### Q: Làm sao để whitelist 1 dòng mà không cần regex?
Cứ ghi giá trị chính xác vào. Plain text = exact match trong regex. Không cần escape.

### Q: update_white.py lấy những cột nào từ log để thêm vào whitelist?
Các cột được định nghĩa sẵn trong `whitelists/<usecase>.csv`. Nếu file whitelist chưa tồn tại, script sẽ dùng `dedup_fields` từ config.

### Q: Occurrence_Count = 0 nghĩa là gì?
Chưa từng thấy tổ hợp `dedup_fields` này trong 5 ngày qua → có thể là anomaly, cần analyst xem xét.

---

## 📄 License

Internal SOC tooling. All rights reserved.
