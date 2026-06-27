# 🔍 Threat Hunter — Automated SOC Log Processing Pipeline

**High-performance ETL pipeline for Security Operations Center (SOC) threat hunting logs.**

Auto-loads logs from timestamp-named directories (`D:\Log\final\<YYYYMMDD_HHMMSS>\`), filters via CSV-based whitelist, enriches with historical frequency analysis, and archives output with an analyst feedback loop. Designed to handle **100,000+ rows in seconds** via pure Pandas vectorization.

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
- [Edge Cases & Graceful Degradation](#-edge-cases--graceful-degradation)
- [FAQ](#-faq)

---

## 🏗 Architecture

```
┌─────────────────────────────────┐
│  D:\Log\final\                  │  ← Tool trước tạo ra
│  ├── 20260627_142209\           │     timestamp-named dirs
│  │   ├── output_vrtt\           │     YYYYMMDD_HHMMSS
│  │   │   └── output_final       │
│  │   │       _uc01_xxx.csv      │
│  │   ├── uc03\                  │
│  │   ├── uc06\                  │
│  │   └── output_domain\         │
│  └── 20260627_203015\           │
│      └── ...                    │
└──────────────┬──────────────────┘
               │
               │  auto-detect closest hoặc manual --timestamp_dir
               │  20260627_142209 → parent=20260627, child=142209
               │
┌──────────────▼──────────────────────────────────┐
│              threat_hunter.py                    │
│                                                  │
│  1. Resolve input: base_dir/<ts>/<pattern>       │
│  2. Read CSV (C engine, auto delimiter)         │
│  3. Whitelist via whitelists/<usecase>.csv      │
│  4. Add is_benign column                        │
│  5. Load 5-day history (past days only)         │
│  6. GroupBy → Occurrence_Count (history only)   │
│  7. Save + Archive (copy output, input untouched)│
└──────┬──────────┬───────────┘
       │          │
┌──────▼──┐  ┌───▼───────────┐
│processed│  │ archive_logs/ │   Cả 2 đều là bản sao
│_logs/   │  │ <parent>/     │   của output. Input
│<parent>/│  │ <child>/      │   không bị đụng vào.
│<child>/ │  └───────────────┘
└──────┬──┘
       │
       │  analyst mở CSV, điền "x" vào cột is_benign
       │
┌──────▼──────┐
│update_white │   Thêm dòng đã mark vào
│    .py      │   whitelists/<usecase>.csv
└─────────────┘
```

### Cách tên thư mục output được tạo

```
Input dir:  D:\Log\final\20260627_142209\
            ───┬─── ──┬──
               │      └── child  = HHMMSS  (142209)
               └── parent = YYYYMMDD (20260627)

Output:  processed_logs/20260627/142209/filename.csv
Archive: archive_logs/20260627/142209/filename.csv
```

---

## 📋 Prerequisites & Installation

- **Python** 3.8+
- **pandas** ≥ 1.5.0

```bash
cd ToHunt
pip install -r requirements.txt
```

Verify:
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
├── requirements.txt
├── configs/
│   └── usecase_config.json     # dedup_fields + input_pattern per usecase
├── whitelists/                 # Whitelist CSV files (one per usecase)
│   ├── uc1.csv
│   ├── uc2.csv
│   ├── uc3.csv
│   ├── uc6.csv
│   └── uc19.csv
├── processed_logs/             # Output (auto-created)
│   └── <YYYYMMDD>/             #   parent = YYYYMMDD từ tên dir input
│       └── <HHMMSS>/           #   child  = HHMMSS từ tên dir input
│           └── <filename>
├── archive_logs/               # Bản sao output (auto-created)
│   └── <YYYYMMDD>/             #   Cấu trúc giống processed_logs
│       └── <HHMMSS>/
│           └── <filename>
└── Samples/                    # Sample data for testing

D:\Log\final\                   # INPUT — tool trước tạo ra (KHÔNG BAO GIỜ bị sửa)
├── 20260627_142209\
│   ├── output_vrtt\
│   ├── uc03\
│   ├── uc06\
│   └── output_domain\
└── 20260627_203015\
    └── ...
```

---

## ⚙️ Configuration Guide

[configs/usecase_config.json](configs/usecase_config.json) — mỗi usecase cần 2 trường:

### JSON Schema

```json
{
  "<usecase_name>": {
    "dedup_fields": ["field_a", "field_b", "..."],
    "input_pattern": "<glob_pattern_relative_to_timestamp_dir>"
  }
}
```

| Key | Type | Description |
|---|---|---|
| `dedup_fields` | `string[]` | Các cột dùng để tính `Occurrence_Count`. |
| `input_pattern` | `string` | Glob pattern để tìm file CSV trong thư mục timestamp. Hỗ trợ `*` wildcard. |

### Ví dụ

```json
{
  "uc1": {
    "dedup_fields": ["target_process_path", "hash_sha256"],
    "input_pattern": "output_vrtt/output_final_uc01*.csv"
  },
  "uc6": {
    "dedup_fields": ["service_target_file_path"],
    "input_pattern": "uc06/final_uc06_merged*.csv"
  },
  "uc19": {
    "dedup_fields": ["net_target_host_name", "source_process_path"],
    "input_pattern": "output_domain/output_uc19*.csv"
  }
}
```

Với config trên, khi chạy với `--timestamp_dir 20260627_142209`:
- `uc1` → `D:\Log\final\20260627_142209\output_vrtt\output_final_uc01*.csv`
- `uc6` → `D:\Log\final\20260627_142209\uc06\final_uc06_merged*.csv`
- `uc19` → `D:\Log\final\20260627_142209\output_domain\output_uc19*.csv`

---

## 🛡 Whitelist System

Whitelist dùng file CSV trong `whitelists/<usecase>.csv`.

### Cấu trúc

```csv
field_a,field_b
value1,
,pattern2
value3,pattern4
```

| Quy tắc | Mô tả |
|---|---|
| **Cột** | Tên field trong log CSV. |
| **Giá trị** | Regex pattern. Plain text = exact match. |
| **Ô trống** | Wildcard — bỏ qua field đó cho dòng này. |
| **AND** trong 1 dòng | Tất cả field có giá trị phải khớp. |
| **OR** giữa các dòng | Khớp bất kỳ dòng nào → bị loại. |
| **Thiếu file** | Pipeline chạy bình thường, 0 dòng bị loại. |

---

## 🚀 Usage

### 3 chế độ input

```bash
# ── Chế độ 1: Auto-detect (mặc định) ──
# Tự chọn thư mục timestamp gần thời điểm hiện tại nhất
python threat_hunter.py

# ── Chế độ 2: Manual timestamp dir(s) ──
# Chỉ định 1 hoặc nhiều thư mục
python threat_hunter.py --timestamp_dir 20260627_142209
python threat_hunter.py --timestamp_dir 20260627_142209 --timestamp_dir 20260627_203015

# ── Chế độ 3: Legacy --input_path (test nhanh) ──
python threat_hunter.py --input_path ./Samples/uc6.csv
python threat_hunter.py --input_path ./Samples/
```

### Tuỳ chọn khác

```bash
# Lọc usecase cụ thể
python threat_hunter.py --usecase uc6

# Đổi base directory
python threat_hunter.py --base_dir E:\OtherLogs\

# Gắn nhãn run (vd: phân biệt ca)
python threat_hunter.py --run_label ca1
# Input dir 20260627_142209 → output: processed_logs/20260627/142209_ca1/

# Dry-run + verbose
python threat_hunter.py --dry-run --verbose
```

### Cách output được đặt tên

| Input dir | `--run_label` | Output path |
|---|---|---|
| `20260627_142209` | — | `processed_logs/20260627/142209/` |
| `20260627_142209` | `ca1` | `processed_logs/20260627/142209_ca1/` |
| `20260627_203015` | — | `processed_logs/20260627/203015/` |
| *(legacy mode)* | — | `processed_logs/20260627/172711/` (HHMMSS hiện tại) |

### CLI Reference — `threat_hunter.py`

| Flag | Required | Default | Description |
|---|---|---|---|
| `--base_dir` | No | `D:\Log\final\` | Thư mục gốc chứa timestamp subdirectories. |
| `--timestamp_dir` | No | (auto) | Tên thư mục timestamp. Dùng nhiều lần để chọn nhiều dir. |
| `--usecase` | No | All | Chỉ process usecase này. |
| `--input_path` | No | — | **Legacy**: đường dẫn trực tiếp đến CSV. |
| `--config` | No | `configs/usecase_config.json` | Path tới config. |
| `--output_dir` | No | `processed_logs/` | Thư mục output gốc. |
| `--archive_dir` | No | `archive_logs/` | Thư mục archive gốc (bản sao output). |
| `--whitelist_dir` | No | `whitelists/` | Thư mục chứa whitelist CSV. |
| `--date` | No | Today | Ngày tham chiếu cho historical lookback `YYYYMMDD`. |
| `--run_label` | No | (none) | Nhãn gắn vào child dir (vd: `ca1` → `142209_ca1`). |
| `--verbose` | No | `false` | DEBUG logging. |
| `--dry-run` | No | `false` | Mô phỏng, không ghi file. |

### Lưu ý

- **Input không bị đụng vào**: File trong `D:\Log\final\` không bao giờ bị move hay xoá.
- **Archive là bản sao output**: `archive_logs/` lưu bản sao của kết quả đã xử lý.
- **Parent/Child từ tên dir input**: `20260627_142209` → parent=`20260627`, child=`142209`. Không dùng ngày giờ hiện tại.

---

## 🔄 Analyst Feedback Loop

### 1. Pipeline xuất CSV có cột `is_benign`

| service_target_name | Occurrence_Count | is_benign |
|---|---|---|
| BrYNSvc | 0 | |
| suspicious_svc | 0 | |

### 2. Analyst đánh dấu dòng benign

Điền `x` vào cột `is_benign`:

| service_target_name | Occurrence_Count | is_benign |
|---|---|---|
| BrYNSvc | 0 | **x** |
| suspicious_svc | 0 | |

### 3. Cập nhật whitelist

```bash
# Từ 1 thư mục run cụ thể
python update_white.py --log_dir processed_logs/20260627/142209/

# Từ thư mục ngày (quét tất cả run trong ngày)
python update_white.py --log_dir processed_logs/20260627/

# Dry-run
python update_white.py --log_dir processed_logs/20260627/ --dry-run --verbose
```

### CLI Reference — `update_white.py`

| Flag | Required | Default | Description |
|---|---|---|---|
| `--log_dir` | ✅ Yes | — | Thư mục processed log (run dir hoặc date dir). |
| `--whitelist_dir` | No | `whitelists/` | Thư mục chứa whitelist CSV. |
| `--config` | No | `configs/usecase_config.json` | Config (để biết column mặc định cho whitelist mới). |
| `--verbose` | No | `false` | DEBUG logging. |
| `--dry-run` | No | `false` | Mô phỏng, không ghi file. |

---

## 🔬 Pipeline Walkthrough

### Step 1 — Input Resolution
```
Auto:      quét D:\Log\final\ → chọn <YYYYMMDD_HHMMSS> gần nhất
Manual:    dùng --timestamp_dir được chỉ định
Parse:     20260627_142209 → parent=20260627, child=142209
Pattern:   config[usecase].input_pattern → glob trong timestamp dir
→          D:\Log\final\<ts>\<pattern>
```

### Step 2 — CSV Ingestion
```python
df = pd.read_csv(file_path, engine="c", low_memory=False)
```
C engine, auto-detect comma vs tab.

### Step 3 — Whitelist
- So sánh từng dòng log với `whitelists/<usecase>.csv`.
- AND trong 1 dòng whitelist, OR giữa các dòng.
- Ô trống = wildcard.

### Step 4 — `is_benign` column
```python
df["is_benign"] = ""
```

### Step 5 — Historical Aggregation
- Scan ngược tối đa 30 ngày, thu thập đủ 5 ngày có data.
- **Không tính ngày hiện tại.**
- Chỉ đọc `dedup_fields`.

### Step 6 — Occurrence Counting
```python
counts = historical.groupby(dedup_fields).size().reset_index(name="Occurrence_Count")
result = current.merge(counts, on=dedup_fields, how="left")
result["Occurrence_Count"] = result["Occurrence_Count"].fillna(0)
```
- `0` = chưa từng thấy → đáng ngờ.
- `> 0` = đã thấy N lần trong lịch sử.

### Step 7 — Save & Archive
```
processed_logs/<parent>/<child>/<filename>
archive_logs/<parent>/<child>/<filename>     ← bản sao output
```
- `parent` = YYYYMMDD từ tên thư mục input
- `child` = HHMMSS từ tên thư mục input
- Input gốc trong `D:\Log\final\` không bị động vào

---

## 🛡 Edge Cases & Graceful Degradation

| Trường hợp | Hành vi |
|---|---|
| **Không có timestamp dir nào** | Auto-detect báo lỗi. Manual mode báo WARNING và bỏ qua. |
| **Pattern không khớp file nào** | WARNING — usecase đó bị bỏ qua. |
| **Thiếu `input_pattern` trong config** | Lỗi khi load config. |
| **Thiếu file whitelist** | 0 dòng bị loại, pipeline chạy bình thường. |
| **Whitelist file rỗng (chỉ có header)** | 0 dòng bị loại. |
| **dedup_fields không khớp column** | Occurrence_Count = 0. |
| **Whitelist xoá 100% dòng** | CSV rỗng (chỉ header + is_benign + Occurrence_Count). |
| **Không có historical data** | Occurrence_Count = 0 cho tất cả dòng. |
| **Ngày gap trong history** | Scan tiếp đến khi đủ 5 ngày hoặc hết 30 ngày. |
| **Regex không hợp lệ trong whitelist** | Tự escape thành literal. |
| **Tên dir input không đúng format** | Dùng nguyên tên làm child, current date làm parent. |

---

## ❓ FAQ

### Q: Làm sao để thêm usecase mới?
1. Thêm key vào `configs/usecase_config.json` với `dedup_fields` và `input_pattern`.
2. (Tuỳ chọn) Tạo `whitelists/<usecase>.csv`.
3. Chạy pipeline.

### Q: Tôi muốn chạy nhiều thư mục timestamp cùng lúc?
```bash
python threat_hunter.py --timestamp_dir 20260627_142209 --timestamp_dir 20260627_203015
```

### Q: Tên thư mục output được đặt như thế nào?
Từ tên thư mục input `YYYYMMDD_HHMMSS`:
- **parent** = `YYYYMMDD` (vd: `20260627`)
- **child** = `HHMMSS` (vd: `142209`)
- Output: `processed_logs/20260627/142209/`

Không dùng ngày giờ hiện tại lúc chạy script.

### Q: File trong `D:\Log\final\` có bị move hay xoá không?
**Không.** Input được đọc và giữ nguyên. Archive là bản sao của output.

### Q: File whitelist bị xoá hết nội dung thì sao?
Pipeline vẫn chạy — 0 dòng bị whitelist. Không crash.

### Q: Occurrence_Count = 0 nghĩa là gì?
Chưa từng thấy tổ hợp `dedup_fields` này trong 5 ngày qua → có thể là anomaly.

### Q: Tôi muốn test nhanh với 1 file CSV?
```bash
python threat_hunter.py --input_path ./Samples/uc6.csv --dry-run --verbose
```
