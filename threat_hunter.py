#!/usr/bin/env python3
"""
Threat Hunter — Automated Log Processing Pipeline
==================================================
High-performance ETL pipeline for SOC threat hunting logs.

Input: auto-loaded from D:\\Log\\final\\<YYYYMMDD_HHMMSS>\\ (configurable).
Two modes:
  - Default: auto-select timestamp dir closest to current time.
  - Manual:  pass one or more --timestamp_dir values.

Each usecase defines an ``input_pattern`` in config that maps to the
correct sub-path within the timestamp directory.

Processing:
  1. CSV-based whitelist filtering (whitelists/<usecase>.csv)
  2. Historical data aggregation (past 5 days, same usecase)
  3. Frequency counting on deduplication fields
  4. Structured output with archival + is_benign flag

Designed to handle 100k+ rows in seconds via pure Pandas vectorization.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("threat_hunter")


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BASE_DIR: str = r"D:\Log\final"
DEFAULT_OUTPUT_DIR: str = "processed_logs"
DEFAULT_ARCHIVE_DIR: str = "archive_logs"
DEFAULT_CONFIG_PATH: str = os.path.join("configs", "usecase_config.json")
DEFAULT_WHITELIST_DIR: str = "whitelists"
HISTORICAL_LOOKBACK_DAYS: int = 5
TS_DIR_PATTERN = re.compile(r"^(\d{8})_(\d{6})$")  # YYYYMMDD_HHMMSS


def parse_ts_dir_name(dirname: str) -> Tuple[str, str]:
    """Parse 'YYYYMMDD_HHMMSS' → (date_YYYYMMDD, time_HHMMSS).

    Returns the original string unchanged if it doesn't match the pattern
    (for legacy or custom dir names).
    """
    m = TS_DIR_PATTERN.match(dirname)
    if m:
        return m.group(1), m.group(2)
    # Not a standard timestamp dir — use as-is for child, current date for parent
    return datetime.now().strftime("%Y%m%d"), dirname


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Threat Hunter — automated log processing pipeline for SOC logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: auto-select closest timestamp dir from D:\\Log\\final\\
  python threat_hunter.py

  # Process specific usecase(s) only
  python threat_hunter.py --usecase uc6

  # Manual: one timestamp directory
  python threat_hunter.py --timestamp_dir 20260627_142209

  # Manual: multiple timestamp directories
  python threat_hunter.py --timestamp_dir 20260627_142209 --timestamp_dir 20260627_203015

  # Custom base directory
  python threat_hunter.py --base_dir E:\\OtherLogs\\

  # Legacy: direct CSV input (bypasses timestamp-dir logic)
  python threat_hunter.py --input_path ./Samples/uc6.csv

  # Dry-run with label
  python threat_hunter.py --run_label ca1 --dry-run --verbose
        """,
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Execution date in YYYYMMDD format. Defaults to current system date.",
    )
    parser.add_argument(
        "--usecase",
        default=None,
        help="Process only this usecase. If omitted, ALL usecases defined in config are processed.",
    )
    parser.add_argument(
        "--base_dir",
        default=DEFAULT_BASE_DIR,
        help="Base directory containing timestamp-named subdirectories. "
             "Defaults to '%s'." % DEFAULT_BASE_DIR,
    )
    parser.add_argument(
        "--timestamp_dir",
        action="append",
        default=None,
        help="One or more timestamp directory names (e.g. '20260627_142209'). "
             "Can be specified multiple times. If omitted, the closest directory "
             "to the current time is auto-selected.",
    )
    parser.add_argument(
        "--input_path",
        default=None,
        help="Legacy: direct path to a CSV file or directory. When specified, "
             "timestamp-dir logic is bypassed entirely.",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to usecase configuration JSON. Defaults to '%s'." % DEFAULT_CONFIG_PATH,
    )
    parser.add_argument(
        "--output_dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Root output directory. Defaults to '%s'." % DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--archive_dir",
        default=DEFAULT_ARCHIVE_DIR,
        help="Root archive directory. Defaults to '%s'." % DEFAULT_ARCHIVE_DIR,
    )
    parser.add_argument(
        "--whitelist_dir",
        default=DEFAULT_WHITELIST_DIR,
        help="Directory containing whitelist CSV files. Defaults to '%s/'." % DEFAULT_WHITELIST_DIR,
    )
    parser.add_argument(
        "--run_label",
        default=None,
        help="Optional label appended to the run timestamp folder "
             "(e.g. 'ca1' produces folder '145530_ca1').",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be done without writing/archiving files.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------
def load_config(config_path: str) -> Dict[str, Any]:
    """Load and validate the usecase configuration JSON.

    Each usecase must define ``dedup_fields`` (list) and ``input_pattern`` (str).
    ``input_pattern`` is a glob relative to the timestamp directory.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError("Configuration file not found: %s" % config_path)

    with open(config_path, "r", encoding="utf-8") as fh:
        config: Dict[str, Any] = json.load(fh)

    for usecase, cfg in config.items():
        if "dedup_fields" not in cfg:
            raise ValueError("Usecase '%s' is missing required key 'dedup_fields'." % usecase)
        if not isinstance(cfg["dedup_fields"], list) or len(cfg["dedup_fields"]) == 0:
            raise ValueError("'dedup_fields' for '%s' must be a non-empty list." % usecase)
        if "input_pattern" not in cfg:
            raise ValueError("Usecase '%s' is missing required key 'input_pattern'." % usecase)

    logger.info("Loaded configuration for %d usecase(s): %s", len(config), ", ".join(config.keys()))
    return config


# ---------------------------------------------------------------------------
# CSV-based Whitelist
# ---------------------------------------------------------------------------
def _load_whitelist_csv(usecase_name: str, whitelist_dir: str) -> Optional[pd.DataFrame]:
    """Load the whitelist CSV for *usecase_name* if it exists."""
    wl_path = Path(whitelist_dir) / ("%s.csv" % usecase_name)
    if not wl_path.is_file():
        logger.debug("No whitelist file for usecase '%s' (%s).", usecase_name, wl_path)
        return None

    wl_df = read_csv_robust(wl_path)
    if wl_df.empty:
        logger.debug("Whitelist file for '%s' is empty.", usecase_name)
        return None

    logger.info("Loaded whitelist for '%s': %d entries × %d fields (%s).",
                 usecase_name, len(wl_df), len(wl_df.columns), wl_path)
    return wl_df


def apply_whitelist(
    df: pd.DataFrame,
    usecase_name: str,
    whitelist_dir: str,
) -> pd.DataFrame:
    """Apply whitelist CSV to the log DataFrame.

    Whitelist values are regex patterns.  Empty cells = wildcard (skip).
    AND within a row, OR across rows.
    """
    if df.empty:
        return df

    wl_df = _load_whitelist_csv(usecase_name, whitelist_dir)
    if wl_df is None:
        logger.info("No whitelist for '%s' — 0 rows dropped.", usecase_name)
        return df

    initial_count = len(df)
    wl_fields = list(wl_df.columns)
    drop_mask = pd.Series(False, index=df.index)

    missing_fields = [f for f in wl_fields if f not in df.columns]
    if missing_fields:
        logger.warning("Whitelist field(s) %s not found in log columns. Ignored.", missing_fields)

    for _, wl_row in wl_df.iterrows():
        row_mask = pd.Series(True, index=df.index)
        for field in wl_fields:
            if field in missing_fields:
                continue
            raw_val = wl_row[field]
            if pd.isna(raw_val) or str(raw_val).strip() == "":
                continue
            pattern = str(raw_val)
            try:
                field_mask = df[field].astype(str).str.contains(pattern, regex=True, na=False)
            except re.error as exc:
                logger.warning("Invalid regex in whitelist '%s', field '%s': '%s' — %s. "
                               "Treating as literal.", usecase_name, field, pattern, exc)
                field_mask = df[field].astype(str).str.contains(
                    re.escape(pattern), regex=True, na=False)
            row_mask = row_mask & field_mask
        drop_mask = drop_mask | row_mask

    result = df[~drop_mask].copy()
    dropped = initial_count - len(result)
    if dropped > 0:
        logger.info("Whitelist dropped %d / %d rows (%.1f%%).", dropped, initial_count,
                     100 * dropped / initial_count)
    else:
        logger.info("Whitelist applied — 0 rows dropped.")
    return result


# ---------------------------------------------------------------------------
# CSV reading helper
# ---------------------------------------------------------------------------
def read_csv_robust(file_path: Path) -> pd.DataFrame:
    """Read a CSV/TSV file, auto-detecting delimiter."""
    path_str = str(file_path)
    try:
        df = pd.read_csv(path_str, engine="c", low_memory=False, encoding="utf-8")
        if df.shape[1] >= 2:
            return df
    except Exception:
        pass
    try:
        df = pd.read_csv(path_str, sep="\t", engine="c", low_memory=False, encoding="utf-8")
        return df
    except Exception as exc:
        raise ValueError("Failed to read CSV/TSV '%s': %s" % (file_path.name, exc)) from exc


# ---------------------------------------------------------------------------
# Timestamp-directory input resolution
# ---------------------------------------------------------------------------
def _list_timestamp_dirs(base_dir: str) -> List[Tuple[str, Path]]:
    """List valid timestamp directories (YYYYMMDD_HHMMSS) in *base_dir*.

    Returns:
        List of ``(dirname, full_path)`` sorted newest-first.
    """
    base = Path(base_dir)
    if not base.is_dir():
        return []

    result: List[Tuple[str, Path]] = []
    for d in base.iterdir():
        if d.is_dir() and TS_DIR_PATTERN.fullmatch(d.name):
            result.append((d.name, d))
    result.sort(key=lambda x: x[0], reverse=True)  # newest first
    return result


def _parse_timestamp(dirname: str) -> datetime:
    """Parse 'YYYYMMDD_HHMMSS' → datetime."""
    return datetime.strptime(dirname, "%Y%m%d_%H%M%S")


def _find_closest_timestamp_dir(base_dir: str) -> Optional[str]:
    """Find the timestamp directory closest to (but not after) the current time.

    Returns the directory name (e.g. '20260627_142209'), or None if no valid
    directories exist.
    """
    dirs = _list_timestamp_dirs(base_dir)
    if not dirs:
        return None

    now = datetime.now()

    # Prefer the most recent directory that is ≤ now
    best: Optional[str] = None
    best_dt: Optional[datetime] = None
    best_diff: float = float("inf")

    for name, _ in dirs:
        try:
            dt = _parse_timestamp(name)
        except ValueError:
            continue
        diff = abs((now - dt).total_seconds())
        if diff < best_diff:
            best_diff = diff
            best = name
            best_dt = dt

    if best is not None and best_dt is not None:
        logger.info("Auto-selected timestamp dir: %s  (Δ = %.0f min from now)", best,
                     best_diff / 60)
    return best


def resolve_input_from_timestamp_dirs(
    timestamp_dirs: List[str],
    config: Dict[str, Any],
    base_dir: str,
    usecase_filter: Optional[str] = None,
) -> List[Tuple[str, str, Path, str]]:
    """Resolve input files from timestamp-named directories using config patterns.

    Returns:
        List of ``(usecase_name, original_filename, full_path, ts_dir_name)`` tuples.
    """
    results: List[Tuple[str, str, Path, str]] = []

    for ts_dir_name in timestamp_dirs:
        ts_path = Path(base_dir) / ts_dir_name
        if not ts_path.is_dir():
            logger.warning("Timestamp directory not found: %s — skipping.", ts_path)
            continue

        usecases = [usecase_filter] if usecase_filter else list(config.keys())

        for usecase in usecases:
            if usecase not in config:
                continue
            pattern = config[usecase].get("input_pattern")
            if not pattern:
                logger.debug("No input_pattern for usecase '%s' — skipping.", usecase)
                continue

            glob_path = ts_path / pattern
            matches = sorted(ts_path.glob(pattern))
            if not matches:
                logger.warning("No files matched for '%s' in %s: %s",
                               usecase, ts_dir_name, pattern)
                continue

            for fp in matches:
                results.append((usecase, fp.name, fp, ts_dir_name))

    logger.info("Resolved %d input file(s) across %d timestamp dir(s).",
                 len(results), len(timestamp_dirs))
    return results


# ---------------------------------------------------------------------------
# Legacy input resolution (for --input_path)
# ---------------------------------------------------------------------------
def extract_usecase_from_filename(filename: str) -> str:
    """Extract the usecase name from a filename (stem without extension)."""
    return Path(filename).stem


def resolve_input_files_legacy(
    input_path: str,
    usecase_filter: Optional[str],
) -> List[Tuple[str, str, Path]]:
    """Legacy: discover and resolve input CSV files from a file or directory."""
    ip = Path(input_path)

    if ip.is_file():
        if ip.suffix.lower() not in (".csv", ".tsv", ".txt"):
            raise ValueError("Input file must be a CSV/TSV: %s" % ip)
        usecase = extract_usecase_from_filename(ip.name)
        if usecase_filter and usecase != usecase_filter:
            logger.warning("File '%s' (usecase='%s') does not match --usecase='%s'. Skipping.",
                           ip.name, usecase, usecase_filter)
            return []
        logger.info("Legacy single-file mode: %s  (usecase: %s)", ip.name, usecase)
        return [(usecase, ip.name, ip)]

    if not ip.is_dir():
        raise FileNotFoundError("Input path not found: %s" % input_path)

    csv_files = sorted(ip.glob("*.csv")) + sorted(ip.glob("*.tsv"))
    if not csv_files:
        logger.warning("No CSV/TSV files found in %s", input_path)
        return []

    results: List[Tuple[str, str, Path]] = []
    for fp in csv_files:
        usecase = extract_usecase_from_filename(fp.name)
        if usecase_filter and usecase != usecase_filter:
            continue
        results.append((usecase, fp.name, fp))

    logger.info("Legacy mode: resolved %d input file(s).", len(results))
    return results


# ---------------------------------------------------------------------------
# Historical data aggregation
# ---------------------------------------------------------------------------
def _find_historical_dates(
    date_str: str,
    processed_dir: str,
    usecase_name: str,
    target_days: int = HISTORICAL_LOOKBACK_DAYS,
    max_scan: int = 30,
) -> List[str]:
    """Find up to *target_days* past dates that contain data for *usecase_name*."""
    ref_date = datetime.strptime(date_str, "%Y%m%d")
    found: List[str] = []

    for offset in range(1, max_scan + 1):
        d = ref_date - timedelta(days=offset)
        day_str = d.strftime("%Y%m%d")
        day_dir = Path(processed_dir) / day_str
        if not day_dir.is_dir():
            continue
        has_data = False
        for run_dir in day_dir.iterdir():
            if not run_dir.is_dir():
                continue
            if list(run_dir.glob("%s*.csv" % usecase_name)):
                has_data = True
                break
        if has_data:
            found.append(day_str)
            if len(found) >= target_days:
                break
    return found


def load_historical_data(
    usecase_name: str,
    dedup_fields: List[str],
    date_str: str,
    processed_dir: str = DEFAULT_OUTPUT_DIR,
    target_days: int = HISTORICAL_LOOKBACK_DAYS,
    max_scan: int = 30,
) -> pd.DataFrame:
    """Load processed logs from past days for the same usecase (excluding today)."""
    if not dedup_fields:
        return pd.DataFrame()

    dates = _find_historical_dates(date_str, processed_dir, usecase_name, target_days, max_scan)

    if not dates:
        logger.info("No historical data found for usecase '%s' (scanned %d days back).",
                     usecase_name, max_scan)
        return pd.DataFrame(columns=dedup_fields)

    logger.info("Historical scan: found %d day(s) with data for '%s' (target: %d). Dates: %s",
                 len(dates), usecase_name, target_days, ", ".join(dates))

    frames: List[pd.DataFrame] = []
    for day in dates:
        day_dir = Path(processed_dir) / day
        for run_dir in day_dir.iterdir():
            if not run_dir.is_dir():
                continue
            for csv_file in run_dir.glob("%s*.csv" % usecase_name):
                try:
                    df = read_csv_robust(csv_file)
                    if df.empty:
                        continue
                    available = [c for c in dedup_fields if c in df.columns]
                    if available:
                        frames.append(df[available].copy())
                except Exception as exc:
                    logger.warning("Failed to read historical file '%s': %s", csv_file, exc)

    if not frames:
        return pd.DataFrame(columns=dedup_fields)

    combined = pd.concat(frames, ignore_index=True, copy=False)
    logger.info("Loaded %d historical row(s) for usecase '%s' from %d day(s).",
                 len(combined), usecase_name, len(dates))
    return combined


# ---------------------------------------------------------------------------
# Occurrence counting (dedup + frequency)
# ---------------------------------------------------------------------------
def compute_occurrence_counts(
    current_df: pd.DataFrame,
    historical_df: pd.DataFrame,
    dedup_fields: List[str],
) -> pd.DataFrame:
    """Compute per-row occurrence counts from HISTORICAL data only (today excluded)."""
    if current_df.empty:
        logger.info("Current DataFrame is empty — assigning empty Occurrence_Count column.")
        current_df["Occurrence_Count"] = pd.Series([], dtype="int64")
        return current_df

    missing = [f for f in dedup_fields if f not in current_df.columns]
    if missing:
        logger.error("Dedup field(s) %s not found in current DataFrame columns: %s. "
                      "Occurrence_Count will be set to 0 for all rows.",
                      missing, list(current_df.columns))
        current_df["Occurrence_Count"] = 0
        return current_df

    if historical_df.empty:
        logger.info("No historical data — all %d row(s) have Occurrence_Count = 0.", len(current_df))
        current_df["Occurrence_Count"] = 0
        return current_df

    hist_cols = [c for c in dedup_fields if c in historical_df.columns]
    if not hist_cols:
        logger.warning("Historical data has none of the dedup fields. All Occurrence_Count = 0.")
        current_df["Occurrence_Count"] = 0
        return current_df

    counts = (
        historical_df[hist_cols]
        .groupby(hist_cols, dropna=False)
        .size()
        .reset_index(name="Occurrence_Count")
    )

    result = current_df.merge(counts, on=hist_cols, how="left")
    result["Occurrence_Count"] = result["Occurrence_Count"].fillna(0).astype(int)

    occ = result["Occurrence_Count"]
    unseen = (occ == 0).sum()
    logger.info("Occurrence_Count (history only): mean=%.2f, median=%s, max=%s, unseen=%d/%d (%.1f%%).",
                 occ.mean(),
                 str(int(occ.median())) if not occ.empty and not pd.isna(occ.median()) else "N/A",
                 str(int(occ.max())) if not occ.empty and not pd.isna(occ.max()) else "N/A",
                 unseen, len(result), 100 * unseen / len(result) if len(result) > 0 else 0)
    return result


# ---------------------------------------------------------------------------
# Run timestamp
# ---------------------------------------------------------------------------
def generate_run_timestamp(run_label: Optional[str] = None) -> str:
    base = datetime.now().strftime("%H%M%S")
    if run_label:
        base = "%s_%s" % (base, run_label)
    return base


def make_run_timestamp_unique(
    ts: str, date_str: str, output_dir: str, archive_dir: str,
) -> str:
    candidate = ts
    counter = 2
    while True:
        if not (Path(output_dir) / date_str / candidate).exists() and \
           not (Path(archive_dir) / date_str / candidate).exists():
            return candidate
        candidate = "%s_%d" % (ts, counter)
        counter += 1


# ---------------------------------------------------------------------------
# Save & Archive
# ---------------------------------------------------------------------------
def save_and_archive(
    df: pd.DataFrame,
    output_path: Path,
    archive_path: Optional[Path] = None,
    dry_run: bool = False,
) -> None:
    """Save processed DataFrame to output, and optionally a copy to archive.

    Input files are NEVER touched — archive is a copy of the output.
    """
    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    if dry_run:
        logger.info("[DRY-RUN] Would save %d row(s) → %s", len(df), output_path)
    else:
        df.to_csv(output_path, index=False)
        logger.info("Saved %d row(s) → %s", len(df), output_path)

    if archive_path is not None:
        if dry_run:
            logger.info("[DRY-RUN] Would archive copy → %s", archive_path)
        else:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(archive_path, index=False)
            logger.info("Archived copy → %s", archive_path)


# ---------------------------------------------------------------------------
# Per-usecase processor
# ---------------------------------------------------------------------------
def process_usecase_file(
    usecase_name: str,
    original_filename: str,
    file_path: Path,
    parent_date: str,
    child_ts: str,
    config: Dict[str, Any],
    lookback_date: str,
    output_dir: str,
    archive_dir: str,
    whitelist_dir: str,
    dry_run: bool = False,
) -> bool:
    """Run the full pipeline for a single usecase file.

    Output: ``output_dir/<parent_date>/<child_ts>/<filename>``
    Archive: ``archive_dir/<parent_date>/<child_ts>/<filename>`` (copy)
    Input files in D:\\Log\\final are NEVER touched.
    """
    logger.info("=" * 70)
    logger.info("Processing: %s  |  usecase: %s  |  output: %s/%s",
                 original_filename, usecase_name, parent_date, child_ts)

    if usecase_name not in config:
        logger.warning("SKIP: No configuration entry for usecase '%s'.", usecase_name)
        return False

    usecase_cfg = config[usecase_name]
    dedup_fields: List[str] = usecase_cfg["dedup_fields"]

    # Step 1: Read CSV
    try:
        df = read_csv_robust(file_path)
    except Exception as exc:
        logger.error("Failed to read input file '%s': %s", file_path, exc)
        return False

    if df.empty:
        logger.warning("Input file '%s' is empty. Exporting empty CSV with headers.", original_filename)
    else:
        logger.info("Read %d row(s) × %d column(s) from %s.", len(df), len(df.columns), original_filename)

    # Step 2: Whitelist
    df = apply_whitelist(df, usecase_name, whitelist_dir)

    # Step 3: Add is_benign
    df["is_benign"] = ""
    if df.empty:
        logger.info("All rows were whitelisted. Will export empty CSV.")

    # Step 4: Historical data
    historical_df = load_historical_data(
        usecase_name=usecase_name,
        dedup_fields=dedup_fields,
        date_str=lookback_date,
        processed_dir=output_dir,
        target_days=HISTORICAL_LOOKBACK_DAYS,
    )

    # Step 5: Occurrence counts
    df = compute_occurrence_counts(df, historical_df, dedup_fields)

    # Step 6: Save & Archive
    # Always save as <usecase>.csv so historical lookup works consistently.
    safe_name = usecase_name + ".csv"
    output_path = Path(output_dir) / parent_date / child_ts / safe_name
    archive_path = Path(archive_dir) / parent_date / child_ts / safe_name

    # Handle collisions within the same run (multiple files → same usecase)
    if not dry_run and output_path.exists():
        counter = 2
        while output_path.exists():
            safe_name = "%s_%d.csv" % (usecase_name, counter)
            output_path = Path(output_dir) / parent_date / child_ts / safe_name
            archive_path = Path(archive_dir) / parent_date / child_ts / safe_name
            counter += 1

    save_and_archive(df, output_path, archive_path, dry_run=dry_run)
    return True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    _setup_logging(args.verbose)

    # Resolve date
    if args.date is None:
        date_str = datetime.now().strftime("%Y%m%d")
        logger.info("No --date provided; using current date: %s", date_str)
    else:
        try:
            datetime.strptime(args.date, "%Y%m%d")
        except ValueError:
            logger.error("Invalid --date format '%s'. Expected YYYYMMDD.", args.date)
            return 1
        date_str = args.date

    # Load config
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Configuration error: %s", exc)
        return 1

    # ------------------------------------------------------------------
    # Resolve input files
    # ------------------------------------------------------------------
    if args.input_path:
        # ── Legacy mode: direct CSV path ──
        logger.info("Using legacy --input_path mode.")
        try:
            raw_files = resolve_input_files_legacy(args.input_path, args.usecase)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Input resolution error: %s", exc)
            return 1
        # Use current date as parent, HHMMSS as child
        parent = date_str
        child = generate_run_timestamp(args.run_label)
        child = make_run_timestamp_unique(child, parent, args.output_dir, args.archive_dir)
        logger.info("Run timestamp: %s/%s", parent, child)
        files: List[Tuple[str, str, Path, str, str]] = [
            (uc, fn, fp, parent, child) for uc, fn, fp in raw_files
        ]
    else:
        # ── Timestamp-directory mode ──
        if args.timestamp_dir:
            timestamp_dirs = args.timestamp_dir
            logger.info("Manual timestamp dir(s): %s", ", ".join(timestamp_dirs))
        else:
            closest = _find_closest_timestamp_dir(args.base_dir)
            if closest is None:
                logger.error("No valid timestamp directories found in %s", args.base_dir)
                return 1
            timestamp_dirs = [closest]

        files_4 = resolve_input_from_timestamp_dirs(
            timestamp_dirs=timestamp_dirs,
            config=config,
            base_dir=args.base_dir,
            usecase_filter=args.usecase,
        )
        # Parse each ts_dir_name → (parent=YYYYMMDD, child=HHMMSS)
        files = []
        for uc, fn, fp, ts_name in files_4:
            parent, child = parse_ts_dir_name(ts_name)
            if args.run_label:
                child = "%s_%s" % (child, args.run_label)
            files.append((uc, fn, fp, parent, child))

    if not files:
        logger.warning("No input files to process. Exiting.")
        return 0

    # Process each file
    success = 0
    failed = 0
    for usecase_name, original_filename, file_path, parent_date, child_ts in files:
        try:
            ok = process_usecase_file(
                usecase_name=usecase_name,
                original_filename=original_filename,
                file_path=file_path,
                parent_date=parent_date,
                child_ts=child_ts,
                config=config,
                lookback_date=date_str,
                output_dir=args.output_dir,
                archive_dir=args.archive_dir,
                whitelist_dir=args.whitelist_dir,
                dry_run=args.dry_run,
            )
            if ok:
                success += 1
            else:
                failed += 1
        except Exception as exc:
            logger.exception("Unhandled exception processing '%s': %s", original_filename, exc)
            failed += 1

    logger.info("=" * 70)
    logger.info("Pipeline complete: %d succeeded, %d failed, %d total.", success, failed, len(files))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
