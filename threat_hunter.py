#!/usr/bin/env python3
"""
Threat Hunter — Automated Log Processing Pipeline
==================================================
High-performance ETL pipeline for SOC threat hunting shift logs.

Processes CSV-exported logs through:
  1. Regex-based whitelist filtering (noise reduction)
  2. Historical data aggregation (past 5 days, same usecase)
  3. Frequency counting on deduplication fields
  4. Structured output with archival

Each run auto-creates a timestamp-based subdirectory under the date folder,
so multiple runs per day never overwrite each other.

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
DEFAULT_INPUT_DIR: str = "input_logs"
DEFAULT_OUTPUT_DIR: str = "processed_logs"
DEFAULT_ARCHIVE_DIR: str = "archive_logs"
DEFAULT_CONFIG_PATH: str = os.path.join("configs", "usecase_config.json")
HISTORICAL_LOOKBACK_DAYS: int = 5

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Threat Hunter — automated log processing pipeline for SOC shift logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_hunter.py
  python threat_hunter.py --usecase uc6
  python threat_hunter.py --date 20260610
  python threat_hunter.py --usecase uc1 --input_path ./Samples/
  python threat_hunter.py --input_path ./Samples/uc6.csv --dry-run --verbose
  python threat_hunter.py --run_label ca1
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
        help="Process only this usecase. If omitted, ALL usecases found in the input path are processed.",
    )
    parser.add_argument(
        "--input_path",
        default=None,
        help="Path to a CSV file or directory of CSVs. Defaults to '%s/'." % DEFAULT_INPUT_DIR,
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
        "--run_label",
        default=None,
        help="Optional human-readable label appended to the run timestamp folder "
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

    Returns:
        Dict keyed by usecase name.  Each value has ``dedup_fields`` (list)
        and ``whitelist_rules`` (list of {field, regex} dicts).

    Raises:
        FileNotFoundError: if the config file is missing.
        ValueError: if the JSON is malformed.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError("Configuration file not found: %s" % config_path)

    with open(config_path, "r", encoding="utf-8") as fh:
        config: Dict[str, Any] = json.load(fh)

    # Validate structure
    for usecase, cfg in config.items():
        if "dedup_fields" not in cfg:
            raise ValueError("Usecase '%s' is missing required key 'dedup_fields'." % usecase)
        if not isinstance(cfg["dedup_fields"], list) or len(cfg["dedup_fields"]) == 0:
            raise ValueError("'dedup_fields' for '%s' must be a non-empty list." % usecase)
        if "whitelist_rules" not in cfg:
            cfg["whitelist_rules"] = []  # tolerate missing whitelist

    logger.info("Loaded configuration for %d usecase(s): %s", len(config), ", ".join(config.keys()))
    return config


# ---------------------------------------------------------------------------
# Regex pre-compilation
# ---------------------------------------------------------------------------
def precompile_regexes(
    whitelist_rules: List[Dict[str, str]],
) -> List[Tuple[str, re.Pattern]]:
    """Pre-compile whitelist regex patterns for ultra-fast application.

    Args:
        whitelist_rules: List of ``{"field": "...", "regex": "..."}`` dicts.

    Returns:
        List of ``(field_name, compiled_pattern)`` tuples.
    """
    compiled: List[Tuple[str, re.Pattern]] = []
    for rule in whitelist_rules:
        field = rule["field"]
        pattern = rule["regex"]
        try:
            compiled.append((field, re.compile(pattern)))
        except re.error as exc:
            logger.error("Invalid regex for field '%s': '%s' — %s. Skipping rule.", field, pattern, exc)
    logger.debug("Pre-compiled %d whitelist regex pattern(s).", len(compiled))
    return compiled


# ---------------------------------------------------------------------------
# Whitelist application (vectorised)
# ---------------------------------------------------------------------------
def apply_whitelist(
    df: pd.DataFrame,
    compiled_rules: List[Tuple[str, re.Pattern]],
) -> pd.DataFrame:
    """Apply whitelist rules to a DataFrame using pure vectorized operations.

    Rows matching *any* whitelist rule are **dropped** (removed as noise).
    This function NEVER iterates over rows — all operations are Pandas-vectorised.

    Args:
        df: Input DataFrame.
        compiled_rules: Pre-compiled ``(field, pattern)`` tuples.

    Returns:
        Filtered DataFrame with whitelisted rows removed.
    """
    if df.empty or not compiled_rules:
        return df

    initial_count = len(df)
    mask = pd.Series(False, index=df.index)  # rows to DROP

    for field, pattern in compiled_rules:
        if field not in df.columns:
            logger.warning("Whitelist field '%s' not found in DataFrame columns. Skipping.", field)
            continue
        col = df[field].astype(str)
        field_mask = col.str.contains(pattern, regex=True, na=False)
        mask = mask | field_mask  # accumulate: drop if ANY rule matches

    result = df[~mask].copy()
    dropped = initial_count - len(result)
    if dropped > 0:
        logger.info("Whitelist dropped %d / %d rows (%.1f%%).", dropped, initial_count, 100 * dropped / initial_count)
    else:
        logger.info("Whitelist applied — 0 rows dropped.")
    return result


# ---------------------------------------------------------------------------
# Input file resolution
# ---------------------------------------------------------------------------
def extract_usecase_from_filename(filename: str) -> str:
    """Extract the usecase name from a filename.

    Simply uses the file stem (name without extension) as the usecase name.
    E.g. ``uc1.csv`` → ``uc1``, ``brute_force_ssh.csv`` → ``brute_force_ssh``.

    Args:
        filename: The file basename (e.g. ``uc1.csv``).

    Returns:
        Usecase name derived from the filename stem.
    """
    return Path(filename).stem


def resolve_input_files(
    input_path: str,
    usecase_filter: Optional[str],
) -> List[Tuple[str, str, Path]]:
    """Discover and resolve input CSV files.

    Returns:
        List of ``(usecase_name, original_filename, full_path)`` tuples.
    """
    ip = Path(input_path)

    if ip.is_file():
        # Single file mode
        if ip.suffix.lower() not in (".csv", ".tsv", ".txt"):
            raise ValueError("Input file must be a CSV/TSV: %s" % ip)
        usecase = extract_usecase_from_filename(ip.name)
        if usecase_filter and usecase != usecase_filter:
            logger.warning(
                "File '%s' (usecase='%s') does not match --usecase='%s'. Skipping.",
                ip.name, usecase, usecase_filter,
            )
            return []
        logger.info("Single-file mode: %s  (usecase: %s)", ip.name, usecase)
        return [(usecase, ip.name, ip)]

    # Directory mode
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
            logger.debug("Skipping '%s' — does not match usecase filter '%s'.", fp.name, usecase_filter)
            continue
        results.append((usecase, fp.name, fp))

    logger.info("Resolved %d input file(s) for processing.", len(results))
    return results


# ---------------------------------------------------------------------------
# CSV reading helper
# ---------------------------------------------------------------------------
def read_csv_robust(file_path: Path) -> pd.DataFrame:
    """Read a CSV/TSV file, auto-detecting delimiter and handling quirks.

    Tries comma delimiter first, falls back to tab.  Uses the C engine for
    maximum throughput.

    Returns:
        DataFrame (may be empty if file has only a header).
    """
    path_str = str(file_path)
    # Try comma first
    try:
        df = pd.read_csv(
            path_str,
            engine="c",
            low_memory=False,
            encoding="utf-8",
        )
        if df.shape[1] >= 2:
            logger.debug("Read %s with comma delimiter — %d columns.", file_path.name, df.shape[1])
            return df
    except Exception:
        pass

    # Try tab-separated
    try:
        df = pd.read_csv(
            path_str,
            sep="\t",
            engine="c",
            low_memory=False,
            encoding="utf-8",
        )
        logger.debug("Read %s with tab delimiter — %d columns.", file_path.name, df.shape[1])
        return df
    except Exception as exc:
        raise ValueError("Failed to read CSV/TSV '%s': %s" % (file_path.name, exc)) from exc


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
    """Find up to *target_days* past dates that actually contain data for *usecase_name*.

    Scans backwards day-by-day from *date_str - 1*, skipping days with no
    matching logs (gaps).  Stops once *target_days* dates with data have been
    found, or *max_scan* calendar days have been searched.

    Args:
        date_str:      Reference date (YYYYMMDD).  Today is excluded.
        processed_dir: Root processed logs directory.
        usecase_name:  Usecase to match.
        target_days:   Ideal number of data-days to collect (default 5).
        max_scan:      Maximum calendar days to scan backwards (default 30).

    Returns:
        List of YYYYMMDD strings that contain matching logs, newest first.
    """
    ref_date = datetime.strptime(date_str, "%Y%m%d")
    found: List[str] = []

    for offset in range(1, max_scan + 1):
        d = ref_date - timedelta(days=offset)
        day_str = d.strftime("%Y%m%d")
        day_dir = Path(processed_dir) / day_str
        if not day_dir.is_dir():
            continue
        # Check if ANY timestamp subdirectory has files for this usecase
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
    """Load processed logs from past days for the same usecase (excluding today).

    Scans ``processed_logs/<YYYYMMDD>/<HHMMSS>/<usecase>*.csv`` backwards,
    skipping days with no data (gaps), until *target_days* days of data are
    collected or *max_scan* calendar days have been searched.  Today's data
    is NEVER included.

    Args:
        usecase_name:  The usecase identifier.
        dedup_fields:  Columns needed for dedup/counting.
        date_str:      Reference date (YYYYMMDD) — historical = before this date.
        processed_dir: Root processed logs directory.
        target_days:   Ideal number of data-days to collect (default 5).
        max_scan:      Maximum calendar days to scan backwards (default 30).

    Returns:
        DataFrame with only *dedup_fields* columns, or empty DataFrame.
    """
    if not dedup_fields:
        return pd.DataFrame()

    # Find dates that actually contain data for this usecase
    dates = _find_historical_dates(date_str, processed_dir, usecase_name, target_days, max_scan)

    if not dates:
        logger.info(
            "No historical data found for usecase '%s' (scanned %d days back).",
            usecase_name, max_scan,
        )
        return pd.DataFrame(columns=dedup_fields)

    logger.info(
        "Historical scan: found %d day(s) with data for '%s' (target: %d). Dates: %s",
        len(dates), usecase_name, target_days, ", ".join(dates),
    )

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
                    else:
                        logger.debug(
                            "Historical file '%s' has none of the dedup fields. Skipping.",
                            csv_file.name,
                        )
                except Exception as exc:
                    logger.warning("Failed to read historical file '%s': %s", csv_file, exc)

    if not frames:
        return pd.DataFrame(columns=dedup_fields)

    combined = pd.concat(frames, ignore_index=True, copy=False)
    logger.info(
        "Loaded %d historical row(s) for usecase '%s' from %d day(s).",
        len(combined), usecase_name, len(dates),
    )
    return combined


# ---------------------------------------------------------------------------
# Occurrence counting (dedup + frequency)
# ---------------------------------------------------------------------------
def compute_occurrence_counts(
    current_df: pd.DataFrame,
    historical_df: pd.DataFrame,
    dedup_fields: List[str],
) -> pd.DataFrame:
    """Compute per-row occurrence counts from HISTORICAL data only.

    Today's data is NEVER included in the count.  The count reflects how many
    times each ``dedup_fields`` combination was seen in the past N days.

    Algorithm:
      1. ``groupby(dedup_fields).size()`` on **historical only** → ``Occurrence_Count``.
      2. Left-merge counts onto the **current** DataFrame.
      3. Rows with no historical match → ``Occurrence_Count = 0`` (new / unseen).

    Args:
        current_df:    Current (whitelisted) DataFrame.
        historical_df: Historical DataFrame (dedup columns only, from past days).
        dedup_fields:  Columns used for deduplication.

    Returns:
        *current_df* with an added integer ``Occurrence_Count`` column.
    """
    # Handle empty current DataFrame (e.g. all rows whitelisted)
    if current_df.empty:
        logger.info("Current DataFrame is empty — assigning empty Occurrence_Count column.")
        current_df["Occurrence_Count"] = pd.Series([], dtype="int64")
        return current_df

    # Validate dedup fields exist in current
    missing = [f for f in dedup_fields if f not in current_df.columns]
    if missing:
        logger.error(
            "Dedup field(s) %s not found in current DataFrame columns: %s. "
            "Occurrence_Count will be set to 0 for all rows.",
            missing, list(current_df.columns),
        )
        current_df["Occurrence_Count"] = 0
        return current_df

    # --- Count occurrences from HISTORICAL data ONLY ---
    if historical_df.empty:
        # No history at all → every row is unseen before
        logger.info("No historical data — all %d row(s) have Occurrence_Count = 0.", len(current_df))
        current_df["Occurrence_Count"] = 0
        return current_df

    # Align historical columns to dedup_fields
    hist_cols = [c for c in dedup_fields if c in historical_df.columns]
    if not hist_cols:
        logger.warning("Historical data has none of the dedup fields. All Occurrence_Count = 0.")
        current_df["Occurrence_Count"] = 0
        return current_df

    if len(hist_cols) != len(dedup_fields):
        logger.warning(
            "Historical data missing some dedup fields. Expected %d, got %d. "
            "Counts based on available fields only.",
            len(dedup_fields), len(hist_cols),
        )

    # GroupBy on historical data only (NOT including current day)
    counts = (
        historical_df[hist_cols]
        .groupby(hist_cols, dropna=False)
        .size()
        .reset_index(name="Occurrence_Count")
    )

    # Left-merge back to current.  NaN → 0 (never seen in history)
    result = current_df.merge(counts, on=hist_cols, how="left")
    result["Occurrence_Count"] = result["Occurrence_Count"].fillna(0).astype(int)

    occ = result["Occurrence_Count"]
    unseen = (occ == 0).sum()
    logger.info(
        "Occurrence_Count (history only): mean=%.2f, median=%s, max=%s, unseen=%d/%d (%.1f%%).",
        occ.mean(),
        str(int(occ.median())) if not occ.empty and not pd.isna(occ.median()) else "N/A",
        str(int(occ.max())) if not occ.empty and not pd.isna(occ.max()) else "N/A",
        unseen, len(result), 100 * unseen / len(result) if len(result) > 0 else 0,
    )
    return result


# ---------------------------------------------------------------------------
# Run timestamp
# ---------------------------------------------------------------------------
def generate_run_timestamp(run_label: Optional[str] = None) -> str:
    """Generate a unique run identifier for the output subdirectory.

    Format: ``HHMMSS`` (e.g. ``145530``).
    If *run_label* is provided, appends it: ``HHMMSS_label`` (e.g. ``145530_ca1``).

    Guarantees uniqueness by appending a counter if the directory already exists
    for today's date (handles sub-second re-runs).
    """
    base = datetime.now().strftime("%H%M%S")
    if run_label:
        base = "%s_%s" % (base, run_label)
    return base


def make_run_timestamp_unique(
    ts: str,
    date_str: str,
    output_dir: str,
    archive_dir: str,
) -> str:
    """Ensure the run timestamp is unique by appending a counter if needed.

    Checks both output and archive directories for collisions.
    """
    candidate = ts
    counter = 2
    while True:
        out_exists = (Path(output_dir) / date_str / candidate).exists()
        arc_exists = (Path(archive_dir) / date_str / candidate).exists()
        if not out_exists and not arc_exists:
            return candidate
        candidate = "%s_%d" % (ts, counter)
        counter += 1


# ---------------------------------------------------------------------------
# Save & Archive
# ---------------------------------------------------------------------------
def save_and_archive(
    df: pd.DataFrame,
    output_path: Path,
    source_path: Path,
    archive_path: Optional[Path],
    dry_run: bool = False,
) -> None:
    """Save processed DataFrame to output and optionally archive the source.

    Args:
        df:           Processed DataFrame.
        output_path:  Destination path for the processed CSV.
        source_path:  Original input file path.
        archive_path: Destination for archiving the original file (or None).
        dry_run:      If True, skip actual file I/O.
    """
    # Ensure output directory exists
    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save processed CSV
    if dry_run:
        logger.info("[DRY-RUN] Would save %d row(s) → %s", len(df), output_path)
    else:
        df.to_csv(output_path, index=False)
        logger.info("Saved %d row(s) → %s", len(df), output_path)

    # Archive original
    if archive_path is not None:
        if not source_path.exists():
            logger.warning(
                "Source file '%s' no longer exists — may have been archived by a previous run. Skipping archive.",
                source_path,
            )
            return
        if dry_run:
            logger.info("[DRY-RUN] Would archive %s → %s", source_path, archive_path)
        else:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source_path), str(archive_path))
            logger.info("Archived original → %s", archive_path)


# ---------------------------------------------------------------------------
# Per-usecase processor
# ---------------------------------------------------------------------------
def process_usecase_file(
    usecase_name: str,
    original_filename: str,
    file_path: Path,
    config: Dict[str, Any],
    date_str: str,
    run_timestamp: str,
    output_dir: str,
    archive_dir: str,
    should_archive: bool,
    dry_run: bool = False,
) -> bool:
    """Run the full pipeline for a single usecase file.

    Returns:
        True on success, False on failure.
    """
    logger.info("=" * 70)
    logger.info("Processing: %s  |  usecase: %s  |  date: %s  |  run: %s",
                 original_filename, usecase_name, date_str, run_timestamp)

    # Lookup config
    if usecase_name not in config:
        logger.warning("SKIP: No configuration entry for usecase '%s'.", usecase_name)
        return False

    usecase_cfg = config[usecase_name]
    dedup_fields: List[str] = usecase_cfg["dedup_fields"]
    whitelist_rules: List[Dict[str, str]] = usecase_cfg.get("whitelist_rules", [])

    # ------------------------------------------------------------------
    # Step 1: Read CSV
    # ------------------------------------------------------------------
    try:
        df = read_csv_robust(file_path)
    except Exception as exc:
        logger.error("Failed to read input file '%s': %s", file_path, exc)
        return False

    if df.empty:
        logger.warning("Input file '%s' is empty. Exporting empty CSV with headers.", original_filename)

    logger.info("Read %d row(s) × %d column(s) from %s.", len(df), len(df.columns), original_filename)

    # ------------------------------------------------------------------
    # Step 2: Whitelist (noise reduction)
    # ------------------------------------------------------------------
    compiled_rules = precompile_regexes(whitelist_rules)
    df = apply_whitelist(df, compiled_rules)

    if df.empty:
        logger.info("All rows were whitelisted (removed as noise). Will export empty CSV.")

    # ------------------------------------------------------------------
    # Step 3: Load historical data
    # ------------------------------------------------------------------
    historical_df = load_historical_data(
        usecase_name=usecase_name,
        dedup_fields=dedup_fields,
        date_str=date_str,
        processed_dir=output_dir,
        target_days=HISTORICAL_LOOKBACK_DAYS,
    )

    # ------------------------------------------------------------------
    # Step 4: Dedup & Counting
    # ------------------------------------------------------------------
    df = compute_occurrence_counts(df, historical_df, dedup_fields)

    # ------------------------------------------------------------------
    # Step 5: Save & Archive
    # ------------------------------------------------------------------
    # Output path: processed_logs/<YYYYMMDD>/<HHMMSS>/<original_filename>
    output_path = Path(output_dir) / date_str / run_timestamp / original_filename
    archive_path: Optional[Path] = None
    if should_archive:
        archive_path = Path(archive_dir) / date_str / run_timestamp / original_filename

    save_and_archive(df, output_path, file_path, archive_path, dry_run=dry_run)
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
        # Validate
        try:
            datetime.strptime(args.date, "%Y%m%d")
        except ValueError:
            logger.error("Invalid --date format '%s'. Expected YYYYMMDD.", args.date)
            return 1
        date_str = args.date

    # Generate run timestamp for this execution
    run_timestamp = generate_run_timestamp(args.run_label)
    run_timestamp = make_run_timestamp_unique(
        run_timestamp, date_str, args.output_dir, args.archive_dir,
    )
    logger.info("Run timestamp: %s", run_timestamp)

    # Resolve input path
    input_path = args.input_path or DEFAULT_INPUT_DIR
    if not os.path.exists(input_path):
        logger.error("Input path does not exist: %s", input_path)
        return 1

    # Load config
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Configuration error: %s", exc)
        return 1

    # Resolve input files
    try:
        files = resolve_input_files(input_path, args.usecase)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Input resolution error: %s", exc)
        return 1

    if not files:
        logger.warning("No input files to process. Exiting.")
        return 0

    # Determine whether to archive (only for default input_dir, not custom paths)
    should_archive = (args.input_path is None)

    # Process each file
    success = 0
    failed = 0
    for usecase_name, original_filename, file_path in files:
        try:
            ok = process_usecase_file(
                usecase_name=usecase_name,
                original_filename=original_filename,
                file_path=file_path,
                config=config,
                date_str=date_str,
                run_timestamp=run_timestamp,
                output_dir=args.output_dir,
                archive_dir=args.archive_dir,
                should_archive=should_archive,
                dry_run=args.dry_run,
            )
            if ok:
                success += 1
            else:
                failed += 1
        except Exception as exc:
            logger.exception("Unhandled exception processing '%s': %s", original_filename, exc)
            failed += 1

    # Summary
    logger.info("=" * 70)
    logger.info("Pipeline complete: %d succeeded, %d failed, %d total.", success, failed, len(files))
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())
