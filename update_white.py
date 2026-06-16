#!/usr/bin/env python3
"""
update_white.py — Update whitelist CSVs from processed log files.
===============================================================

Scans processed log directories for rows marked ``is_benign = "x"`` and
adds their corresponding field values to the appropriate whitelist CSV
(``whitelists/<usecase>.csv``).  Duplicates are automatically skipped.

Usage:
  python update_white.py --log_dir processed_logs/20260616/093000/
  python update_white.py --log_dir processed_logs/20260616/
  python update_white.py --log_dir processed_logs/20260616/ --dry-run --verbose
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import pandas as pd

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("update_white")


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
DEFAULT_WHITELIST_DIR: str = "whitelists"
DEFAULT_CONFIG_PATH: str = os.path.join("configs", "usecase_config.json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update whitelist CSVs from processed logs marked is_benign='x'.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python update_white.py --log_dir processed_logs/20260616/093000/
  python update_white.py --log_dir processed_logs/20260616/
  python update_white.py --log_dir processed_logs/20260616/ --dry-run --verbose
        """,
    )
    parser.add_argument(
        "--log_dir",
        required=True,
        help="Path to processed log directory. Can be a specific run (e.g. "
             "processed_logs/20260616/093000/) or a date folder (scans all runs).",
    )
    parser.add_argument(
        "--whitelist_dir",
        default=DEFAULT_WHITELIST_DIR,
        help="Directory containing whitelist CSV files. Defaults to '%s/'." % DEFAULT_WHITELIST_DIR,
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to usecase config JSON (for fallback column discovery). Defaults to '%s'." % DEFAULT_CONFIG_PATH,
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
        help="Show what would be added without writing files.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def extract_usecase_from_filename(filename: str) -> str:
    return Path(filename).stem


def read_csv_robust(file_path: Path) -> pd.DataFrame:
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


def load_config(config_path: str) -> Dict[str, Any]:
    """Load usecase config, returns empty dict if not found."""
    if not os.path.isfile(config_path):
        logger.warning("Config file not found: %s. Will infer whitelist columns from log data.", config_path)
        return {}
    import json
    with open(config_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Whitelist update logic
# ---------------------------------------------------------------------------
def _normalize_row(row: pd.Series, columns: List[str]) -> str:
    """Build a hashable key from a row of whitelist fields."""
    parts = []
    for col in columns:
        val = row.get(col)
        if pd.isna(val) or str(val).strip() == "":
            parts.append("")
        else:
            parts.append(str(val))
    return "\x00".join(parts)


def _row_exists(wl_df: pd.DataFrame, row: pd.Series, columns: List[str]) -> bool:
    """Check if *row*'s values already exist as a row in *wl_df*."""
    target = _normalize_row(row, columns)
    for _, wl_row in wl_df.iterrows():
        if _normalize_row(wl_row, columns) == target:
            return True
    return False


def update_whitelist(
    usecase_name: str,
    benign_rows: pd.DataFrame,
    whitelist_dir: str,
    config: Dict[str, Any],
    dry_run: bool = False,
) -> int:
    """Add benign rows to the whitelist CSV for *usecase_name*.

    Args:
        usecase_name: Usecase identifier.
        benign_rows:  DataFrame of rows marked ``is_benign = "x"``.
        whitelist_dir: Path to whitelists folder.
        config:       Usecase config (for fallback column discovery).
        dry_run:      If True, only preview changes.

    Returns:
        Number of new entries added.
    """
    wl_path = Path(whitelist_dir) / ("%s.csv" % usecase_name)

    # Determine whitelist columns
    if wl_path.is_file():
        existing_wl = read_csv_robust(wl_path)
        wl_columns = list(existing_wl.columns)
    else:
        # New whitelist — infer columns from config dedup_fields or benign data
        if usecase_name in config and "dedup_fields" in config[usecase_name]:
            wl_columns = list(config[usecase_name]["dedup_fields"])
        else:
            # Use all columns from benign data except is_benign and Occurrence_Count
            wl_columns = [c for c in benign_rows.columns
                          if c not in ("is_benign", "Occurrence_Count")]
        existing_wl = pd.DataFrame(columns=wl_columns)
        logger.info("Whitelist '%s' will be created with columns: %s", usecase_name, wl_columns)

    # Only keep columns that exist in benign data
    usable_cols = [c for c in wl_columns if c in benign_rows.columns]
    if not usable_cols:
        logger.warning("No whitelist columns found in benign data for '%s'. Skipping.", usecase_name)
        return 0

    if len(usable_cols) != len(wl_columns):
        logger.debug("Some whitelist columns not in log data. Using: %s", usable_cols)

    # Find new entries
    new_rows: List[pd.Series] = []
    existing_keys: Set[str] = set()
    for _, wl_row in existing_wl.iterrows():
        existing_keys.add(_normalize_row(wl_row, usable_cols))

    skipped_empty = 0
    for _, benign_row in benign_rows.iterrows():
        key = _normalize_row(benign_row, usable_cols)
        # Skip rows where ALL whitelist fields are empty (would match everything)
        if key.replace("\x00", "").strip() == "":
            skipped_empty += 1
            continue
        if key not in existing_keys:
            new_rows.append(benign_row)
            existing_keys.add(key)

    if skipped_empty > 0:
        logger.warning("Skipped %d row(s) with all-empty whitelist fields for '%s'.", skipped_empty, usecase_name)

    added = len(new_rows)
    if added == 0:
        logger.info("Usease '%s': 0 new entries (all already in whitelist).", usecase_name)
        return 0

    # Build updated whitelist DataFrame
    new_df = pd.DataFrame([{c: r.get(c) if c in r.index else "" for c in wl_columns}
                           for r in new_rows])
    updated = pd.concat([existing_wl, new_df], ignore_index=True)

    if dry_run:
        logger.info("[DRY-RUN] Would add %d entry(s) to %s:", added, wl_path)
        for _, row in new_df.iterrows():
            logger.info("  + %s", {c: row[c] for c in usable_cols if str(row[c]).strip()})
    else:
        wl_path.parent.mkdir(parents=True, exist_ok=True)
        updated.to_csv(wl_path, index=False)
        logger.info("Added %d entry(s) → %s", added, wl_path)

    return added


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    _setup_logging(args.verbose)

    log_dir = Path(args.log_dir)
    if not log_dir.is_dir():
        logger.error("Log directory not found: %s", log_dir)
        return 1

    config = load_config(args.config)

    # Discover CSV files
    csv_files: List[Path] = []
    if any(f.suffix.lower() in (".csv", ".tsv") for f in log_dir.iterdir() if f.is_file()):
        # Specific run directory (contains CSVs directly)
        csv_files = sorted(log_dir.glob("*.csv")) + sorted(log_dir.glob("*.tsv"))
    else:
        # Date directory — walk all run subdirectories
        for run_dir in sorted(log_dir.iterdir()):
            if run_dir.is_dir():
                csv_files.extend(sorted(run_dir.glob("*.csv")) + sorted(run_dir.glob("*.tsv")))

    if not csv_files:
        logger.warning("No CSV files found in %s", log_dir)
        return 0

    logger.info("Found %d CSV file(s) to scan.", len(csv_files))

    # Group benign rows by usecase
    grouped: Dict[str, pd.DataFrame] = {}
    for fp in csv_files:
        usecase = extract_usecase_from_filename(fp.name)
        try:
            df = read_csv_robust(fp)
        except Exception as exc:
            logger.warning("Skipping '%s': %s", fp.name, exc)
            continue

        if "is_benign" not in df.columns:
            logger.debug("File '%s' has no is_benign column — skipping.", fp.name)
            continue

        benign = df[df["is_benign"].astype(str).str.strip().str.lower() == "x"]
        if benign.empty:
            continue

        logger.info("File '%s' (usecase=%s): %d benign row(s) found.", fp.name, usecase, len(benign))

        if usecase not in grouped:
            grouped[usecase] = benign
        else:
            grouped[usecase] = pd.concat([grouped[usecase], benign], ignore_index=True)

    if not grouped:
        logger.info("No rows with is_benign='x' found in any file.")
        return 0

    # Update whitelists
    total_added = 0
    for usecase, benign_rows in grouped.items():
        try:
            added = update_whitelist(
                usecase_name=usecase,
                benign_rows=benign_rows,
                whitelist_dir=args.whitelist_dir,
                config=config,
                dry_run=args.dry_run,
            )
            total_added += added
        except Exception as exc:
            logger.exception("Failed to update whitelist for '%s': %s", usecase, exc)

    logger.info("=" * 70)
    if args.dry_run:
        logger.info("DRY-RUN complete: would add %d entry(s) across %d usecase(s).",
                     total_added, len(grouped))
    else:
        logger.info("Update complete: added %d entry(s) across %d usecase(s).",
                     total_added, len(grouped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
