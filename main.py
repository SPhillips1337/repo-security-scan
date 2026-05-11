#!/usr/bin/env python3
"""
Repo Security Scanner – CLI Entry Point

Scan local repository directories for hardcoded secrets and sensitive data,
with configurable patterns and alerting.

Usage:
    python main.py [OPTIONS] [TARGET_DIR]

Examples:
    python main.py --config .repo_scan.yaml ./my-repo
    python main.py --verbose --scan-mode quick src/
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


def load_config(config_path: str) -> dict:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If YAML parsing fails or pyyaml is missing.
    """
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if yaml is None:
        raise ValueError("pyyaml is required to load config files. Install it with: pip install pyyaml")

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse config file '{config_path}': {exc}")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all CLI flags."""
    parser = argparse.ArgumentParser(
        prog="repo-scan",
        description="Scan repositories for hardcoded secrets and sensitive data.",
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory).",
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to a YAML configuration file.",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose output with detailed scan information.",
    )

    parser.add_argument(
        "--scan-mode",
        choices=["full", "quick", "incremental"],
        default="full",
        help=(
            "Scan mode: 'full' scans all pattern categories (default), "
            "'quick' only checks critical-severity patterns, "
            "'incremental' scans only files changed in Git since --since."
        ),
    )

    parser.add_argument(
        "--since",
        type=str,
        default="HEAD~1",
        help="Git reference to compare from in 'incremental' mode (default: HEAD~1).",
    )

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: List of argument strings. Defaults to sys.argv[1:].

    Returns:
        Parsed namespace with target, config, verbose, and scan_mode attributes.
    """
    parser = build_parser()
    return parser.parse_args(argv)


def run(
    target: str,
    *,
    config_path: Optional[str] = None,
    verbose: bool = False,
    scan_mode: str = "full",
    since: str = "HEAD~1",
    return_report: bool = False,
):
    """Execute a security scan and print results.

    Args:
        target: Directory path to scan for secrets.
        config_path: Optional path to a YAML configuration file.
        verbose: If True, print detailed progress and match information.
        scan_mode: 'full', 'quick', or 'incremental'.
        since: Git reference for 'incremental' mode.
        return_report: If True, return a tuple (exit_code, AggregatedReport).

    Returns:
        Exit code or (Exit code, AggregatedReport).
        Exit code: 0 = no critical findings, 1 = critical secrets detected, 2 = error.
    """
    # Load config if provided
    cfg: dict = {}
    if config_path:
        try:
            cfg = load_config(config_path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error loading config: {exc}", file=sys.stderr)
            if return_report:
                return 2, AggregatedReport()
            return 2

    # Validate target directory
    target_path = Path(target).resolve()
    if not target_path.is_dir():
        print(f"Error: '{target}' is not a valid directory.", file=sys.stderr)
        if return_report:
            return 2, AggregatedReport()
        return 2

    # Import scanner components (lazy import to allow config loading first)
    from src.scanner import FileScanner, ScanConfig, ScanMatch
    from src.aggregator import ResultAggregator, AggregatedReport
    from src.patterns import Severity
    from src.git_utils import get_changed_files, is_git_repo

    if verbose:
        print(f"Scanning directory: {target_path}")
        print(f"Scan mode: {scan_mode}")
        if scan_mode == "incremental":
            print(f"Comparing since: {since}")
        print()

    # Build scanner config based on scan mode and optional YAML config
    from src.patterns import PATTERN_REGISTRY, Severity as PatternSeverity
    
    scanner_config = ScanConfig()
    
    # Use patterns from the central registry
    scanner_config.patterns = {}
    for p in PATTERN_REGISTRY:
        # If in quick mode, only include CRITICAL patterns
        if scan_mode == "quick" and p.severity != PatternSeverity.CRITICAL:
            continue
        scanner_config.patterns[p.name] = p.regex

    # Apply exclusions from config if present
    if cfg.get("exclusions"):
        excl = cfg["exclusions"]
        if "ignore_dirs" in excl:
            scanner_config.ignored_dirs = frozenset(excl["ignore_dirs"]) | scanner_config.ignored_dirs
        if "max_file_size" in excl:
            size = excl["max_file_size"]
            if isinstance(size, (int, float)):
                scanner_config.max_file_size = int(size)

    # Run the scan
    scanner = FileScanner(scanner_config)
    matches: List[ScanMatch] = []

    try:
        if scan_mode == "incremental":
            if not is_git_repo(str(target_path)):
                print(f"Error: '{target_path}' is not a git repository. Cannot use 'incremental' mode.", file=sys.stderr)
                if return_report:
                    return 2, AggregatedReport()
                return 2
            
            changed_files = get_changed_files(str(target_path), base_ref=since)
            if verbose:
                print(f"  Found {len(changed_files)} changed file(s) in Git.")
            matches = scanner.scan_files(changed_files)
        else:
            for file_path in scanner.walk_files(str(target_path)):
                if verbose:
                    print(f"  scanning: {file_path}")
                file_matches = scanner.scan_file(file_path)
                matches.extend(file_matches)
    except Exception as exc:
        print(f"Error during scan: {exc}", file=sys.stderr)
        if return_report:
            return 2, AggregatedReport()
        return 2

    # Aggregate results
    aggregator = ResultAggregator()
    report: AggregatedReport = aggregator.aggregate(matches)

    if verbose:
        print()
        print(report.summary())
        print()

        for finding in report.deduplicated_results:
            dup_tag = " (DUPLICATE)" if finding.is_duplicate else ""
            severity = aggregator.get_severity(finding.matched_secret_type).value
            print(f"[{severity}] {finding.matched_secret_type}{dup_tag}")
            print(f"  value : ...{finding.matched_text[:80]}...")
            for file_path, line_no in finding.file_locations:
                print(f"  found : {file_path}:{line_no}")
            print()

    # Summary output (always shown)
    has_critical = len(report.findings_by_severity.get(Severity.CRITICAL, [])) > 0
    total = report.unique_findings

    if total == 0:
        print("No secrets detected.")
    else:
        print(f"Scan complete: {total} unique finding(s) across {len(matches)} raw match(es).")

        if scan_mode == "quick":
            # In quick mode, filter to show only critical findings in summary
            critical_count = len(report.findings_by_severity.get(Severity.CRITICAL, []))
            if critical_count > 0:
                print(f"  -> {critical_count} CRITICAL finding(s) require immediate attention.")

    # Exit with non-zero code on critical findings
    exit_code = 1 if has_critical else 0
    if return_report:
        return exit_code, report
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Parse args and dispatch to run()."""
    args = parse_args(argv)
    exit_code = run(
        target=args.target,
        config_path=args.config,
        verbose=args.verbose,
        scan_mode=args.scan_mode,
        since=args.since,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
