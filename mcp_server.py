#!/usr/bin/env python3
"""
MCP Server for Repo Security Scanner

This server allows AI assistants to scan repositories for secrets using the
Repo Security Scanner's core logic.
"""

import os
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("Error: 'fastmcp' not found. Install it with: pip install fastmcp")
    sys.exit(1)

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from src.scanner import FileScanner, ScanConfig, ScanMatch
from src.aggregator import ResultAggregator, AggregatedReport
from src.patterns import PATTERN_REGISTRY, Severity

# Initialize FastMCP server
mcp = FastMCP("Repo Security Scanner")

@mcp.tool()
def scan_directory(path: str, mode: str = "full", verbose: bool = False) -> Dict[str, Any]:
    """
    Scan a directory for hardcoded secrets.
    
    Args:
        path: Absolute path to the directory to scan.
        mode: Scan mode ('full' for all patterns, 'quick' for critical only).
        verbose: Whether to include detailed match locations.
    """
    target_path = Path(path).resolve()
    if not target_path.is_dir():
        return {"error": f"Path '{path}' is not a directory."}

    # Setup config
    config = ScanConfig()
    config.patterns = {}
    for p in PATTERN_REGISTRY:
        if mode == "quick" and p.severity != Severity.CRITICAL:
            continue
        config.patterns[p.name] = p.regex

    # Run scan
    scanner = FileScanner(config)
    matches = []
    for file_path in scanner.walk_files(str(target_path)):
        matches.extend(scanner.scan_file(file_path))

    # Aggregate
    aggregator = ResultAggregator()
    report = aggregator.aggregate(matches)

    # Format result
    result = {
        "summary": report.summary(),
        "unique_findings": report.unique_findings,
        "findings_by_severity": {
            sev.value: len(findings) 
            for sev, findings in report.findings_by_severity.items()
        }
    }

    if verbose or report.unique_findings < 50:
        findings_list = []
        for finding in report.deduplicated_results:
            findings_list.append({
                "type": finding.matched_secret_type,
                "severity": aggregator.get_severity(finding.matched_secret_type).value,
                "sample": f"...{finding.matched_text[:50]}...",
                "locations": [f"{loc[0]}:{loc[1]}" for loc in finding.file_locations[:5]]
            })
        result["findings"] = findings_list

    return result

@mcp.tool()
def list_patterns() -> List[Dict[str, str]]:
    """List all secret detection patterns supported by the scanner."""
    return [
        {
            "name": p.name,
            "category": p.category,
            "severity": p.severity.value,
            "description": p.description
        }
        for p in PATTERN_REGISTRY
    ]

@mcp.resource("reports://latest")
def get_latest_report() -> str:
    """Retrieve the content of the most recent JSON scan report."""
    report_dir = Path("scan-reports")
    if not report_dir.is_dir():
        return "No reports found."
    
    reports = sorted(report_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
    if not reports:
        return "No reports found."
    
    return reports[0].read_text()

if __name__ == "__main__":
    mcp.run()
