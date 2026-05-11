"""
Result Aggregation Module

Consolidates scan results by deduplicating identical secrets across files
and grouping findings by severity level or secret type.

Usage:
    from src.aggregator import ResultAggregator

    aggregator = ResultAggregator()
    aggregated = aggregator.deduplicate(matches)
    by_severity = aggregator.group_by_severity(matches)
    by_type = aggregator.group_by_secret_type(matches)
"""

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, Iterable, List, Optional

from src.patterns import Severity


@dataclass(frozen=True)
class DeduplicatedFinding:
    """A unique secret finding after deduplication.

    When the same secret value appears in multiple files or lines, this
    consolidates those occurrences into a single record while preserving
    all locations where it was found.

    Attributes:
        matched_secret_type: The type/category of the detected secret (e.g., 'api_key').
        matched_text: The actual secret text/value that was matched.
        file_locations: List of (file_path, line_number) tuples for every occurrence.
    """

    matched_secret_type: str
    matched_text: str
    file_locations: List[tuple]  # list of (file_path: str, line_number: int)

    @property
    def first_occurrence(self) -> tuple:
        """Return the first file location where this secret was found."""
        return self.file_locations[0] if self.file_locations else ("", 0)

    @property
    def occurrence_count(self) -> int:
        """Number of files/lines containing this duplicate secret."""
        return len(self.file_locations)

    @property
    def is_duplicate(self) -> bool:
        """Whether this secret appears in more than one location."""
        return self.occurrence_count > 1


@dataclass
class AggregatedReport:
    """Summary report of aggregated scan results.

    Attributes:
        total_raw_matches: Total number of raw matches before deduplication.
        unique_findings: Number of distinct secret values found.
        duplicates_removed: How many duplicate occurrences were consolidated.
        findings_by_severity: Findings grouped by severity level.
        findings_by_type: Findings grouped by matched secret type.
        deduplicated_results: List of DeduplicatedFinding records.
    """

    total_raw_matches: int = 0
    unique_findings: int = 0
    duplicates_removed: int = 0
    findings_by_severity: Dict[Severity, List[DeduplicatedFinding]] = field(default_factory=dict)
    findings_by_type: Dict[str, List[DeduplicatedFinding]] = field(default_factory=dict)
    deduplicated_results: List[DeduplicatedFinding] = field(default_factory=list)

    def summary(self) -> str:
        """Produce a human-readable summary of the aggregated results."""
        lines = [
            "=== Scan Results Summary ===",
            f"Total raw matches : {self.total_raw_matches}",
            f"Unique findings   : {self.unique_findings}",
            f"Duplicates removed: {self.duplicates_removed}",
            "",
            "By Severity:",
        ]

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            count = len(self.findings_by_severity.get(sev, []))
            if count:
                lines.append(f"  {sev.value:<12} : {count}")

        lines.append("")
        lines.append("By Secret Type:")
        for secret_type, findings in sorted(
            self.findings_by_type.items(), key=lambda x: -len(x[1])
        ):
            lines.append(f"  {secret_type:<25} : {len(findings)}")

        return "\n".join(lines)


class ResultAggregator:
    """Aggregate and deduplicate scan results from multiple files.

    The aggregator consolidates raw ScanMatch objects produced by the scanner
    into a cleaner set of findings, removing duplicates and providing grouping
    by severity and secret type.

    Example:
        matches = scanner.scan_directory("path/to/repo")
        agg = ResultAggregator()
        report = agg.aggregate(matches)
        print(report.summary())
    """

    # Resolve severity from the central pattern registry
    def get_severity(self, secret_type: str) -> Severity:
        """Resolve the severity level for a given secret type name.

        Args:
            secret_type: The matched_secret_type from a ScanMatch.

        Returns:
            Corresponding Severity enum value (defaults to MEDIUM if unknown).
        """
        from src.patterns import PATTERN_REGISTRY
        for pattern in PATTERN_REGISTRY:
            if pattern.name == secret_type:
                return pattern.severity
        
        # Fallback for legacy pattern names
        legacy_map = {
            "api_key": Severity.HIGH,
            "password": Severity.HIGH,
            "secret_key": Severity.CRITICAL,
            "access_token": Severity.CRITICAL,
            "aws_access_key_id": Severity.CRITICAL,
            "private_key": Severity.CRITICAL,
            "generic_secret": Severity.MEDIUM,
            "email_in_code": Severity.LOW,
        }
        return legacy_map.get(secret_type, Severity.MEDIUM)

    def deduplicate(
        self, matches: Iterable
    ) -> List[DeduplicatedFinding]:
        """Remove duplicate secrets that appear across multiple files or lines.

        Two matches are considered duplicates when they share the same
        (matched_secret_type, matched_text) pair, i.e., the same type of secret
        with the identical value.

        Args:
            matches: Iterable of ScanMatch objects from the scanner.

        Returns:
            List of DeduplicatedFinding with all occurrences consolidated.
        """
        # Key: (matched_secret_type, matched_text) -> list of locations
        groups: Dict[tuple, List[tuple]] = defaultdict(list)

        for match in matches:
            key = (match.matched_secret_type, match.matched_text)
            groups[key].append((match.file_path, match.line_number))

        return [
            DeduplicatedFinding(
                matched_secret_type=secret_type,
                matched_text=text,
                file_locations=locations,
            )
            for (secret_type, text), locations in sorted(groups.items())
        ]

    def group_by_severity(
        self, matches: Iterable
    ) -> Dict[Severity, List]:
        """Group raw findings by severity level.

        Args:
            matches: Iterable of ScanMatch objects from the scanner.

        Returns:
            Dictionary mapping Severity levels to lists of matching ScanMatch objects.
        """
        grouped: Dict[Severity, List] = defaultdict(list)

        for match in matches:
            severity = self.get_severity(match.matched_secret_type)
            grouped[severity].append(match)

        return dict(grouped)

    def group_by_secret_type(
        self, matches: Iterable
    ) -> Dict[str, List]:
        """Group raw findings by matched secret type.

        Args:
            matches: Iterable of ScanMatch objects from the scanner.

        Returns:
            Dictionary mapping secret type strings to lists of ScanMatch objects.
        """
        grouped: Dict[str, List] = defaultdict(list)

        for match in matches:
            grouped[match.matched_secret_type].append(match)

        return dict(grouped)

    def aggregate(
        self,
        matches: Iterable,
        deduplicate_flag: bool = True,
    ) -> AggregatedReport:
        """Produce a full aggregated report from raw scan results.

        This is the primary entry point for consolidating all findings into
        a single report with deduplication and grouping information.

        Args:
            matches: Iterable of ScanMatch objects from the scanner.
            deduplicate_flag: If True (default), merge duplicate secrets
                              across files. Set to False to keep every match.

        Returns:
            AggregatedReport containing summary stats, grouped findings,
            and the deduplicated result list.
        """
        matches_list = list(matches)
        total_raw = len(matches_list)
        report = AggregatedReport(total_raw_matches=total_raw)

        if deduplicate_flag:
            deduped = self.deduplicate(matches_list)
            report.unique_findings = len(deduped)
            report.duplicates_removed = total_raw - len(deduped)
        else:
            # Treat each raw match as its own "finding"
            deduped = [
                DeduplicatedFinding(
                    matched_secret_type=m.matched_secret_type,
                    matched_text=m.matched_text,
                    file_locations=[(m.file_path, m.line_number)],
                )
                for m in matches_list
            ]
            report.unique_findings = total_raw

        report.deduplicated_results = deduped

        # Group by severity (using deduplicated findings)
        sev_grouped: Dict[Severity, List[DeduplicatedFinding]] = defaultdict(list)
        for finding in deduped:
            sev = self.get_severity(finding.matched_secret_type)
            sev_grouped[sev].append(finding)
        report.findings_by_severity = dict(sev_grouped)

        # Group by secret type (using deduplicated findings)
        type_grouped: Dict[str, List[DeduplicatedFinding]] = defaultdict(list)
        for finding in deduped:
            type_grouped[finding.matched_secret_type].append(finding)
        report.findings_by_type = dict(type_grouped)

        return report


def aggregate(
    matches: Iterable,
    deduplicate_flag: bool = True,
) -> AggregatedReport:
    """Convenience function to aggregate scan results.

    Args:
        matches: Iterable of ScanMatch objects from the scanner.
        deduplicate_flag: If True, merge duplicate secrets across files.

    Returns:
        AggregatedReport with consolidated findings and statistics.
    """
    aggregator = ResultAggregator()
    return aggregator.aggregate(matches, deduplicate_flag=deduplicate_flag)


if __name__ == "__main__":
    from src.scanner import scan, ScanMatch

    # Quick demo: scan current directory and aggregate results
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    raw_matches = scan(target)

    report = aggregate(raw_matches)
    print(report.summary())
    print()

    # Show deduplicated findings
    for finding in report.deduplicated_results:
        dup_tag = " (DUPLICATE)" if finding.is_duplicate else ""
        print(f"[{finding.matched_secret_type}]{dup_tag}")
        print(f"  Value : ...{finding.matched_text[:60]}...")
        for file_path, line_no in finding.file_locations:
            print(f"  Found : {file_path}:{line_no}")
        print()
