"""
Repository Security Scanner - File Traversal and Content Scanning Module

Provides recursive directory walking with configurable pattern matching to detect
hardcoded secrets and sensitive data in source code files.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Pattern


# Default directories to ignore during traversal (e.g., large or generated dirs)
DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".egg-info",
})

# Common binary file extensions to skip
BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".bin",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".svg",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".webp",
    ".cache",
})

# Default regex patterns for detecting common secrets
DEFAULT_PATTERNS: Dict[str, Pattern[str]] = {
    "api_key": re.compile(r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?"""),
    "password": re.compile(r"""(?i)password\s*[:=]\s*['"][^\s'"]{4,}['"]"""),
    "secret_key": re.compile(r"""(?i)(?:secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?"""),
    "access_token": re.compile(r"""(?i)(?:access[_-]?token|bearer)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{20,}['"]?"""),
    "aws_access_key_id": re.compile(r"(?:AKIA[0-9A-Z]{16})"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?(PRIVATE KEY)-----"),
    "generic_secret": re.compile(r"""(?i)(?:secret|token|credential)\s*[:=]\s*['"][^\s'"]{8,}['"]"""),
    "email_in_code": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
}


@dataclass(frozen=True)
class ScanMatch:
    """Structured object representing a single secret match found during scanning."""

    file_path: str
    line_number: int
    matched_secret_type: str
    matched_text: str = ""
    line_content: str = ""

    def __str__(self) -> str:
        return (
            f"[{self.matched_secret_type}] {self.file_path}:{self.line_number}"
        )


@dataclass
class ScanConfig:
    """Configuration for the file scanner."""

    ignored_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_IGNORED_DIRS)
    binary_extensions: frozenset[str] = field(default_factory=lambda: BINARY_EXTENSIONS)
    patterns: Dict[str, Pattern[str]] = field(
        default_factory=lambda: dict(DEFAULT_PATTERNS)
    )
    max_file_size: int = 10 * 1024 * 1024  # 10 MB default limit

    def add_pattern(self, name: str, pattern: Pattern[str]) -> None:
        """Add or update a named regex pattern."""
        self.patterns[name] = pattern


class FileScanner:
    """Recursive directory walker that scans files for hardcoded secrets.

    Features:
      - Skips binary files based on extension and content inspection
      - Ignores large/generated directories (node_modules, .git, etc.)
      - Returns structured ScanMatch objects with file path, line number,
        and matched secret type
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        # Cache for binary file detection to avoid re-reading large files
        self._binary_cache: Dict[str, bool] = {}

    @staticmethod
    def _is_binary_file(file_path: str) -> bool:
        """Check if a file is binary by reading the first 8192 bytes and looking for null bytes."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
                return b"\x00" in chunk
        except (OSError, IOError):
            # If we can't read the file, treat it as binary to be safe
            return True

    def _should_skip_dir(self, dir_name: str) -> bool:
        """Check if a directory should be skipped during traversal."""
        return dir_name in self.config.ignored_dirs

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if a file should be skipped based on extension or size."""
        # Skip by binary extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.config.binary_extensions:
            return True

        # Skip large files
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.config.max_file_size:
                return True
        except OSError:
            pass

        return False

    def _is_binary(self, file_path: str) -> bool:
        """Check if a file is binary with caching."""
        if file_path not in self._binary_cache:
            self._binary_cache[file_path] = self._is_binary_file(file_path)
        return self._binary_cache[file_path]

    def walk_files(self, root_dir: str) -> Iterator[str]:
        """Yield file paths from the directory tree, skipping ignored dirs and binary files.

        Args:
            root_dir: The root directory to scan recursively.

        Yields:
            Paths of text files suitable for content scanning.
        """
        if not os.path.isdir(root_dir):
            raise NotADirectoryError(f"'{root_dir}' is not a valid directory.")

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories in-place to avoid descending into them
            dirnames[:] = [
                d for d in dirnames
                if not self._should_skip_dir(d)
            ]

            # Sort for deterministic output
            dirnames.sort()
            filenames.sort()

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)

                # Skip by extension/size checks first (cheaper than content read)
                if self._should_skip_file(file_path):
                    continue

                # Content-based binary detection
                if self._is_binary(file_path):
                    continue

                yield file_path

    def scan_file(self, file_path: str) -> List[ScanMatch]:
        """Scan a single file for secrets using configured patterns.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of ScanMatch objects representing detected secrets.
        """
        matches: List[ScanMatch] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    stripped_line = line.rstrip("\n\r")
                    for secret_type, pattern in self.config.patterns.items():
                        search_result = pattern.search(stripped_line)
                        if search_result:
                            matches.append(ScanMatch(
                                file_path=file_path,
                                line_number=line_number,
                                matched_secret_type=secret_type,
                                matched_text=search_result.group(),
                                line_content=stripped_line[:200],  # Truncate long lines
                            ))
        except (OSError, IOError):
            pass

        return matches

    def scan_directory(self, root_dir: str) -> List[ScanMatch]:
        """Recursively scan a directory for all secrets.

        Args:
            root_dir: The root directory to scan recursively.

        Returns:
            List of ScanMatch objects representing all detected secrets.
        """
        all_matches: List[ScanMatch] = []

        for file_path in self.walk_files(root_dir):
            file_matches = self.scan_file(file_path)
            all_matches.extend(file_matches)

        return all_matches

    def scan_files(self, file_paths: List[str]) -> List[ScanMatch]:
        """Scan a specific list of files for secrets.

        Args:
            file_paths: List of absolute or relative file paths.

        Returns:
            List of ScanMatch objects.
        """
        all_matches: List[ScanMatch] = []
        for path in file_paths:
            if os.path.isfile(path) and not self._should_skip_file(path) and not self._is_binary(path):
                all_matches.extend(self.scan_file(path))
        return all_matches


def scan(
    root_dir: str,
    config: Optional[ScanConfig] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[ScanMatch]:
    """Convenience function to perform a full directory scan.

    Args:
        root_dir: The root directory to scan recursively.
        config: Optional scanner configuration (uses defaults if not provided).
        progress_callback: Optional callback(progress, total) for reporting progress.

    Returns:
        List of ScanMatch objects representing all detected secrets.
    """
    scanner = FileScanner(config)
    matches: List[ScanMatch] = []
    file_count = 0

    # First pass to count files (for progress tracking)
    total_files = sum(1 for _ in scanner.walk_files(root_dir))

    # Second pass to scan files
    for file_path in scanner.walk_files(root_dir):
        matches.extend(scanner.scan_file(file_path))
        file_count += 1

        if progress_callback:
            progress_callback(file_count, total_files)

    return matches


if __name__ == "__main__":
    # Quick demo when run directly
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan(target)

    print(f"\nScan Results: {len(results)} potential secrets found\n")
    for match in sorted(results, key=lambda m: (m.file_path, m.line_number)):
        print(match)
        print(f"  Content: ...{match.matched_text}...")
        print()
