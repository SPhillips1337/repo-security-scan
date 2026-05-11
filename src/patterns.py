"""
Secret Detection Patterns Module

Defines regex-based rules for detecting hardcoded secrets and sensitive data
in repository files. Patterns are organized by category and designed to be
modular and easily extendable.

Usage:
    from src.patterns import PATTERN_REGISTRY, get_patterns_for_category

    # Get all patterns
    for pattern in PATTERN_REGISTRY:
        print(pattern.name, pattern.regex)

    # Filter by category
    aws_patterns = get_patterns_for_category("aws")
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import re


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    """Severity classification for detected secrets."""
    CRITICAL = "CRITICAL"   # High risk of immediate exposure (private keys, tokens)
    HIGH = "HIGH"           # Likely to cause issues if exposed
    MEDIUM = "MEDIUM"       # Should be reviewed and potentially rotated
    LOW = "LOW"             # Informational / lower risk


# ---------------------------------------------------------------------------
# Pattern Data Structure
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SecretPattern:
    """A single secret detection pattern with metadata.

    Attributes:
        name:       Human-readable identifier for the pattern.
        category:   Category tag (e.g., 'aws', 'github', 'generic').
        severity:   Risk level if this pattern matches.
        regex:      Compiled regular expression to detect the secret.
        description: Short explanation of what this pattern detects.
        example:    Example value that would match this pattern.
        ignore_words: Words that, when adjacent to a match, suggest it is not
                      a real secret (e.g., 'example', 'test').
    """

    name: str
    category: str
    severity: Severity
    regex: re.Pattern[str]
    description: str
    example: Optional[str] = None
    ignore_words: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern Definitions by Category
# ---------------------------------------------------------------------------

def _compile(patterns_dict: Dict[str, str]) -> re.Pattern[str]:
    """Compile a raw regex string into a Pattern object."""
    return re.compile(patterns_dict["raw"], flags=re.IGNORECASE if patterns_dict.get("case_insensitive", False) else 0)


# --- AWS Patterns ----------------------------------------------------------
_AWS_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "category": "aws",
        "severity": Severity.CRITICAL,
        "raw": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "AWS Access Key IDs are 20-character strings starting with a specific prefix.",
        "example": "AKIAIOSFODNN7EXAMPLE",
    },
    {
        "name": "AWS Secret Access Key",
        "category": "aws",
        "severity": Severity.CRITICAL,
        "raw": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}",
        "description": "AWS Secret Access Key is a 40-character base64 string.",
        "example": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    },
]

# --- GitHub Patterns -------------------------------------------------------
_GITHUB_PATTERNS = [
    {
        "name": "GitHub Personal Access Token (Classic)",
        "category": "github",
        "severity": Severity.CRITICAL,
        "raw": r"ghp_[A-Za-z0-9]{36}",
        "description": "GitHub classic personal access tokens start with ghp_.",
        "example": "ghp_EXAMPLE_TOKEN_REDACTED_FOR_PUSH_SAFETY",
    },
    {
        "name": "GitHub Fine-grained Personal Access Token",
        "category": "github",
        "severity": Severity.CRITICAL,
        "raw": r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        "description": "Fine-grained personal access tokens start with github_pat_.",
        "example": "github_pat_11ABCDEFGH0ABCDEFGH_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy",
    },
    {
        "name": "GitHub OAuth Access Token (User)",
        "category": "github",
        "severity": Severity.HIGH,
        "raw": r"gho_[A-Za-z0-9]{36}",
        "description": "GitHub user OAuth access tokens start with gho_.",
        "example": "gho_EXAMPLE_TOKEN_REDACTED_FOR_PUSH_SAFETY",
    },
    {
        "name": "GitHub App Installation Access Token",
        "category": "github",
        "severity": Severity.HIGH,
        "raw": r"ghs_[A-Za-z0-9]{36}",
        "description": "GitHub server-to-server tokens start with ghs_.",
        "example": "ghs_EXAMPLE_TOKEN_REDACTED_FOR_PUSH_SAFETY",
    },
    {
        "name": "GitHub Refresh Token",
        "category": "github",
        "severity": Severity.HIGH,
        "raw": r"ghr_[A-Za-z0-9]{36}",
        "description": "GitHub refresh tokens start with ghr_.",
        "example": "ghr_EXAMPLE_TOKEN_REDACTED_FOR_PUSH_SAFETY",
    },
]

# --- Generic API Key Patterns ----------------------------------------------
_GENERIC_API_PATTERNS = [
    {
        "name": "Generic API Key / Secret",
        "category": "generic_api_key",
        "severity": Severity.HIGH,
        "raw": r"(?i)(?:api[_\-]?key|apikey)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{20,}",
        "description": "Common API key patterns assigned via key-value notation.",
        "example": "API_KEY = 'abcdef1234567890ghijkl'",
    },
    {
        "name": "Generic Secret / Token",
        "category": "generic_api_key",
        "severity": Severity.MEDIUM,
        "raw": r"(?i)(?:secret|token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{20,}",
        "description": "Generic secret or token assigned via key-value notation.",
        "example": "SECRET = 'some_long_random_string_here'",
    },
]

# --- Password Patterns -----------------------------------------------------
_PASSWORD_PATTERNS = [
    {
        "name": "Password Assignment",
        "category": "password",
        "severity": Severity.HIGH,
        "raw": r"(?i)(?:passwd|pwd|password)[\"']?\s*[:=]\s*[\"'][^\"]{8,}[\"']",
        "description": "Passwords assigned in code or config via key-value notation.",
        "example": 'PASSWORD = "mySecureP@ss123"',
    },
]

# --- Private Key Patterns --------------------------------------------------
_PRIVATE_KEY_PATTERNS = [
    {
        "name": "RSA Private Key",
        "category": "private_key",
        "severity": Severity.CRITICAL,
        "raw": r"-----BEGIN RSA PRIVATE KEY-----",
        "description": "PEM-encoded RSA private key block.",
        "example": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
    },
    {
        "name": "EC Private Key",
        "category": "private_key",
        "severity": Severity.CRITICAL,
        "raw": r"-----BEGIN EC PRIVATE KEY-----",
        "description": "PEM-encoded Elliptic Curve private key block.",
        "example": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...",
    },
    {
        "name": "OpenSSH Private Key",
        "category": "private_key",
        "severity": Severity.CRITICAL,
        "raw": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "description": "Modern OpenSSH-format private key block.",
        "example": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...",
    },
    {
        "name": "Generic PEM Private Key",
        "category": "private_key",
        "severity": Severity.CRITICAL,
        "raw": r"-----BEGIN PRIVATE KEY-----",
        "description": "PKCS#8 generic private key block.",
        "example": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANB...",
    },
]

# --- Cloud Provider Patterns -----------------------------------------------
_CLOUD_PATTERNS = [
    {
        "name": "Google API Key",
        "category": "cloud",
        "severity": Severity.HIGH,
        "raw": r"AIza[0-9A-Za-z_\-]{35}",
        "description": "Google Cloud / Firebase API key.",
        "example": "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    },
    {
        "name": "Slack Bot Token",
        "category": "cloud",
        "severity": Severity.HIGH,
        "raw": r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}",
        "description": "Slack bot user token.",
        "example": "xoxb-00000000000-00000000000-REDACTED_FOR_SAFETY",
    },
]


# ---------------------------------------------------------------------------
# Registry Builder
# ---------------------------------------------------------------------------

def _build_patterns(raw_list: List[dict]) -> List[SecretPattern]:
    """Build a list of SecretPattern instances from raw configuration dicts."""
    return [
        SecretPattern(
            name=entry["name"],
            category=entry["category"],
            severity=Severity(entry["severity"]),
            regex=_compile(entry),
            description=entry["description"],
            example=entry.get("example"),
        )
        for entry in raw_list
    ]


# ---------------------------------------------------------------------------
# Public Registry – extend by appending new lists here
# ---------------------------------------------------------------------------

PATTERN_REGISTRY: List[SecretPattern] = (
    _build_patterns(_AWS_PATTERNS)
    + _build_patterns(_GITHUB_PATTERNS)
    + _build_patterns(_GENERIC_API_PATTERNS)
    + _build_patterns(_PASSWORD_PATTERNS)
    + _build_patterns(_PRIVATE_KEY_PATTERNS)
    + _build_patterns(_CLOUD_PATTERNS)
)

# Category index for quick filtering
_CATEGORY_INDEX: Dict[str, List[SecretPattern]] = {}
for pattern in PATTERN_REGISTRY:
    _CATEGORY_INDEX.setdefault(pattern.category, []).append(pattern)


def get_patterns_for_category(category: str) -> List[SecretPattern]:
    """Return all patterns belonging to a given category."""
    return _CATEGORY_INDEX.get(category, [])


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

ALL_CATEGORIES = list(_CATEGORY_INDEX.keys())


def print_registry() -> None:
    """Pretty-print the full pattern registry (useful for debugging)."""
    print(f"{'Name':<45} {'Category':<18} {'Severity':<10}")
    print("-" * 73)
    for p in PATTERN_REGISTRY:
        print(f"{p.name:<45} {p.category:<18} {p.severity.value:<10}")
