# Repo Security Scanner

A Python-based CLI tool for scanning local repositories and source code directories to detect hardcoded secrets, API keys, tokens, passwords, and other sensitive data before they leak into version control.

In an ever increasing world of AI generated code and Open Source software and collaborative development it has become increasingly important to ensure that our code is secure and free of vulnerabilities. With more and more automated agents and AI being added to the software supply chain it can be an essential defense for developers to audit their own work. This is the gap that this tool aims to fill.

## Description

Repo Security Scanner performs recursive file traversal across repository directories, applying configurable regex patterns to identify potential security issues such as:

- **AWS credentials** (Access Key IDs, Secret Access Keys)
- **GitHub tokens** (Classic PATs, fine-grained PATs, OAuth tokens)
- **Private keys** (RSA, EC, OpenSSH, generic PEM)
- **Cloud provider secrets** (Slack, Stripe, Twilio, SendGrid, DigitalOcean, Google API keys)
- **Generic patterns** (API key assignments, passwords, database connection strings)

### Key Features

- **Three scan modes**: `full` (all files), `quick` (critical patterns only), and `incremental` (Git changes since a specific ref)
- **Configurable detection rules** via YAML configuration with custom pattern support
- **Severity classification**: CRITICAL, HIGH, MEDIUM, LOW
- **Deduplication**: Consolidates identical secrets found across multiple locations
- **Binary file skipping**: Automatically ignores non-text and large files
- **Multiple entry points**: Python CLI (`main.py`), standalone scanner (`scanner.py`), or shell script (`scan.sh`)

## Project Structure

```
repo-security-scan/
├── main.py              # Primary CLI entry point with full config support
├── scanner.py           # Standalone scanner (no YAML config required)
├── scan.sh              # Bash wrapper for quick scans
├── .env                 # Configuration file for SMTP and GitHub settings
├── .env.template        # Template for environment configuration
├── src/                 # Core scanning modules
│   ├── scanner.py       # File traversal and content scanning
│   ├── patterns.py      # Secret detection pattern definitions
│   ├── aggregator.py    # Result aggregation and deduplication
│   ├── notifier.py      # Email alert system (SMTP)
│   ├── git_utils.py     # Git-based file discovery and repo validation
│   └── github_utils.py  # GitHub API integration for profile discovery
├── config/              # Configuration files
│   └── schema.yaml      # Configuration schema reference
├── scripts/             # Additional utility scripts
│   ├── scheduled_scan.py # Git monitoring with email alerts
│   └── scan_profile.py   # Bulk scanning of a GitHub profile
└── scan-reports/        # Output directory for scan reports
```

## Installation

### Prerequisites

- Python 3.8+
- `pyyaml` (optional, for YAML config support)
- `requests` (for GitHub API discovery)
- `python-dotenv` (for `.env` file support)

### Steps

```bash
# Clone the repository
git clone <repo-url> repo-security-scan
cd repo-security-scan

# Install dependencies
pip install pyyaml requests python-dotenv

# Set up configuration
cp .env.template .env
# Edit .env with your SMTP and GitHub settings
```

No additional packages are required for basic scanning. The tool runs entirely from source without a formal package installation.

## Usage

### Basic Scan (Python CLI)

Scan the current directory using default settings:

```bash
python main.py
```

Scan a specific target directory with verbose output:

```bash
python main.py --verbose ./path/to/repo
```

```bash
python main.py --scan-mode quick src/
```

### Incremental Scan (Git Integration)

Scan only the files that have changed in Git since a specific reference (default is `HEAD~1`):

```bash
python main.py --scan-mode incremental --since HEAD~5
```

### Scheduled Monitoring (with Email Alerts)

Automatically monitor a repository for new commits and trigger incremental scans. If `SMTP` is configured in `.env`, email alerts will be sent for critical findings:

```bash
python scripts/scheduled_scan.py . --interval 300 --verbose
```

### GitHub Profile Bulk Scan

Scan every repository belonging to a specific GitHub user:

```bash
# Uses GITHUB_USERNAME from .env by default
python scripts/scan_profile.py

# Or specify a username directly
python scripts/scan_profile.py some-other-user --report my_report.md
```

Use a custom YAML configuration file:

```bash
python main.py --config .repo_scan.yaml ./my-repo
```

### Standalone Scanner

Quick scan without config loading:

```bash
python scanner.py /path/to/repo
```

Deep scan all files with minimum severity filter:

```bash
python scanner.py --deep --min-severity HIGH /path/to/repo -o ./scan-reports
```

Scan a remote repository by URL:

```bash
python scanner.py https://github.com/user/project.git --deep --format json
```

### Shell Script

```bash
# Quick scan (default)
./scan.sh https://github.com/user/project.git

# Deep scan all files
./scan.sh https://github.com/user/project.git true
```

### CLI Options (`main.py`)

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Directory to scan | Current directory (`.`) |
| `--config`, `-c` | Path to YAML configuration file | None |
| `--verbose`, `-v` | Enable detailed output | Off |
| `--scan-mode` | Scan mode: `full`, `quick`, or `incremental` | `full` |
| `--since` | Git reference for `incremental` mode | `HEAD~1` |

### Exit Codes

- **0**: No critical findings detected
- **1**: Critical secrets found (requires attention)
- **2**: Error during scan execution

## Configuration

### Severity Levels

| Level    | Description                                      |
|----------|--------------------------------------------------|
| CRITICAL | High risk of immediate exposure (private keys, tokens) |
| HIGH     | Likely to cause issues if exposed                 |
| MEDIUM   | Should be reviewed and potentially rotated        |
| LOW      | Informational / lower risk                        |

### Detected Pattern Categories

- **AWS**: Access Key IDs, Secret Access Keys
- **GitHub**: Personal Access Tokens (classic & fine-grained), OAuth tokens, App installation tokens, Refresh tokens
- **Private Keys**: RSA, EC, OpenSSH, generic PEM keys
- **Cloud Providers**: Google API keys, Slack bot tokens
- **Generic**: API key assignments, secret/token values, password assignments

### YAML Configuration Example

```yaml
exclusions:
  ignore_dirs:
    - node_modules
    - .git
    - __pycache__
  max_file_size: 10485760  # 10 MB in bytes
```

## Output

Scan reports are saved to the `scan-reports/` directory (configurable via `-o` flag). Reports include:

- Timestamp of scan execution
- Repository path scanned
- Scan mode used (`quick` or `deep`)
- List of findings with severity, file location, line number, and pattern matched

## Responsible Use & Disclaimer

**IMPORTANT: This tool is intended for authorized security auditing and personal repository management only.**

The authors and contributors of Repo Security Scanner are not responsible for any misuse of this tool. By using this software, you agree to:
- Use it only on repositories you own or have explicit permission to scan.
- Comply with all local and international laws regarding cybersecurity and privacy.
- Not use it for unauthorized data collection or "secret hunting" on third-party profiles without consent.

The primary goal of the tool is to empower developers to find and fix leaks before an attacker does. In the security world, tools like TruffleHog, Gitleaks, and Git-secrets are already widely available and used by both sides. Sharing this tool contributes to the ecosystem of defensive utilities that help normalize "security-first" development.

**Educational Purpose**: This tool is designed to help developers identify vulnerabilities and improve their security posture. Misuse can lead to severe legal consequences.

**Inherent Limitations**
While the tool can scan any public profile, it is naturally limited by the GitHub API rate limits. Without a Personal Access Token, a user can only make 60 requests per hour—which makes large-scale "fishing" across many profiles difficult. This acts as a minor built-in deterrent for casual misuse.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
