# AGENTS.md — Repo Security Scanner

## 1. Project Overview

### 1.1 Purpose
**Repo Security Scanner** is a Python-based CLI tool that scans local repository directories and source code to detect hardcoded secrets, API keys, tokens, passwords, and other sensitive data before they leak into version control. The goal is to surface security risks early — especially critical findings like exposed private keys or cloud credentials — so teams can rotate them proactively.

### 1.2 Scope
The scanner detects the following secret categories using configurable regex patterns:

| Category | Examples |
|---|---|
| **AWS** | Access Key IDs (`AKIA…`), Secret Access Keys |
| **GitHub** | Classic PATs (`ghp_…`), fine-grained PATs, OAuth tokens, App installation tokens, Refresh tokens |
| **Private Keys** | RSA, EC, OpenSSH, generic PEM key blocks |
| **Cloud Providers** | Google API keys, Slack bot tokens |
| **Generic** | API key assignments, secret/token values, password assignments |

Two scan modes are supported:
- **`full`** — Recursively scans all non-binary files in the target directory.
- **`quick`** — Targets only known sensitive-file patterns (`.env`, `settings.py`, etc.) and checks critical-severity patterns only.
- **`incremental`** — Scans only files added or modified in Git since a specific reference (default: `HEAD~1`).

---

## 2. Tech Stack

### 2.1 Languages & Runtime
- **Python 3.8+** — The project uses modern Python features including dataclasses, `typing` annotations (`frozenset[str]`, `Optional`, `List`, `Dict`), and enum classes. No formal packaging (`pyproject.toml` or `setup.py`) is used; the tool runs directly from source.

### 2.2 Dependencies
| Package | Purpose | Status |
|---|---|---|
| **`pyyaml`** | YAML config file parsing for `--config` support in `main.py` | Optional — graceful fallback if missing (no-op import) |

All other functionality uses the Python standard library: `argparse`, `pathlib`, `re`, `dataclasses`, `enum`, `collections.defaultdict`, `subprocess`, `json`, `os`, `sys`.

### 2.3 Configuration Format
- **YAML** — Config files (e.g., `.repo_scan.yaml`) define targets, exclusions, pattern overrides, severity thresholds, and output preferences per the schema in [`config/schema.yaml`](config/schema.yaml). Top-level keys: `targets`, `exclusions`, `patterns`, `severity`, `output`, `validation`.

---

## 3. Architecture & Structure

### 3.1 Directory Layout
```
repo-security-scan/
├── main.py                 # Primary CLI entry point with full YAML config support
├── scanner.py              # Standalone scanner (no YAML dependency; supports deep scan, severity filter)
├── scan.sh                 # Bash wrapper for quick scans / repo cloning + scanning
├── AGENTS.md               # This file — agent guidelines and project reference
├── README.md               # User-facing documentation
├── .env.template           # Template for SMTP/notification credentials
├── .env                    # Local environment variables (git-ignored)
│
├── src/                    # Core scanning modules (imported lazily by main.py)
│   ├── scanner.py          # FileScanner class: directory walk, binary detection, per-file regex scan
│   ├── patterns.py         # SecretPattern definitions, Severity enum, PATTERN_REGISTRY, category index
│   └── aggregator.py       # ResultAggregator: deduplication, grouping by severity/type, AggregatedReport
│
├── config/                 # Configuration schema and reference files
│   └── schema.yaml         # Full YAML config schema with type hints, defaults, and examples
│
├── scripts/                # Additional utility scripts
│   ├── scheduled_scan.py   # Monitors local Git repo for new commits (daemon)
│   ├── scan_profile.py     # Bulk scan every repo in a GitHub profile (full scan)
│   └── monitor_profile.py  # Crontab-friendly incremental profile monitor (recommended)
│
└── scan-reports/           # Output directory — JSON reports saved per scan run
```

### 3.2 Core Modules

#### 3.2.1 `main.py` — CLI Entry Point
- Parses arguments via `argparse`: target directory, optional `--config`, `--verbose`, `--scan-mode`.
- Loads YAML configuration if provided (with graceful fallback when `pyyaml` is missing).
- Validates the target directory exists and is accessible.
- Orchestrates scanning: creates a `FileScanner`, walks files, collects `ScanMatch` objects, delegates to `ResultAggregator`, prints summary.
- **Exit codes**: `0` = no critical findings, `1` = critical secrets detected, `2` = error during scan execution.

#### 3.2.2 `scanner.py` — Standalone Scanner
- Self-contained scanner that works without YAML config or the `src/` modules.
- Supports `--deep` flag for full file traversal vs. quick targeted-file scan.
- Can clone a remote Git repository from URL, filter by minimum severity, and output in text or JSON format.
- Reports saved as timestamped JSON files to `scan-reports/`.

#### 3.2.3 `src/scanner.py` — FileScanner
- **`ScanConfig`** dataclass: holds ignored dirs, binary extensions, regex patterns, max file size (default 10 MB).
- **`FileScanner`** class: recursive directory walker that skips ignored directories (`node_modules`, `.git`, `__pycache__`, etc.), detects binary files by extension and null-byte inspection, returns structured `ScanMatch` objects per line match.
- **Convenience function `scan()`**: one-call directory scan with optional progress callback.

#### 3.2.4 `src/patterns.py` — Pattern Registry
- **`Severity` enum**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **`SecretPattern` dataclass** (frozen): name, category, severity, compiled regex, description, example value.
- Patterns organized by category: `_AWS_PATTERNS`, `_GITHUB_PATTERNS`, `_GENERIC_API_PATTERNS`, `_PASSWORD_PATTERNS`, `_PRIVATE_KEY_PATTERNS`, `_CLOUD_PATTERNS`.
- **`PATTERN_REGISTRY`**: combined list of all patterns; extendable by appending new category lists.
- **`get_patterns_for_category()`** and **`ALL_CATEGORIES`**: helpers for filtering the registry.

#### 3.2.5 `src/aggregator.py` — ResultAggregator
- **`DeduplicatedFinding`**: consolidates identical secrets found across multiple files/lines.
- **`ResultAggregator`**: deduplicates raw matches, groups by severity and secret type, produces an `AggregatedReport` with summary statistics.
- Severity resolution via `_TYPE_SEVERITY_MAP` (maps pattern names like `"api_key"`, `"private_key"` to `Severity` levels).

### 3.3 Data Flow
```
CLI args / shell script
        │
        ▼
┌───────────────┐
│  Config Load   │  ← YAML config optional; defaults applied if absent
└───────┬───────┘
        │ ScanConfig + target path
        ▼
┌───────────────┐     ┌──────────────────────────┐
│ FileScanner    │────▶│ walk_files() → text files  │
│ (src/scanner)  │     │ scan_file() → [ScanMatch]   │
└───────┬───────┘     └──────────────────────────┘
        │ List[ScanMatch] (raw matches)
        ▼
┌───────────────┐     ┌─────────────────────────────┐
│ ResultAggre-  │────▶│ deduplicate()                 │
│ gator         │     │ group_by_severity()/type      │
│ (src/aggreg.) │     │ → AggregatedReport            │
└───────┬───────┘     └─────────────────────────────┘
        │ AggregatedReport (summary + findings)
        ▼
  Console output / JSON report → scan-reports/
```

---

## 4. Development Workflow

### 4.1 Branching Strategy

This repository follows a **main-branch-first** workflow:

| Branch | Purpose | Protection |
|---|---|---|
| `main` | Stable, production-ready code. All user-facing releases originate here. | Protected — no direct pushes; requires PR review. |
| `feature/<name>` | New features or enhancements (e.g., `feature/azure-patterns`). Short-lived; delete after merge. | — |
| `fix/<description>` | Bug fixes and patches (e.g., `fix/false-positive-dns`). Targeted and minimal in scope. | — |
| `docs/<topic>` | Documentation-only changes (AGENTS.md, README.md, schema updates). | — |

**Rules**:
- Always branch **from `main`**. Never branch off another feature branch unless building on unmerged work (coordinate with the owner).
- Branch names use lowercase kebab-case with a descriptive prefix.
- Delete branches after merging to keep the repository tidy.
- For urgent fixes, create a `fix/` branch directly from `main`, merge via PR, and consider backporting if needed.

### 4.2 Pull Request Process

All changes to `main` must go through a pull request:

1. **Open a PR** with a descriptive title following Conventional Commits format (see §5.6).
2. **Include a summary** in the body describing what changed, why, and any user-visible impact.
3. **Self-review checklist** — Before requesting review, confirm:
   - [ ] Code follows style guidelines (§5.1) and naming conventions (§5.2).
   - [ ] New patterns are registered in `PATTERN_REGISTRY` and tested manually.
   - [ ] Exit code behavior is unchanged unless intentionally modified.
   - [ ] No secrets or sensitive data introduced (run scanner on own changes: `python main.py .`).
4. **Review requirements** — At least one approval before merge. Critical severity pattern changes warrant extra scrutiny.
5. **Merge method** — Prefer **squash merge** for feature/fix branches to keep history linear. Use **rebase merge** for larger multi-commit work that benefits from preserved history.

### 4.3 Running the Scanner Locally

Quick-reference commands during development:

```bash
# Full scan of a target directory
python main.py /path/to/repo --scan-mode full

# Quick scan (sensitive files only, critical patterns)
python main.py . --scan-mode quick

# With YAML config and verbose output
python main.py . --config .repo_scan.yaml --verbose

# Standalone scanner with deep traversal and JSON output
python scanner.py /path/to/repo --deep --format json

# Incremental scan of changes in the last 3 commits
python main.py . --scan-mode incremental --since HEAD~3

# Run scheduled monitoring script
python scripts/scheduled_scan.py . --interval 300 --verbose

# Filter by minimum severity level (standalone)
python scanner.py /path/to/repo --severity high
```

### 4.4 Configuration Guidelines

When adding or modifying YAML configuration options:

1. **Schema-first** — Update [`config/schema.yaml`](config/schema.yaml) to document any new keys, types, defaults, and constraints before implementing support in `main.py`.
2. **Backwards compatibility** — New config options should have sensible defaults so existing configs continue working without modification.
3. **Graceful degradation** — Optional features (like YAML parsing via `pyyaml`) must not crash the scanner when unavailable. Fall back to built-in defaults.
4. **Severity thresholds** — When adjusting severity levels for patterns, document the rationale in a comment near the pattern definition in [`src/patterns.py`](src/patterns.py).

### 4.5 Adding New Detection Patterns

Follow this step-by-step process:

1. **Define the regex** — Craft a raw-string pattern (`r"..."`) that matches the target secret format. Test it against sample values using `re.search()`.
2. **Choose category and severity** — Map to an existing category (AWS, GitHub, Private Keys, Cloud Providers, Generic) or create a new one. Assign severity per §5.4 rules.
3. **Add to the appropriate dict-list** in [`src/patterns.py`](src/patterns.py) (e.g., `_GENERIC_API_PATTERNS`). Include `name`, `category`, `severity`, `raw`, `description`, and optionally `example`.
4. **Register if creating a new category** — Append the built pattern list to `PATTERN_REGISTRY` via `+ _build_patterns(_NEW_CATEGORY)`.
5. **Verify** — Run a manual scan on a repo known to contain examples of this secret type. Confirm no unexpected false positives in unrelated files.

### 4.6 Testing Requirements & Quality Gates

While the project does not use a formal test framework (e.g., pytest), all changes must pass these verification steps:

| Gate | Description | How to Verify |
|---|---|---|
| **Syntax check** | All modified files parse without errors | `python -m py_compile main.py src/scanner.py src/patterns.py src/aggregator.py` |
| **Import validation** | No broken or circular imports | Run each entry point: `python main.py --help`, `python scanner.py --help` |
| **Manual scan** | Scanner runs on a known target without crashing | `python main.py . --scan-mode full` (should exit 0, 1, or 2 as expected) |
| **Pattern accuracy** | New/changed patterns detect intended secrets | Scan a sample file containing the secret type; confirm match in output |
| **False-positive check** | Patterns don't flag non-secret values excessively | Review `MEDIUM`/`LOW` findings on a clean repo to assess noise |
| **Exit code correctness** | Return codes align with §5.3 expectations | Verify exit 0 (no critical), 1 (critical found), or 2 (error) |
| **JSON report validity** | Output reports are well-formed JSON | `python -m json.tool scan-reports/latest.json` |

**Pattern-specific testing**: When adding or modifying a regex pattern, test against at least:
- One known positive match (the secret value it should detect).
- One known negative case (a similar string that should not match).
- An edge case (e.g., partial key in comments, multi-line formatting).

### 4.7 Documentation Expectations

All changes must maintain documentation parity with code:

1. **AGENTS.md** — Update this file when architecture, conventions, or workflow rules change. Sections 3–5 are the primary reference for agents and contributors.
2. **README.md** — Keep user-facing docs in sync with new features, CLI flags, or scan modes. Example commands should be accurate and tested.
3. **Module docstrings** — Every public module (`src/scanner.py`, `src/patterns.py`, `src/aggregator.py`) must have a current docstring describing purpose and usage. Update when behavior changes.
4. **Config schema** — [`config/schema.yaml`](config/schema.yaml) must reflect all supported keys, types, defaults, and constraints. New options are documented before merge.
5. **Inline comments** — Add brief comments for non-obvious logic (regex rationale, severity choices, fallback behaviors). Avoid restating what the code already says clearly.

### 4.8 Output & Reporting

Report conventions to maintain consistency:

- JSON reports are saved to `scan-reports/` with timestamps in filenames.
- Reports include scan metadata (timestamp, target path, mode), summary counts by severity, and detailed findings list.
- Console output separates critical findings visually for quick review.
- When extending report format, ensure backward compatibility — existing fields should not be removed or renamed without migration notes.

---

## 5. Coding Standards & Conventions

### 5.1 Python Style Guidelines

| Area | Rule | Example |
|---|---|---|
| **Type Hints** | Use on all public function signatures, return types, and dataclass fields. Prefer `typing` module generics (`List`, `Dict`, `Optional`) for compatibility with Python 3.8+. | `def scan_file(self, file_path: str) -> List[ScanMatch]:` |
| **Docstrings** | Multi-line Google-style docstrings on all public modules, classes, functions, and methods. Include `Args:`, `Returns:`, and `Raises:` where applicable. Module-level docstring describes purpose + usage example. | See [`src/scanner.py`](src/scanner.py) for reference. |
| **Imports** | Group in order: stdlib → third-party → local (`from src.xxx import ...`). Place lazy imports inside functions when they avoid circular deps or enable optional dependencies (e.g., `yaml` in `main.py`). | — |
| **Line Length** | Target 88 characters. Use implicit line continuation inside parentheses/brackets for long expressions and function calls. | — |
| **Spacing** | Two blank lines before top-level classes and functions; one blank line before methods. Use section separators (`# --- Section Name ---`) in module bodies to group related code. | See [`src/patterns.py`](src/patterns.py). |

### 5.2 Naming Conventions

| Element | Convention | Example |
|---|---|---|
| **Classes** | `PascalCase` — descriptive nouns representing a thing or behavior. | `FileScanner`, `ResultAggregator`, `ScanConfig` |
| **Functions / Methods** | `snake_case` — verb-led descriptions of actions. Public methods start lowercase; private helpers prefixed with `_`. | `scan_file()`, `_should_skip_dir()` |
| **Module-Level Constants** | `UPPER_SNAKE_CASE` for immutable values, collections, and registry references. | `DEFAULT_IGNORED_DIRS`, `PATTERN_REGISTRY`, `ALL_CATEGORIES` |
| **Private Module Vars** | Leading underscore, lowercase or UPPER_SNAKE_CASE depending on mutability. | `_AWS_PATTERNS`, `_CATEGORY_INDEX` |
| **Dataclasses** | Frozen (`frozen=True`) for immutable value objects (e.g., `ScanMatch`, `DeduplicatedFinding`). Mutable for configuration containers (e.g., `ScanConfig`, `AggregatedReport`). | — |

### 5.3 File Organization Patterns

Each source file follows this structure:

```
1. Module-level docstring  (purpose + usage example)
2. Imports                (stdlib → third-party → local)
3. Constants / Enums       (UPPER_SNAKE_CASE, top of scope)
4. Dataclasses             (frozen models first, mutable configs next)
5. Core Classes            (primary public interface)
6. Helper Functions        (module-level convenience wrappers)
7. Registry / Index Build  (PATTERN_REGISTRY, _CATEGORY_INDEX, etc.)
8. Public API functions    (get_patterns_for_category(), print_registry())
9. __main__ block          (standalone demo when run directly)
```

### 5.4 Pattern Definition Rules

When adding or modifying detection patterns in [`src/patterns.py`](src/patterns.py):

1. **Define as raw dicts first** — Use the `_CATEGORY_PATTERNS` dict-list convention with keys: `name`, `category`, `severity`, `raw` (regex string), `description`, optional `example`.
2. **Assign severity conservatively** — Reserve `CRITICAL` for secrets that should never appear in source control (private keys, access tokens). Use `HIGH` for likely-real credentials, `MEDIUM` for generic matches needing review, and `LOW` for informational findings.
3. **Use raw string literals (`r"..."`)** for regex to avoid backslash escaping issues.
4. **Prefer anchored or contextual patterns** — Where possible, match key-value assignment patterns (e.g., `"api_key\s*[:=]"`) rather than bare value shapes to reduce false positives.
5. **Register new categories in `PATTERN_REGISTRY`** by appending the built list (`+ _build_patterns(_NEW_CATEGORY)`). Update `_CATEGORY_INDEX` is automatic via the comprehension loop.

### 5.5 Error Handling & Exit Codes

| Exit Code | Meaning | When Used |
|---|---|---|
| **0** | Success — no critical findings detected | Scan completes with zero `CRITICAL`-severity matches. |
| **1** | Critical secrets found | One or more patterns classified as `Severity.CRITICAL` matched. Action (rotation) required. |
| **2** | Error during scan execution | Target directory invalid, config parse failure, I/O error, or unexpected exception. Message printed to `stderr`. |

**Error-handling rules**:
- Catch specific exceptions (`OSError`, `IOError`, `FileNotFoundError`) rather than bare `except:`.
- Surface user-facing errors via `print(..., file=sys.stderr)` and return exit code 2 from `run()`.
- Use graceful fallbacks for optional dependencies (e.g., `yaml = None` when `pyyaml` is not installed).

### 5.6 Commit Message Guidelines

Use **Conventional Commits** format for all commits:

```
<type>[optional scope]: <description>

[optional body]
```

| Type | When to Use | Example |
|---|---|---|
| `feat` | New detection pattern, scan mode, or CLI flag | `feat(patterns): add Slack bot token detection` |
| `fix` | Bug fix in scanning logic, regex correction | `fix(scanner): handle binary files with no extension` |
| `refactor` | Internal restructuring without behavior change | `refactor(aggregator): simplify deduplication loop` |
| `docs` | Documentation or AGENTS.md updates | `docs: expand coding standards section` |
| `chore` | Config, dependency, or tooling changes | `chore: bump max file size default to 10 MB` |

Keep descriptions under 72 characters. Use imperative mood ("add" not "added"). Reference issue numbers in the body when applicable.

---

## 6. AI Agent Guidelines

### 6.1 General Instructions

When working on this repository, follow these priorities:

1. **Preserve backward compatibility** — Never remove existing CLI flags, exit codes, or report fields without explicit approval. New features should have sensible defaults.
2. **Run the scanner on your changes** — Before completing any task, verify with `python main.py . --scan-mode full` that no new secrets were introduced by your modifications.
3. **Check patterns before logic** — When debugging detection issues, examine `src/patterns.py` first (regex definitions), then `src/scanner.py` (file walking/matching), then `src/aggregator.py` (deduplication/reporting).
4. **Follow the module structure** — Each file in `src/` has a single responsibility. Do not add cross-cutting concerns; create helpers or extend existing classes instead.
5. **Graceful degradation is mandatory** — Optional dependencies (like `pyyaml`) must never crash the scanner. Always provide fallback defaults when an import fails.

### 6.2 Pattern-Related Changes

When modifying detection patterns in [`src/patterns.py`](src/patterns.py):

1. **Never remove a pattern without documenting why** — If a pattern is deprecated, move it to a `_DEPRECATED_PATTERNS` list with a comment explaining the removal rationale.
2. **Test every regex change manually** — Use `python -c "import re; print(re.search(r'YOUR_PATTERN', 'test_string'))"` before committing.
3. **Severity changes require justification** — If you adjust a pattern's severity level, add an inline comment explaining the decision (e.g., `"# lowered to HIGH: matches too many placeholder values"`).
4. **New categories must be registered** — After adding `_NEW_CATEGORY` patterns, append them to `PATTERN_REGISTRY`. The `_CATEGORY_INDEX` updates automatically via comprehension.
5. **Do not introduce overlapping patterns** — If two patterns can match the same secret value, document which one takes precedence in deduplication.

### 6.3 Testing Expectations

After any code change, perform these verification steps before considering work complete:

1. **Syntax validation**: `python -m py_compile main.py src/scanner.py src/patterns.py src/aggregator.py`
2. **Import check**: Run both entry points — `python main.py --help` and `python scanner.py --help` — confirming no import errors.
3. **Scan execution**: Run `python main.py . --scan-mode full` on the project itself; verify exit code matches expectations (0, 1, or 2 per §5.5).
4. **JSON report check**: If a report was generated, validate with `python -m json.tool scan-reports/latest.json`.
5. **Pattern-specific tests** (when adding/modifying patterns): Verify against at least one positive match, one negative case, and one edge case before committing.

---

## 7. Configuration Reference

### 7.1 Schema Overview

Configuration files follow the schema defined in [`config/schema.yaml`](config/schema.yaml). Top-level keys:

| Key | Purpose | Required |
|-----|---------|----------|
| `targets` | Directories to scan (list of paths with optional labels) | Yes |
| `exclusions` | Dirs, extensions, and size limits to ignore | No — sensible defaults |
| `patterns` | Enable/disable categories, overrides, custom rules | No — all patterns active by default |
| `severity` | Minimum severity level to report | No — defaults to `MEDIUM` |
| `output` | Format (`text`, `json`, `csv`), file path, display options | No |
| `validation` | Pre-scan checks (target existence, regex validation) | No — all enabled by default |

### 7.2 Minimal Working Example

```yaml
# .repo_scan.yaml — minimal configuration for scanning this project
targets:
  - path: "."
    label: "Repo Security Scanner"

exclusions:
  ignore_dirs: [".git", "__pycache__"]
  max_file_size: "10MB"

patterns:
  enabled_categories: ["aws", "github", "private_key", "password"]
  custom:
    - name: Datadog API Key
      category: cloud
      severity: HIGH
      regex: "dd-api-[A-F0-9]{32}"

severity:
  minimum_level: MEDIUM

output:
  format: json
  file_path: "./scan-reports/results.json"
```

Run with: `python main.py . --config .repo_scan.yaml`
