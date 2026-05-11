#!/usr/bin/env python3
"""repo-security-scanner - Scan GitHub repos for leaked API keys and secrets."""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"

# Quick-scan target filenames
QUICK_SCAN_TARGETS = [
    ".env", ".env.local", ".env.production", ".env.development", ".envrc",
    "config.py", "settings.py", "credentials.py", "secrets.py",
    "config.php", "settings.php", "wp-config.php", "php.ini",
    "docker-compose.yml", ".npmrc", ".pypirc",
    ".aws/credentials", ".aws/config",
    ".vscode/settings.json", ".idea/workspace.xml",
    "serverless.yml", "netlify.toml", "vercel.json",
    "application.properties", "application.yml",
    "terraform.tfvars", "*.tfvars",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
]

SECRET_PATTERNS = {
    # AWS
    "AWS_ACCESS_KEY": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS_SECRET": r"\bAKIA[A-Z0-9]{16}\b",
    "GITHUB_PAT": r"\b(ghp_[a-zA-Z0-9]{36,})\b",
    "GITHUB_OAUTH": r"\b(gho_[a-zA-Z0-9]{36,})\b",
    "GITHUB_REFRESH": r"\b(ghr_[a-zA-Z0-9]{36,})\b",
    "GITHUB_FINE_PAT": r"\b(github_pat_[0-9a-zA-Z_]{5,})\b",
    "STRIPE_PUBLISHABLE": r"\b(pk_live_[0-9a-zA-Z]{24,})\b",
    "STRIPE_SECRET": r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
    "STRIPE_TEST_SECRET": r"\b(sk_test_[0-9a-zA-Z]{24,})\b",
    "SLACK_TOKEN": r"\b(xox[bap]-[0-9]{10,13}-[0-9a-zA-Z-]{20,})\b",
    "SLACK_WEBHOOK": r"\b(https://hooks\.slack\.com/services/T[a-zA-Z0-9]{8,}/B[a-zA-Z0-9]{8,}/[a-zA-Z0-9]{24})\b",
    "TELEGRAM_BOT": r"\b([0-9]{8,12}:[A-Za-z0-9_-]{35})\b",
    "DISCORD_TOKEN": r"\b([MN][a-zA-Z0-9]{23,}\.[\w-]{6}\.[\w-]{27,})\b",
    "TWILIO_SID": r"\b(AC[a-f0-9]{32})\b",
    "TWILIO_TOKEN": r"\b(SK[a-f0-9]{32})\b",
    "SENDGRID_API_KEY": r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b",
    "DIGITALOCEAN_TOKEN": r"\b(dop_v1_[a-zA-Z0-9]{64})\b",
    "MAILGUN_API_KEY": r"\b(key-[a-zA-Z0-9]{32})\b",
    "SQL_CONNECTION": r"(?i)(postgres(?:ql)?|mysql|mongodb)://[^:]+:([^@]+)@",
    "API_KEY_ASSIGNMENT": r"(?i)(api[_-]?key|secret[_-]?key|password)\s*[=:]\s*[\s]*[\'\"]([^\'\"]{10,})[\'\"]",
}

SEVERITY = {
    "AWS_ACCESS_KEY": "CRITICAL", "GITHUB_PAT": "CRITICAL", "GITHUB_OAUTH": "CRITICAL",
    "GITHUB_REFRESH": "CRITICAL", "GITHUB_FINE_PAT": "CRITICAL", "STRIPE_SECRET": "CRITICAL",
    "STRIPE_TEST_SECRET": "CRITICAL", "SLACK_TOKEN": "CRITICAL", "DISCORD_TOKEN": "CRITICAL",
    "TWILIO_TOKEN": "CRITICAL", "SENDGRID_API_KEY": "CRITICAL", "SQL_CONNECTION": "CRITICAL",
    "AWS_SECRET": "HIGH", "STRIPE_PUBLISHABLE": "HIGH", "SLACK_WEBHOOK": "HIGH",
    "TELEGRAM_BOT": "HIGH", "TWILIO_SID": "HIGH", "DIGITALOCEAN_TOKEN": "HIGH",
    "MAILGUN_API_KEY": "HIGH", "API_KEY_ASSIGNMENT": "HIGH", "PASSWORD": "MEDIUM",
}

SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll', '.so'}

def is_binary(filepath):
    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return True
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
    except:
        return True
    return False

def get_quick_files(repo_path):
    found = []
    for target in QUICK_SCAN_TARGETS:
        if '*' in target:
            for f in repo_path.glob(target):
                if f.is_file() and not is_binary(f):
                    found.append(f)
        else:
            f = repo_path / target
            if f.is_file() and not is_binary(f):
                found.append(f)
    return sorted(set(found))

def get_all_files(repo_path):
    files = []
    for f in repo_path.rglob('*'):
        if f.is_file() and not is_binary(f) and '.git' not in str(f):
            files.append(f)
    return sorted(files)

def scan_file(filepath, min_severity="LOW"):
    findings = []
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except:
        return findings
    
    for name, pattern in SECRET_PATTERNS.items():
        sev = SEVERITY.get(name, "LOW")
        if sev == "CRITICAL": sev_rank = 0
        elif sev == "HIGH": sev_rank = 1
        elif sev == "MEDIUM": sev_rank = 2
        else: sev_rank = 3
        if sev_rank > {"LOW": 3, "MEDIUM": 2, "HIGH": 1, "CRITICAL": 0}.get(min_severity, 3):
            continue
        
        for match in re.finditer(pattern, content, re.IGNORECASE):
            findings.append({
                "file": str(filepath),
                "line": content[:match.start()].count('\n') + 1,
                "pattern": name,
                "severity": sev,
                "match": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
            })
    return findings

def clone_repo(url, workdir):
    repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
    target = Path(workdir) / repo_name
    if target.exists():
        subprocess.run(['git', '-C', str(target), 'fetch', '--all'], capture_output=True)
        subprocess.run(['git', '-C', str(target), 'reset', '--hard', 'origin/HEAD'], capture_output=True)
    else:
        subprocess.run(['git', 'clone', '--depth', '1', url, str(target)], capture_output=True, check=True)
    return target

def main():
    parser = argparse.ArgumentParser(description="Scan repos for leaked secrets")
    parser.add_argument("target", nargs="?", help="Repo URL or local path")
    parser.add_argument("--deep", "-d", action="store_true", help="Deep scan all files")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="LOW")
    parser.add_argument("--workdir", default="/tmp/scanner-repos")
    parser.add_argument("--output-dir", "-o", default="./scan-reports")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text")
    args = parser.parse_args()

    Path(args.workdir).mkdir(parents=True, exist_ok=True)
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    if args.target and args.target.startswith(('http://', 'https://')):
        repo_path = clone_repo(args.target, args.workdir)
    elif args.target:
        repo_path = Path(args.target).resolve()
    else:
        parser.print_help()
        sys.exit(1)

    print(f"\nScanning: {repo_path}")
    print(f"Mode: {'deep' if args.deep else 'quick'}")
    
    files = get_all_files(repo_path) if args.deep else get_quick_files(repo_path)
    print(f"Files: {len(files)}")

    all_findings = []
    for f in files:
        findings = scan_file(f, args.min_severity)
        all_findings.extend(findings)

    # Print results
    if all_findings:
        print(f"\n=== FINDINGS ({len(all_findings)}) ===")
        for fd in all_findings:
            print(f"[{fd['severity']}] {fd['file'].replace(str(repo_path), '')}:{fd['line']} - {fd['pattern']}")
    else:
        print("\nNo secrets detected.")

    # Save report
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repo": str(repo_path),
        "mode": "deep" if args.deep else "quick",
        "findings": all_findings
    }
    out = Path(args.output_dir) / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved: {out}")

if __name__ == "__main__":
    main()