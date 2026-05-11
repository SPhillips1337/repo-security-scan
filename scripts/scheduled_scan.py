#!/usr/bin/env python3
"""
Scheduled Git Scanner

This script monitors a local Git repository for new commits and triggers
an incremental security scan on the changed files.

Usage:
    python scripts/scheduled_scan.py [REPO_PATH] [OPTIONS]

Example:
    python scripts/scheduled_scan.py . --interval 60 --branch master
"""

import argparse
import os
import subprocess
import time
import sys
from pathlib import Path

# Add project root to path so we can import src
sys.path.append(str(Path(__file__).parent.parent))

from src.git_utils import is_git_repo, get_changed_files
from main import run as run_scan


def get_current_head(repo_path: str) -> str:
    """Get the current HEAD commit hash."""
    result = subprocess.run(
        ["git", "-C", repo_path, "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def fetch_remote(repo_path: str):
    """Fetch updates from remote."""
    try:
        subprocess.run(["git", "-C", repo_path, "fetch"], capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Warning: Failed to fetch from remote: {exc.stderr}")


def main():
    parser = argparse.ArgumentParser(description="Monitor a Git repo for new commits and scan them.")
    parser.add_argument("repo", nargs="?", default=".", help="Path to the Git repository.")
    parser.add_argument("--interval", type=int, default=300, help="Check interval in seconds (default: 300).")
    parser.add_argument("--branch", default="HEAD", help="Branch to monitor (default: HEAD).")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--state-file", default=".last_scanned_commit", help="File to store the last scanned commit hash.")
    
    args = parser.parse_args()
    repo_path = str(Path(args.repo).resolve())
    state_file = Path(repo_path) / args.state_file

    if not is_git_repo(repo_path):
        print(f"Error: '{repo_path}' is not a Git repository.")
        sys.exit(1)

    # Initialize notifier
    from src.notifier import EmailNotifier, format_findings_email
    notifier = EmailNotifier()

    print(f"Monitoring repository: {repo_path}")
    print(f"Check interval: {args.interval}s")
    print(f"State file: {state_file}")
    if notifier.is_configured():
        print("Email notifications: ENABLED")
    else:
        print("Email notifications: DISABLED (Set SMTP environment variables)")

    # Load last scanned commit
    last_commit = None
    if state_file.exists():
        last_commit = state_file.read_text().strip()
        print(f"Last scanned commit: {last_commit}")
    else:
        # If no state file, start from current HEAD but don't scan anything yet
        last_commit = get_current_head(repo_path)
        state_file.write_text(last_commit)
        print(f"Initial state set to current HEAD: {last_commit}")

    try:
        while True:
            if args.verbose:
                print(f"Checking for updates at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
            
            # Optionally fetch from remote if we are monitoring origin
            # fetch_remote(repo_path)
            
            current_commit = get_current_head(repo_path)
            
            if current_commit != last_commit:
                print(f"\nNew commits detected: {last_commit[:8]} -> {current_commit[:8]}")
                
                # Trigger incremental scan
                exit_code, report = run_scan(
                    target=repo_path,
                    scan_mode="incremental",
                    since=last_commit,
                    verbose=args.verbose,
                    return_report=True
                )
                
                if exit_code == 1:
                    print("CRITICAL: Secrets found in new commits!")
                    if notifier.is_configured():
                        print("Sending email alert...")
                        # Get critical findings
                        from src.patterns import Severity
                        critical_findings = report.findings_by_severity.get(Severity.CRITICAL, [])
                        repo_name = Path(repo_path).name
                        body = format_findings_email(repo_name, critical_findings)
                        notifier.send_alert(f"SECURITY ALERT: Secrets detected in {repo_name}", body)
                elif exit_code == 0:
                    print("Clean scan: No secrets found in new commits.")
                else:
                    print("Error during scan.")

                # Update state
                last_commit = current_commit
                state_file.write_text(last_commit)
            
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


if __name__ == "__main__":
    main()
