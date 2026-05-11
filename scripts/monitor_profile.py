#!/usr/bin/env python3
"""
Monitor GitHub Profile (Incremental)

This script scans all repositories in a GitHub profile for new commits.
It maintains state to ensure only new changes are scanned, and it is
optimized for use with Crontab (runs once and exits).

Usage:
    python scripts/monitor_profile.py [USERNAME] [OPTIONS]
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.github_utils import get_user_repositories
from src.git_utils import is_git_repo, get_changed_files
from src.notifier import EmailNotifier, format_findings_email
from main import run as run_scan

STATE_FILE = "profile_scan_state.json"
CACHE_DIR = "repo_cache"

def load_state() -> Dict[str, Any]:
    """Load the last scanned commit for each repository and branch."""
    state_path = Path(STATE_FILE)
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except json.JSONDecodeError:
            return {}
    return {}

def save_state(state: Dict[str, Any]):
    """Save the last scanned commit for each repository and branch."""
    Path(STATE_FILE).write_text(json.dumps(state, indent=2))

def get_remote_branches(repo_path: str) -> List[str]:
    """Get a list of all remote branches for the repository."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "branch", "-r"],
            capture_output=True, text=True, check=True
        )
        branches = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line or " -> " in line:
                continue
            # Remove 'origin/' prefix
            if line.startswith("origin/"):
                branches.append(line.replace("origin/", "", 1))
        return branches
    except subprocess.CalledProcessError:
        return []

def get_branch_head(repo_path: str, branch: str) -> str:
    """Get the latest commit hash for a specific remote branch."""
    result = subprocess.run(
        ["git", "-C", repo_path, "rev-parse", f"origin/{branch}"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Monitor a GitHub profile for new commits and scan them.")
    parser.add_argument("username", nargs="?", default=os.environ.get("GITHUB_USERNAME"), 
                        help="GitHub username to scan (default: from .env).")
    parser.add_argument("--cache-dir", default=CACHE_DIR, help="Directory for caching repository clones.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--force-full", action="store_true", help="Force a full scan for all repos.")
    
    parser.add_argument("--limit", type=int, default=None, help="Limit the number of repositories to scan.")
    
    args = parser.parse_args()
    username = args.username
    
    if not username:
        print("Error: No GitHub username provided. Set GITHUB_USERNAME in .env or pass as argument.")
        sys.exit(1)

    print(f"Checking for updates in GitHub profile: {username}")
    
    # Initialize state and cache
    state = load_state()
    cache_base = Path(args.cache_dir).resolve()
    cache_base.mkdir(exist_ok=True)
    
    # Initialize notifier
    notifier = EmailNotifier()
    all_important_findings = []

    # Fetch repositories
    repos = get_user_repositories(username, limit=args.limit)
    print(f"Found {len(repos)} repositories.")

    for repo in repos:
        name = repo["name"]
        url = repo["clone_url"]
        target_dir = cache_base / name
        default_branch = repo.get("default_branch", "main")
        
        # Migration: if state[name] is a string, convert it to a dict
        repo_state = state.get(name, {})
        if isinstance(repo_state, str):
            repo_state = {default_branch: repo_state}
            state[name] = repo_state
        
        if args.verbose:
            print(f"\nProcessing {name}...")
        
        # Clone or update
        try:
            if not target_dir.exists():
                print(f"Cloning {name} for the first time...")
                subprocess.run(["git", "clone", url, str(target_dir)], 
                               check=True, capture_output=True)
            else:
                if args.verbose:
                    print(f"Fetching updates for {name}...")
                subprocess.run(["git", "-C", str(target_dir), "fetch", "--all"], 
                               check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            print(f"Error updating {name}: {exc.stderr.decode() if exc.stderr else 'Unknown error'}")
            continue

        # Discover all branches
        branches = get_remote_branches(str(target_dir))
        if not branches:
            branches = [default_branch]
            
        for branch in branches:
            try:
                # Get current commit for this branch
                current_commit = get_branch_head(str(target_dir), branch)
                last_commit = repo_state.get(branch)
                
                if current_commit == last_commit and not args.force_full:
                    continue
                
                print(f"Changes detected for {name} [{branch}]: {last_commit[:8] if last_commit else 'Initial'} -> {current_commit[:8]}")
                
                # Switch to the branch
                subprocess.run(["git", "-C", str(target_dir), "reset", "--hard", f"origin/{branch}"], 
                               check=True, capture_output=True)
                
                # Determine scan mode
                scan_mode = "incremental" if last_commit and not args.force_full else "full"
                since = last_commit if scan_mode == "incremental" else None
                
                # Run scan
                exit_code, report = run_scan(
                    target=str(target_dir),
                    scan_mode=scan_mode,
                    since=since,
                    verbose=args.verbose,
                    return_report=True
                )
                
                if exit_code == 2:
                    print(f"Error during scan of {name} [{branch}].")
                    continue

                from src.patterns import Severity
                critical_findings = report.findings_by_severity.get(Severity.CRITICAL, [])
                high_findings = report.findings_by_severity.get(Severity.HIGH, [])
                
                if critical_findings or high_findings:
                    print(f"Findings detected in {name} [{branch}]: {len(critical_findings)} CRITICAL, {len(high_findings)} HIGH")
                    all_important_findings.extend([(name, branch, f) for f in critical_findings])
                    all_important_findings.extend([(name, branch, f) for f in high_findings])
                elif exit_code == 0:
                    if args.verbose:
                        print(f"Scan clean for {name} [{branch}].")
                
                # Update state for this branch
                repo_state[branch] = current_commit
                state[name] = repo_state
                
            except subprocess.CalledProcessError as exc:
                print(f"Error processing branch {branch} in {name}: {exc.stderr.decode() if exc.stderr else 'Unknown error'}")
                continue

    # Save final state
    save_state(state)
    
    # Notify if critical/high findings found
    if all_important_findings and notifier.is_configured():
        print(f"\nSending consolidated email alert for {len(all_important_findings)} findings...")
        
        # Group findings by repo for the email body
        body = f"Security Scan Alert for GitHub Profile: {username}\n"
        body += "=" * 60 + "\n\n"
        body += "Potential secrets were detected across the following repositories:\n\n"
        
        current_repo_branch = None
        for repo_name, branch_name, finding in all_important_findings:
            if (repo_name, branch_name) != current_repo_branch:
                body += f"\n--- Repository: {repo_name} [Branch: {branch_name}] ---\n"
                current_repo_branch = (repo_name, branch_name)
            
            # Use raw aggregator to get severity value for display
            # Use raw aggregator to get severity value for display
            sev = finding.matched_secret_type
            
            body += f"[{sev}] {finding.matched_secret_type} in {finding.file_path.replace(str(cache_base / repo_name), '').lstrip('/')}:{finding.line_number}\n"
            body += f"  Matched: ...{finding.matched_text}...\n"
        
        body += "\n\nACTION REQUIRED: Please review and rotate these secrets immediately."
        
        notifier.send_alert(f"SECURITY ALERT: Secrets detected in GitHub profile {username}", body)
    elif all_important_findings:
        print(f"\nATTENTION: {len(all_important_findings)} findings detected, but email is not configured.")

    print("\nScan process complete.")

if __name__ == "__main__":
    main()
