#!/usr/bin/env python3
"""
Scan GitHub Profile
Discovers and scans all repositories for a given GitHub user.
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.github_utils import get_user_repositories
from main import run as run_scan

def main():
    parser = argparse.ArgumentParser(description="Scan all repositories for a GitHub user.")
    parser.add_argument("username", nargs="?", default=os.environ.get("GITHUB_USERNAME"), 
                        help="GitHub username to scan (default: from .env).")
    parser.add_argument("--temp-dir", default="temp_repos", help="Directory for temporary clones.")
    parser.add_argument("--report", default="profile_report.md", help="Path for the generated report.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    
    args = parser.parse_args()
    username = args.username
    
    if not username:
        print("Error: No GitHub username provided. Set GITHUB_USERNAME in .env or pass as argument.")
        sys.exit(1)

    print(f"Fetching repositories for user: {username}...")
    repos = get_user_repositories(username)
    print(f"Found {len(repos)} repositories.")

    temp_base = Path(args.temp_dir).resolve()
    temp_base.mkdir(exist_ok=True)
    
    report_path = Path(args.report).resolve()
    
    with open(report_path, "w") as f:
        f.write(f"# Security Scan Report for GitHub User: {username}\n\n")
        f.write("| Repository | Status | Summary |\n")
        f.write("|------------|--------|---------|\n")

    for repo in repos:
        name = repo["name"]
        url = repo["clone_url"]
        target_dir = temp_base / name
        
        print(f"\nProcessing {name}...")
        
        # Clone
        try:
            subprocess.run(["git", "clone", "--depth", "1", url, str(target_dir)], 
                           check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            print(f"Error cloning {name}: {exc.stderr.decode()}")
            with open(report_path, "a") as f:
                f.write(f"| {name} | ⚠️ ERROR | Failed to clone |\n")
            continue

        # Scan
        exit_code, report = run_scan(
            target=str(target_dir),
            scan_mode="full",
            verbose=args.verbose,
            return_report=True
        )
        
        status = "✅ CLEAN" if exit_code == 0 else "❌ CRITICAL"
        summary = f"Found {report.unique_findings} unique finding(s)." if report.unique_findings > 0 else "No secrets detected."
        
        with open(report_path, "a") as f:
            f.write(f"| [{name}](#{name.lower()}) | {status} | {summary} |\n")
            
        # Cleanup
        shutil.rmtree(target_dir, ignore_errors=True)

    print(f"\nScan complete! Report generated at: {report_path}")

if __name__ == "__main__":
    main()
