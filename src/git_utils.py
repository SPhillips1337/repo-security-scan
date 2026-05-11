"""
Git Integration Utilities

Provides functions to interface with the local Git repository to identify
changed files and commit history for incremental scanning.
"""

import subprocess
from pathlib import Path
from typing import List, Optional


def is_git_repo(repo_path: str) -> bool:
    """Check if the given path is a valid Git repository."""
    path = Path(repo_path).resolve()
    git_dir = path / ".git"
    return git_dir.is_dir()


def get_changed_files(repo_path: str, base_ref: str = "HEAD~1", target_ref: str = "HEAD") -> List[str]:
    """Get a list of files changed between two Git references.

    Args:
        repo_path: Path to the local Git repository.
        base_ref: The base commit or branch to compare from.
        target_ref: The target commit or branch to compare to.

    Returns:
        List of absolute file paths that were added or modified.
    """
    if not is_git_repo(repo_path):
        raise ValueError(f"'{repo_path}' is not a Git repository.")

    try:
        # Get list of changed files (Added, Modified, Renamed, Type-changed)
        # --diff-filter=AMRT excludes Deleted (D) files as they don't exist anymore
        cmd = [
            "git", "-C", repo_path, "diff", "--name-only", "--diff-filter=AMRT",
            f"{base_ref}..{target_ref}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        relative_paths = result.stdout.strip().split("\n")
        # Filter out empty strings if no files changed
        relative_paths = [p for p in relative_paths if p]
        
        return [str(Path(repo_path) / p) for p in relative_paths]

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to get changed files from Git: {exc.stderr}")


def get_latest_commits(repo_path: str, count: int = 5) -> List[dict]:
    """Get metadata for the most recent commits.

    Returns:
        List of dicts with 'hash', 'author', 'date', and 'message'.
    """
    if not is_git_repo(repo_path):
        return []

    try:
        # Format: hash|author|date|message
        cmd = [
            "git", "-C", repo_path, "log", f"-n{count}", 
            "--pretty=format:%H|%an|%ad|%s", "--date=iso"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        commits = []
        for line in result.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split("|")
            if len(parts) >= 4:
                commits.append({
                    "hash": parts[0],
                    "author": parts[1],
                    "date": parts[2],
                    "message": "|".join(parts[3:]) # handle messages containing pipes
                })
        return commits
    except subprocess.CalledProcessError:
        return []
