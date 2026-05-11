"""
GitHub Utility Module

Provides functions for interacting with the GitHub API to discover repositories.
"""

import requests
import os
from typing import List, Dict, Optional

def get_user_repositories(username: str, token: Optional[str] = None, sort: str = "pushed", direction: str = "desc", limit: Optional[int] = None) -> List[Dict[str, str]]:
    """Fetch public repositories for a given GitHub user.

    Args:
        username: GitHub username (e.g., 'SPhillips1337').
        token: Optional GitHub personal access token for higher rate limits.
        sort: Field to sort by ('created', 'updated', 'pushed', 'full_name').
        direction: Sort direction ('asc', 'desc').
        limit: Maximum number of repositories to return.

    Returns:
        List of dictionaries containing 'name' and 'clone_url'.
    """
    repos = []
    page = 1
    headers = {}
    if token or os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"token {token or os.environ.get('GITHUB_TOKEN')}"

    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}&sort={sort}&direction={direction}"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print(f"Error fetching repositories: {response.status_code} - {response.text}")
            break
            
        data = response.json()
        if not data:
            break
            
        for repo in data:
            if not repo.get("fork"):  # Optional: skip forks
                repos.append({
                    "name": repo["name"],
                    "clone_url": repo["clone_url"],
                    "default_branch": repo.get("default_branch", "main")
                })
                if limit and len(repos) >= limit:
                    return repos
        
        page += 1
        
    return repos
