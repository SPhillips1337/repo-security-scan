"""
GitHub Utility Module

Provides functions for interacting with the GitHub API to discover repositories.
"""

import requests
import os
from typing import List, Dict, Optional

def get_user_repositories(username: str, token: Optional[str] = None) -> List[Dict[str, str]]:
    """Fetch all public repositories for a given GitHub user.

    Args:
        username: GitHub username (e.g., 'SPhillips1337').
        token: Optional GitHub personal access token for higher rate limits.

    Returns:
        List of dictionaries containing 'name' and 'clone_url'.
    """
    repos = []
    page = 1
    headers = {}
    if token or os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"token {token or os.environ.get('GITHUB_TOKEN')}"

    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
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
                    "clone_url": repo["clone_url"]
                })
        
        page += 1
        
    return repos
