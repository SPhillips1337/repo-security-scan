#!/bin/bash

# --- Premium Install Script for Repo Security Scanner ---
# Designed by Antigravity AI

set -e

# Colors for premium look
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ASCII Art Header
echo -e "${CYAN}${BOLD}"
echo "    ____                        _____                      _ __         "
echo "   / __ \___  ____  ____       / ___/___  _______  _______(_) /_  __  __"
echo "  / /_/ / _ \/ __ \/ __ \      \__ \/ _ \/ ___/ / / / ___/ / __/ / / / /"
echo " / _, _/  __/ /_/ / /_/ /     ___/ /  __/ /__/ /_/ / /  / / /_  / /_/ / "
echo "/_/ |_|\___/ .___/\____/     /____/\___/\___/\__,_/_/  /_/\__/  \__, /  "
echo "          /_/                                                  /____/   "
echo -e "                      ${PURPLE}Security Scanning Tool${NC}"
echo ""

# Function to print status messages
status_msg() {
    echo -e "${BLUE}${BOLD}[*]${NC} $1"
}

success_msg() {
    echo -e "${GREEN}${BOLD}[+]${NC} $1"
}

error_msg() {
    echo -e "${RED}${BOLD}[!]${NC} $1"
}

warning_msg() {
    echo -e "${YELLOW}${BOLD}[!]${NC} $1"
}

# 1. Dependency Check
status_msg "Checking environment..."
if ! command -v python3 &> /dev/null; then
    error_msg "Python 3 is not installed. Please install it first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
status_msg "Found Python $PYTHON_VERSION"

# 2. Install optional dependencies
echo -e "\n${BOLD}Optional Dependencies${NC}"
read -p "Do you want to install 'pyyaml' for YAML configuration support? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    status_msg "Installing pyyaml..."
    pip3 install pyyaml || warning_msg "Failed to install pyyaml. YAML config will be disabled."
fi

# 3. Directory Setup
status_msg "Setting up directories..."
mkdir -p scan-reports
success_msg "Created 'scan-reports/' directory."

# 4. Email Configuration
echo -e "\n${BOLD}Email Notification Setup${NC}"
read -p "Would you like to configure email alerts for critical findings? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ ! -f .env ]; then
        cp .env.template .env
    fi
    
    echo -e "${CYAN}Please enter your SMTP details (saved to .env):${NC}"
    read -p "SMTP Server (e.g., smtp.gmail.com): " smtp_server
    read -p "SMTP Port (e.g., 587): " smtp_port
    read -p "SMTP User (Email): " smtp_user
    read -s -p "SMTP Password/App Token: " smtp_pass
    echo
    read -p "Alert Recipient Email: " alert_email

    # Update .env
    sed -i "s/SMTP_SERVER=.*/SMTP_SERVER=$smtp_server/" .env
    sed -i "s/SMTP_PORT=.*/SMTP_PORT=$smtp_port/" .env
    sed -i "s/SMTP_USER=.*/SMTP_USER=$smtp_user/" .env
    sed -i "s/SMTP_PASSWORD=.*/SMTP_PASSWORD=$smtp_pass/" .env
    sed -i "s/ALERT_RECIPIENT=.*/ALERT_RECIPIENT=$alert_email/" .env
    
    success_msg "Email configuration saved to .env"
else
    status_msg "Skipping email configuration."
fi

# 5. Scheduled Scan Setup
echo -e "\n${BOLD}Scheduling Setup${NC}"
read -p "Would you like to schedule a background scan every 15 minutes? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    REPO_PATH=$(pwd)
    PYTHON_CMD=$(which python3)
    CRON_JOB="*/15 * * * * cd $REPO_PATH && $PYTHON_CMD scripts/scheduled_scan.py . --interval 900 >> scan.log 2>&1"
    
    # Check if already in crontab
    if crontab -l 2>/dev/null | grep -q "scheduled_scan.py"; then
        warning_msg "A scheduled scan is already in your crontab."
    else
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        success_msg "Added scheduled scan to crontab."
    fi
else
    status_msg "Skipping scheduling."
fi

# 6. MCP Server Setup
echo -e "\n${BOLD}MCP Server Setup${NC}"
read -p "Do you want to install 'mcp' and 'fastmcp' to use this as an AI tool? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    status_msg "Installing MCP dependencies..."
    pip3 install mcp fastmcp || warning_msg "Failed to install MCP dependencies."
    success_msg "MCP Server 'mcp_server.py' is ready."
fi

# 7. Finalization
echo -e "\n${CYAN}${BOLD}--- Installation Complete! ---${NC}"
echo -e "You can now run the scanner using:"
echo -e "  ${PURPLE}python3 main.py .${NC}"
echo -e ""
echo -e "To perform a deep scan of all files:"
echo -e "  ${PURPLE}python3 main.py --scan-mode full .${NC}"
echo -e ""
echo -e "To start the MCP server for AI assistants:"
echo -e "  ${PURPLE}fastmcp run mcp_server.py${NC}"
echo -e ""
echo -e "Happy Hunting! 🛡️"
echo ""
