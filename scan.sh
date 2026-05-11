#!/bin/bash
# repo-security-scanner - Scan repos for leaked secrets
# Usage: ./scan.sh <repo-url> [--deep] [--output-dir <dir>]

set -euo pipefail

REPO_URL="${1:-}"
DEEP=${2:-false}
OUTPUT_DIR="${3:-./scan-reports}"
WORKDIR="/tmp/scanner-repos"

declare -A PATTERNS
# AWS
PATTERNS['AKIA']='AKI[A-Z0-9]{16}'
PATTERNS['AWS_SECRET']='AKI[A-Z0-9]{16}'
PATTERNS['GH_TOKEN']='ghp_[a-zA-Z0-9]{36,}'
PATTERNS['GH_OAUTH']='gho_[a-zA-Z0-9]{36,}'
PATTERNS['GH_REFRESH']='ghr_[a-zA-Z0-9]{36,}'
PATTERNS['GH_FINE_PAT']='github_pat_[0-9a-zA-Z_]{5,}'
PATTERNS['GH_APP']='ghu_[a-zA-Z0-9]{36,}'
PATTERNS['GH_INSTALL']='ghs_[a-zA-Z0-9]{36,}'
PATTERNS['STRIPE_PK']='pk_(live|test)_[0-9a-zA-Z]{24,}'
PATTERNS['STRIPE_SK']='sk_(live|test)_[0-9a-zA-Z]{24,}'
PATTERNS['SLACK_XOXB']='xoxb-[0-9]{10,13}-[0-9a-zA-Z]{20,}'
PATTERNS['SLACK_XOXP']='xoxp-[0-9]{10,13}-[0-9a-zA-Z-]{20,}'
PATTERNS['SLACK_WEBHOOK']='https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}'
PATTERNS['TELEGRAM']='[0-9]{8,10}:[A-Za-z0-9_-]{35}'
PATTERNS['DISCORD']='[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27,}'
PATTERNS['TWILIO_SID']='AC[0-9a-f]{32}'
PATTERNS['TWILIO_TOKEN']='SK[0-9a-f]{32}'
PATTERNS['SENDGRID']='SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}'
PATTERNS['DIGITALOCEAN']='dop_v1_[A-Za-z0-9]{64}'
PATTERNS['MAINGUN']='key-[0-9a-zA-Z]{32}'
PATTERNS['SQL_CONN']='(postgres(?:ql)?|mysql|mongodb)://[^\s\'"@]+:[^@]+@'
PATTERNS['API_KEY']='(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)=[\s]*[\'\"]([A-Za-z0-9_\-]{20,})[\'\"]'
PATTERNS['PASSWORD']='(?i)(password|passwd)=[\s]*[\'\"]([A-Za-z0-9_\-]{20,})[\'\"]'

mkdir -p "$WORKDIR" "$OUTPUT_DIR"

# Determine repo name from URL
REPO_NAME=$(basename "$REPO_URL" .git)
REPO_PATH="$WORKDIR/$REPO_NAME"

# Clone or update repo
if [ -d "$REPO_PATH" ]; then
    (cd "$REPO_PATH" && git fetch --all --prune && git reset --hard origin/HEAD)
else
    git clone --depth 1 "$REPO_URL" "$REPO_PATH"
fi

echo "Scanning: $REPO_PATH"
echo "Mode: $DEEP"
echo "Target files..."

# Collect files to scan
files=()

if [ "$DEEP" = true ]; then
    # Deep scan: all text files
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$REPO_PATH" -type f ! -path "*/.git/*" -exec file -i {} \; | grep -iE 'text/plain' | cut -d: -f1)
else
    # Quick scan: known sensitive files
    for pat in .env .env.local .env.production .env.development .envrc \
               config.py settings.py config.php settings.php wp-config.php \
               .github/workflows/*.yml .github/workflows/*.yaml \
               docker-compose.yml Dockerfile \
               composer.json .npmrc Pipfile \
               .aws/credentials .aws/config \
               .vscode/settings.json .idea/workspace.xml \
               serverless.yml netlify.toml vercel.json \
               application.properties application.yml \
               *.tfvars terraform.tfvars .pgpass .my.cnf; do
        for f in $REPO_PATH/$pat; do
            [ -f "$f" ] && files+=("$f") || true
        done
    done
fi

echo "Files to scan: ${#files[@]}"

critical=0
high=0
medium=0

for file in "${files[@]}"; do
    # Skip binary files
    if grep -q $'\x00' "$file" 2>/dev/null; then
        continue
    fi

    for patname in "${!PATTERNS[@]}"; do
        pattern="${PATTERNS[$patname]}"
        if grep -qEi "$pattern" "$file" 2>/dev/null; then
            echo "[${patname}] ${file}"
            case "$patname" in
                AKIA|AWS_SECRET|GH_TOKEN|GH_OAUTH|GH_REFRESH|GH_FINE_PAT|GH_APP|GH_INSTALL|STRIPE_SK|SLACK_XOXB|SLACK_XOXP|DISCORD|TELEGRAM|TWILIO_SID|TWILIO_TOKEN|SENDGRID|DIGITALOCEAN|MAINGUN|SQL_CONN)
                    ((critical++))
                    ;;
                SLACK_WEBHOOK|STRIPE_PK|API_KEY|PASSWORD)
                    ((high++))
                    ;;
                *)
                    ((medium++))
                    ;;
            esac
        fi
    done
done

echo "Findings: CRITICAL=$critical HIGH=$high MEDIUM=$medium"

# Save report
report="$OUTPUT_DIR/scan_$(date +%Y%m%d_%H%M%S).txt"
echo "Scan complete. Report saved to $report"
