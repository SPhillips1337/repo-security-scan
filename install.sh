#!/bin/bash
set -e

REPO="SPhillips1337/repo-security-scan"
INSTALL_DIR="${HOME}/.repo-security-scan"
BIN_DIR="${HOME}/.local/bin"

echo "Installing Repo Security Scanner..."

# Create install directory
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Download the latest source via git archive
TEMP_DIR=$(mktemp -d)
echo "Downloading source..."
git clone --depth 1 "https://github.com/$REPO.git" "$TEMP_DIR/repo-security-scan" 2>/dev/null || {
    echo "Error: Failed to clone repository"
    exit 1
}

# Copy files to install directory
cp -r "$TEMP_DIR/repo-security-scan/"* "$INSTALL_DIR/"
rm -rf "$TEMP_DIR"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install pyyaml requests python-dotenv -q

# Create convenience script in PATH
cat > "$BIN_DIR/repo-scan" << 'SCRIPT'
#!/bin/bash
python "$HOME/.repo-security-scan/main.py" "$@"
SCRIPT
chmod +x "$BIN_DIR/repo-scan"

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  $BIN_DIR/repo-scan <directory>    # Scan a directory"
echo "  python $INSTALL_DIR/main.py --help # Full help"
echo ""
echo "Add $BIN_DIR to your PATH to use 'repo-scan' from anywhere."