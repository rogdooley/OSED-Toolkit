#!/bin/bash
# build_bundle.sh - Prepare the OSED exam bundle on Kali
#
# Downloads Python wheels for Windows x86 and packages everything
# into a zip ready to transfer via SMB.
#
# Usage:
#   cd Tools/exam_bundle
#   ./build_bundle.sh
#
# Output: exam_bundle.zip (transfer this to the exam box)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUNDLE="$SCRIPT_DIR/dist/exam_bundle"

# Find pip (Kali uses pip3 by default)
PIP="pip"
if ! command -v pip &>/dev/null; then
    PIP="pip3"
fi

echo "[*] Building OSED exam bundle..."

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/wheels" "$BUNDLE/tools" "$BUNDLE/badchars" "$BUNDLE/badchars/examples"

# --- Download keystone wheel for Windows x86 ---
echo "[*] Downloading keystone-engine wheels for win32..."
# Try multiple Python versions the exam box might have
for pyver in 37 38 39 310 311 312; do
    $PIP download keystone-engine \
        --platform win32 \
        --python-version "${pyver:0:1}.${pyver:1}" \
        --only-binary=:all: \
        --no-deps \
        -d "$BUNDLE/wheels/" 2>/dev/null && \
        echo "    [+] Got wheel for cp${pyver}" || \
        echo "    [-] No wheel for cp${pyver} (ok)"
done

echo "[*] Wheels downloaded:"
ls -1 "$BUNDLE/wheels/"

# --- Copy standalone tools ---
echo "[*] Copying standalone tools..."

# Bad character automation
cp "$REPO_ROOT/Tools/badchars/standalone/badchar_auto.py" "$BUNDLE/badchars/"
cp "$REPO_ROOT/Tools/badchars/standalone/examples/"*.py "$BUNDLE/badchars/examples/" 2>/dev/null || true
cp "$REPO_ROOT/Tools/badchars/scripts/badchar_bp.wds" "$BUNDLE/badchars/" 2>/dev/null || true

# Recon binary (Go, pre-compiled for Windows x86)
if [ -f "$REPO_ROOT/Tools/recon/dist/recon.exe" ]; then
    cp "$REPO_ROOT/Tools/recon/dist/recon.exe" "$BUNDLE/tools/"
    echo "    [+] recon.exe (cached)"
elif command -v go &>/dev/null; then
    echo "    [*] Cross-compiling recon.exe for windows/386..."
    (cd "$REPO_ROOT/Tools/recon" && \
        GOOS=windows GOARCH=386 go build -o dist/recon.exe . 2>&1) && \
        cp "$REPO_ROOT/Tools/recon/dist/recon.exe" "$BUNDLE/tools/" && \
        echo "    [+] recon.exe (built)" || \
        echo "    [-] recon.exe build failed, skipping"
else
    echo "    [-] recon.exe not found and Go not installed, skipping"
fi

# TCP stage server (runs on Kali, but useful to have a copy)
cp "$REPO_ROOT/Tools/tcp_stage_server.py" "$BUNDLE/tools/"

# Install script
cp "$SCRIPT_DIR/install.bat" "$BUNDLE/"

# Quick reference
cp "$SCRIPT_DIR/EXAM_README.txt" "$BUNDLE/"

# --- Package ---
echo "[*] Creating zip..."
cd "$SCRIPT_DIR/dist"
rm -f exam_bundle.zip
zip -r exam_bundle.zip exam_bundle/

SIZE=$(du -sh exam_bundle.zip | cut -f1)
echo ""
echo "[+] Bundle ready: $SCRIPT_DIR/dist/exam_bundle.zip ($SIZE)"
echo "[+] Transfer to exam box via SMB:"
echo "    impacket-smbserver kalismb . -smb2support"
echo "    (on Windows) copy \\\\<kali_ip>\\kalismb\\exam_bundle.zip C:\\exam\\"
