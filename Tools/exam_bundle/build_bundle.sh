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

PYVER="3.12.10"
PYVER_SHORT="312"

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/wheels"
mkdir -p "$BUNDLE/tools"
mkdir -p "$BUNDLE/badchars/examples"
mkdir -p "$BUNDLE/templates"
mkdir -p "$BUNDLE/payloads"
mkdir -p "$BUNDLE/convert"
mkdir -p "$BUNDLE/reference"
mkdir -p "$BUNDLE/python"

# ============================================================
# 1. Python embeddable package (win32)
# ============================================================
PYZIP="python-${PYVER}-embed-win32.zip"
PYURL="https://www.python.org/ftp/python/${PYVER}/${PYZIP}"
GETPIP_URL="https://bootstrap.pypa.io/get-pip.py"

download() {
    local url="$1" dest="$2"
    rm -f "$dest"
    if command -v curl &>/dev/null; then
        curl -fSL -o "$dest" "$url" 2>/dev/null && return 0
    fi
    if command -v wget &>/dev/null; then
        wget -q -O "$dest" "$url" 2>/dev/null && return 0
    fi
    rm -f "$dest"
    return 1
}

echo "[*] Downloading Python ${PYVER} embeddable (win32)..."
if download "$PYURL" "$BUNDLE/python/${PYZIP}"; then
    echo "    [+] ${PYZIP} ($(du -h "$BUNDLE/python/${PYZIP}" | cut -f1))"
else
    echo "    [!] Could not download Python embed zip. Bundle will rely on system Python."
fi

echo "[*] Downloading get-pip.py..."
if download "$GETPIP_URL" "$BUNDLE/python/get-pip.py"; then
    echo "    [+] get-pip.py"
else
    echo "    [!] Could not download get-pip.py."
fi

# ============================================================
# 2. Keystone wheels for Windows x86
# ============================================================
echo "[*] Downloading keystone-engine wheels for win32..."
for pyver in 37 38 39 310 311 312 313; do
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
ls -1 "$BUNDLE/wheels/" 2>/dev/null || echo "    (none)"

# ============================================================
# 3. Recon binary (Go, cross-compiled for Windows x86)
# ============================================================
echo "[*] Copying recon.exe..."
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

# ============================================================
# 4. Bad character automation
# ============================================================
echo "[*] Copying bad character tools..."
cp "$REPO_ROOT/Tools/badchars/standalone/badchar_auto.py" "$BUNDLE/badchars/"
cp "$REPO_ROOT/Tools/badchars/standalone/examples/"*.py "$BUNDLE/badchars/examples/" 2>/dev/null || true
cp "$REPO_ROOT/Tools/badchars/scripts/badchar_bp.wds" "$BUNDLE/badchars/" 2>/dev/null || true

# ============================================================
# 5. Exploit templates (standalone, stdlib only)
# ============================================================
echo "[*] Copying exploit templates..."
for tmpl in stack_bof seh_exploit dep_bypass egghunter format_string aslr_leak badchars_ref; do
    src="$REPO_ROOT/exam/templates/${tmpl}.py"
    if [ -f "$src" ]; then
        cp "$src" "$BUNDLE/templates/"
        echo "    [+] templates/${tmpl}.py"
    fi
done
cp "$REPO_ROOT/exam/templates/README.md" "$BUNDLE/templates/" 2>/dev/null || true

# ============================================================
# 6. Payload helpers (standalone ones)
# ============================================================
echo "[*] Copying payload helpers..."
for payload in eip_check vp_skeleton; do
    src="$REPO_ROOT/exam/payloads/${payload}.py"
    if [ -f "$src" ]; then
        cp "$src" "$BUNDLE/payloads/"
        echo "    [+] payloads/${payload}.py"
    fi
done

# ============================================================
# 7. Value conversion scripts (standalone, stdlib only)
# ============================================================
echo "[*] Copying conversion tools..."
cp "$REPO_ROOT/Tools/Value_Conversion_Scripts/string2hex.py" "$BUNDLE/convert/"
cp "$REPO_ROOT/Tools/Value_Conversion_Scripts/opcode.py" "$BUNDLE/convert/"
echo "    [+] convert/string2hex.py  (string/ip/sockaddr -> hex)"
echo "    [+] convert/opcode.py      (API name -> ROR13 hash)"

# ============================================================
# 8. TCP stage server (runs on Kali, copy for reference)
# ============================================================
echo "[*] Copying staging tools..."
cp "$REPO_ROOT/Tools/tcp_stage_server.py" "$BUNDLE/tools/"

# ============================================================
# 9. Reference documentation
# ============================================================
echo "[*] Copying reference documentation..."

copy_ref() {
    local src="$1" dest="$2"
    if [ -f "$src" ]; then
        cp "$src" "$BUNDLE/reference/$dest"
        echo "    [+] reference/$dest"
    else
        echo "    [-] $dest not found, skipping"
    fi
}

# WinDbg
copy_ref "$REPO_ROOT/Documentation/WinDbg/Commands_Reference.md" \
         "WinDbg_Commands.md"
copy_ref "$REPO_ROOT/Documentation/WinDbg/Shellcode_Debugging.md" \
         "WinDbg_Shellcode_Debugging.md"
copy_ref "$REPO_ROOT/Documentation/WinDbg/Structure_Inspection.md" \
         "WinDbg_Structure_Inspection.md"

# DEP bypass
copy_ref "$REPO_ROOT/Documentation/Windows/DEP/OSED_DEP_Bypass_CheatSheet.md" \
         "DEP_Bypass_CheatSheet.md"
copy_ref "$REPO_ROOT/Documentation/Windows/DEP/ROP_Chain_Design_Worksheet.md" \
         "ROP_Chain_Design_Worksheet.md"

# Egghunters
copy_ref "$REPO_ROOT/Documentation/Windows/Egghunters/Egghunter_Quick_Reference.md" \
         "Egghunter_Quick_Reference.md"

# SEH
copy_ref "$REPO_ROOT/Documentation/Windows/SEH/SEH_Exploitation.md" \
         "SEH_Exploitation.md"

# Bad characters
copy_ref "$REPO_ROOT/Documentation/OSED_x86_Bad_Character_Quick_Reference.md" \
         "Bad_Character_Quick_Reference.md"
copy_ref "$REPO_ROOT/Documentation/Windows/Protocol_Badchars_Reference.md" \
         "Protocol_Badchars_Reference.md"

# Shellcode
copy_ref "$REPO_ROOT/Documentation/windows_x86_shellcode/Shellcode_Reference.md" \
         "Shellcode_Reference.md"
copy_ref "$REPO_ROOT/Documentation/OSED_Emitter_Exam_Guide.md" \
         "Emitter_Exam_Guide.md"
copy_ref "$REPO_ROOT/Documentation/windows_x86_shellcode/osed_exam_day_checklist.md" \
         "Exam_Day_Checklist.md"

# Gadgets
copy_ref "$REPO_ROOT/Documentation/Windows/Gadget_Byte_Patterns.md" \
         "Gadget_Byte_Patterns.md"

# Assembly quick reference
copy_ref "$REPO_ROOT/Documentation/x86-osed-assembly-reference/27-fast-reference-tables.md" \
         "x86_Fast_Reference_Tables.md"

# ============================================================
# 10. Install script and README
# ============================================================
cp "$SCRIPT_DIR/install.bat" "$BUNDLE/"
cp "$SCRIPT_DIR/EXAM_README.txt" "$BUNDLE/"

# ============================================================
# 11. Package
# ============================================================
echo "[*] Creating zip..."
cd "$SCRIPT_DIR/dist"
rm -f exam_bundle.zip
zip -r exam_bundle.zip exam_bundle/

SIZE=$(du -sh exam_bundle.zip | cut -f1)
NFILES=$(find exam_bundle -type f | wc -l | tr -d ' ')
echo ""
echo "[+] Bundle ready: $SCRIPT_DIR/dist/exam_bundle.zip ($SIZE, $NFILES files)"
echo ""
echo "[+] Contents:"
echo "    python/          Python ${PYVER} embeddable (win32) + get-pip.py"
echo "    wheels/          Keystone-engine wheels (offline pip install)"
echo "    tools/           recon.exe, tcp_stage_server.py"
echo "    badchars/        badchar_auto.py + WinDbg script + examples"
echo "    templates/       Exploit templates (stack, SEH, DEP, egghunter, fmt, ASLR)"
echo "    payloads/        Payload helpers (eip_check, vp_skeleton)"
echo "    convert/         string2hex.py, opcode.py (shellcode value helpers)"
echo "    reference/       Cheat sheets and quick references (Markdown)"
echo ""
echo "[+] Transfer to exam box via SMB:"
echo "    impacket-smbserver kalismb . -smb2support"
echo "    (on Windows) copy \\\\<kali_ip>\\kalismb\\exam_bundle.zip C:\\exam\\"
