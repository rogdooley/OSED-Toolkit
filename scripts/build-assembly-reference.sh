#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC_DIR="$REPO_ROOT/Documentation/x86-osed-assembly-reference"
METADATA="$SRC_DIR/metadata.yaml"
OUT="$REPO_ROOT/Documentation/x86-osed-assembly-reference.pdf"

if [ ! -d "$SRC_DIR" ]; then
    echo "ERROR: Source directory not found: $SRC_DIR" >&2
    exit 1
fi

if ! command -v pandoc &>/dev/null; then
    echo "ERROR: pandoc is required but not found. Install with: brew install pandoc" >&2
    exit 1
fi

# Detect available PDF engine
PDF_ENGINE=""
for engine in pdflatex xelatex lualatex; do
    if command -v "$engine" &>/dev/null; then
        PDF_ENGINE="$engine"
        break
    fi
done

if [ -z "$PDF_ENGINE" ]; then
    echo "ERROR: No PDF engine found. Install a TeX distribution:" >&2
    echo "  brew install --cask mactex-no-gui" >&2
    echo "  or: brew install basictex" >&2
    exit 1
fi

# Collect section files in sort order (numeric prefix controls sequence)
SECTION_FILES=()
for f in "$SRC_DIR"/[0-9][0-9]-*.md; do
    [ -f "$f" ] && SECTION_FILES+=("$f")
done

if [ ${#SECTION_FILES[@]} -eq 0 ]; then
    echo "ERROR: No section files found in $SRC_DIR" >&2
    exit 1
fi

echo "Building PDF with pandoc + $PDF_ENGINE (${#SECTION_FILES[@]} sections) ..."

# Build pandoc args array
ARGS=(
    -o "$OUT"
    --pdf-engine="$PDF_ENGINE"
    --toc
    --toc-depth=2
    -V "geometry:margin=0.75in"
    -V "fontsize=10pt"
    -V "linkcolor=blue"
    -N
)

# Include metadata if present
if [ -f "$METADATA" ]; then
    ARGS+=("--metadata-file=$METADATA")
fi

# Add header/footer via fancyhdr
HEADER_TEX='\usepackage{fancyhdr}\pagestyle{fancy}\fancyhead[L]{x86 Assembly Reference for OSED}\fancyhead[R]{\thepage}\fancyfoot[C]{}'
ARGS+=(-V "header-includes=${HEADER_TEX}")

# Engine-specific font options
if [ "$PDF_ENGINE" = "pdflatex" ]; then
    ARGS+=(-V "header-includes=\\usepackage[T1]{fontenc}")
    ARGS+=(-V "header-includes=\\usepackage{inconsolata}")
elif [ "$PDF_ENGINE" = "xelatex" ] || [ "$PDF_ENGINE" = "lualatex" ]; then
    ARGS+=(-V "mainfont=Liberation Sans")
    ARGS+=(-V "monofont=Source Code Pro")
fi

# Syntax highlighting
if pandoc --help 2>&1 | grep -q -- '--syntax-highlighting'; then
    ARGS+=(--syntax-highlighting=tango)
else
    ARGS+=(--highlight-style=tango)
fi

# Pass all section files as inputs (pandoc concatenates them with \newpage between)
pandoc "${ARGS[@]}" "${SECTION_FILES[@]}"

echo "Built: $OUT"
echo "Size: $(du -h "$OUT" | cut -f1)"
