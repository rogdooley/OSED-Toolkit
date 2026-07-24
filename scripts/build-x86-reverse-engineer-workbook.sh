#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC_DIR="$REPO_ROOT/Documentation/learning-to-read-x86-assembly-like-a-reverse-engineer"
METADATA="$SRC_DIR/metadata.yaml"
OUT="$REPO_ROOT/Documentation/learning-to-read-x86-assembly-like-a-reverse-engineer.pdf"

if [ ! -d "$SRC_DIR" ]; then
    echo "ERROR: Source directory not found: $SRC_DIR" >&2
    exit 1
fi

if ! command -v pandoc &>/dev/null; then
    echo "ERROR: pandoc is required but not found. Install with: brew install pandoc" >&2
    exit 1
fi

PDF_ENGINE=""
for engine in xelatex lualatex pdflatex; do
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

SECTION_FILES=()
for f in "$SRC_DIR"/[0-9][0-9]-*.md; do
    [ -f "$f" ] && SECTION_FILES+=("$f")
done

if [ ${#SECTION_FILES[@]} -eq 0 ]; then
    echo "ERROR: No chapter files found in $SRC_DIR" >&2
    exit 1
fi

echo "Building workbook PDF with pandoc + $PDF_ENGINE (${#SECTION_FILES[@]} chapters) ..."

ARGS=(
    -o "$OUT"
    --pdf-engine="$PDF_ENGINE"
    --toc
    --toc-depth=2
    -V "geometry:margin=1in"
    -V "fontsize=11pt"
    -V "linkcolor=blue"
    -V "documentclass=report"
    -V "classoption=oneside"
    -N
)

if [ -f "$METADATA" ]; then
    ARGS+=("--metadata-file=$METADATA")
fi

HEADER_TEX='\usepackage{fancyhdr}\pagestyle{fancy}\fancyhead[L]{Learning to Read x86 Assembly}\fancyhead[R]{\thepage}\fancyfoot[C]{}\usepackage{fvextra}\DefineVerbatimEnvironment{Highlighting}{Verbatim}{breaklines,breakanywhere,commandchars=\\\{\}}'
ARGS+=(-V "header-includes=${HEADER_TEX}")

if [ "$PDF_ENGINE" = "pdflatex" ]; then
    ARGS+=(-V "header-includes=\\usepackage[T1]{fontenc}")
    ARGS+=(-V "header-includes=\\usepackage{inconsolata}")
else
    ARGS+=(-V "mainfont=Helvetica")
    ARGS+=(-V "monofont=Menlo")
fi

if pandoc --help 2>&1 | grep -q -- '--syntax-highlighting'; then
    ARGS+=(--syntax-highlighting=tango)
else
    ARGS+=(--highlight-style=tango)
fi

pandoc "${ARGS[@]}" "${SECTION_FILES[@]}"

echo "Built: $OUT"
echo "Size: $(du -h "$OUT" | cut -f1)"
