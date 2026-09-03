#!/usr/bin/env bash
# Build recon for the analysis workstation (host) and the Win10 x86 exam box.
# Uses the vendored deps so it works with no network (GOPROXY=off).
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-./dist}"
mkdir -p "$OUT"

FLAGS=(-trimpath -ldflags "-s -w")

echo "[*] host build -> $OUT/recon"
GOPROXY=off GOFLAGS=-mod=vendor go build "${FLAGS[@]}" -o "$OUT/recon" .

echo "[*] win10 x86 build -> $OUT/recon.exe"
GOPROXY=off GOFLAGS=-mod=vendor GOOS=windows GOARCH=386 go build "${FLAGS[@]}" -o "$OUT/recon.exe" .

echo "[*] win10 x64 build -> $OUT/recon64.exe"
GOPROXY=off GOFLAGS=-mod=vendor GOOS=windows GOARCH=amd64 go build "${FLAGS[@]}" -o "$OUT/recon64.exe" .

echo "[+] done:"
ls -la "$OUT"
