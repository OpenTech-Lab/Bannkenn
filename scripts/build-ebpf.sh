#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/agent/ebpf/containment.bpf.c"
OUT="${BANNKENN_EBPF_OUT:-$ROOT_DIR/agent/ebpf/bannkenn-containment.bpf.o}"
CC="${CC:-clang}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build-ebpf.sh [--out PATH]

Options:
  --out PATH   Write the compiled BPF object to PATH
  -h, --help   Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || {
        printf 'missing value for --out\n' >&2
        exit 1
      }
      OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

command -v "$CC" >/dev/null 2>&1 || {
  printf 'required compiler not found: %s\n' "$CC" >&2
  exit 1
}

[[ -f /usr/include/linux/bpf.h ]] || {
  printf 'missing /usr/include/linux/bpf.h; install linux headers/libc headers first\n' >&2
  exit 1
}

INCLUDE_ARGS=()
if command -v gcc >/dev/null 2>&1; then
  MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
  if [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]]; then
    INCLUDE_ARGS+=(-I "/usr/include/$MULTIARCH")
  fi
fi

mkdir -p "$(dirname "$OUT")"

"$CC" \
  "${INCLUDE_ARGS[@]}" \
  -O2 \
  -g \
  -target bpf \
  -Wall \
  -Werror \
  -c "$SRC" \
  -o "$OUT"

printf 'Built %s\n' "$OUT"
