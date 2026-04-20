#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SBIN_DIR="${SBIN_DIR:-$PREFIX/sbin}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
STOP_SERVICE=0

usage() {
  cat <<'EOF'
usage: scripts/uninstall-systemd.sh [--stop]

Removes bloomd binaries and the systemd unit that were installed under
/usr/local by default. It does not delete pinned maps or metadata under
/sys/fs/bpf/bloomd or /var/lib/bloomd.

Options:
  --stop    stop and disable bloomd.service before removing files

Environment overrides:
  PREFIX
  SBIN_DIR
  BIN_DIR
  UNIT_DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stop)
      STOP_SERVICE=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this uninstaller must run as root" >&2
  exit 1
fi

if [[ "$STOP_SERVICE" -eq 1 ]]; then
  systemctl disable --now bloomd.service >/dev/null 2>&1 || true
fi

rm -f \
  "$SBIN_DIR/bloomd" \
  "$BIN_DIR/bloomctl" \
  "$BIN_DIR/bloominspect"
rm -f "$UNIT_DIR/bloomd.service"

systemctl daemon-reload

echo "removed bloomd install artifacts from:"
echo "  $SBIN_DIR"
echo "  $BIN_DIR"
echo "  $UNIT_DIR/bloomd.service"
