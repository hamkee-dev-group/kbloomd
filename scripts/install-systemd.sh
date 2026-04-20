#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SBIN_DIR="${SBIN_DIR:-$PREFIX/sbin}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
ENABLE_SERVICE=0
START_SERVICE=0

usage() {
  cat <<'EOF'
usage: scripts/install-systemd.sh [--enable] [--start]

Builds bloomd, installs the runtime binaries under /usr/local by default,
installs the systemd unit into /etc/systemd/system, and runs
systemctl daemon-reload.

Options:
  --enable   enable bloomd.service
  --start    restart (or start) bloomd.service after install

Environment overrides:
  PREFIX
  SBIN_DIR
  BIN_DIR
  UNIT_DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable)
      ENABLE_SERVICE=1
      ;;
    --start)
      START_SERVICE=1
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
  echo "this installer must run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"
make all

install -d "$SBIN_DIR" "$BIN_DIR" "$UNIT_DIR"
install -m 0755 build/bloomd "$SBIN_DIR/bloomd"
install -m 0755 build/bloomctl "$BIN_DIR/bloomctl"
install -m 0755 build/bloominspect "$BIN_DIR/bloominspect"
install -m 0644 systemd/bloomd.service "$UNIT_DIR/bloomd.service"

mkdir -p /sys/fs/bpf/bloomd /var/lib/bloomd

systemctl daemon-reload

if [[ "$ENABLE_SERVICE" -eq 1 ]]; then
  systemctl enable bloomd.service
fi

if [[ "$START_SERVICE" -eq 1 ]]; then
  systemctl restart bloomd.service
fi

echo "installed bloomd:"
echo "  daemon: $SBIN_DIR/bloomd"
echo "  client: $BIN_DIR/bloomctl"
echo "  admin:  $BIN_DIR/bloominspect"
echo "  unit:   $UNIT_DIR/bloomd.service"
