#!/usr/bin/env sh
# 1-Line Zero-Config macOS / Linux Installer for `ap` (agent-primitives)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.sh | sh
set -eu

REPO="${AP_REPO:-xgbtxy/ap}"
VERSION="${AP_VERSION:-latest}"
BIN_DIR="${AP_INSTALL_DIR:-$HOME/.local/bin}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) TARGET="" ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64|amd64) TARGET="x86_64-apple-darwin" ;;
      *) TARGET="" ;;
    esac
    ;;
  *)
    TARGET=""
    ;;
esac

mkdir -p "$BIN_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

INSTALLED=0
if [ -n "$TARGET" ]; then
  ARCHIVE="ap-${TARGET}.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  echo "[ap install] Downloading prebuilt native binary ${ARCHIVE} ..."
  if curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}" 2>/dev/null; then
    if curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS" 2>/dev/null; then
      EXPECTED="$(grep " ${ARCHIVE}\$" "${TMP_DIR}/SHA256SUMS" | awk '{print $1}' || true)"
      if [ -n "$EXPECTED" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
          ACTUAL="$(sha256sum "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
          ACTUAL="$(shasum -a 256 "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')"
        else
          ACTUAL="$EXPECTED"
        fi
        if [ "$EXPECTED" != "$ACTUAL" ]; then
          echo "[ap install] SHA-256 checksum mismatch for ${ARCHIVE}!" >&2
          exit 1
        fi
      fi
    fi
    tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
    install -m 0755 "${TMP_DIR}/ap" "${BIN_DIR}/ap"
    INSTALLED=1
  fi
fi

if [ "$INSTALLED" -eq 0 ]; then
  if command -v cargo >/dev/null 2>&1; then
    echo "[ap install] Building from Rust source via cargo ..."
    cargo install --git "https://github.com/${REPO}.git" --bin ap --locked --root "${TMP_DIR}/cargo"
    install -m 0755 "${TMP_DIR}/cargo/bin/ap" "${BIN_DIR}/ap"
  else
    echo "[ap install] No prebuilt binary for ${OS}/${ARCH} and cargo is not installed." >&2
    exit 1
  fi
fi

ORIG_PATH="${PATH:-}"
export PATH="${BIN_DIR}:${PATH}"
if [ "$#" -gt 0 ]; then
  "${BIN_DIR}/ap" init "$@"
else
  "${BIN_DIR}/ap" init
fi

echo ""
echo "----------------------------------------------------------------"
echo "[ap] Ready! Your coding agents are now accelerated."
echo "  -> Next step : Open your coding agent and chat normally (0 new commands needed)"
echo "  -> Check env : ap doctor"
echo "  -> View gains: ap stats   (see saved tokens & compressed logs)"
case ":${ORIG_PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) echo "  -> Add to PATH (restart shell or run): export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
echo "----------------------------------------------------------------"
