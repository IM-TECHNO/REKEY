#!/bin/sh
# Install the Rekey CLI on Linux: download the binary for this machine, check its SHA-256 against the
# release's SHA256SUMS, and put it on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/IM-TECHNO/REKEY/main/scripts/install.sh | sh
#
# Settings (environment variables, all optional):
#   REKEY_VERSION      a CLI version such as 0.1.0 (default: the latest release)
#   REKEY_INSTALL_DIR  where to put it (default: /usr/local/bin if writable, else ~/.local/bin)
#   REKEY_REPO         GitHub owner/name to download from (default: IM-TECHNO/REKEY)
#   REKEY_BASE_URL     a mirror folder holding the binary and SHA256SUMS (overrides the two above)
set -eu

REPO="${REKEY_REPO:-IM-TECHNO/REKEY}"
VERSION="${REKEY_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
die() { printf 'rekey install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux; on other systems use: pipx install \"git+https://github.com/$REPO.git#subdirectory=cli\""

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "no prebuilt binary for $(uname -m); use: pipx install \"git+https://github.com/$REPO.git#subdirectory=cli\"" ;;
esac
name="rekey-linux-$arch"

if [ -n "${REKEY_BASE_URL:-}" ]; then
  base="${REKEY_BASE_URL%/}"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/cli-v${VERSION#v}"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https,file' -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  die "need sha256sum or shasum to verify the download"
fi

if [ -n "${REKEY_INSTALL_DIR:-}" ]; then
  dir="$REKEY_INSTALL_DIR"
elif [ -w /usr/local/bin ]; then
  dir=/usr/local/bin
else
  dir="$HOME/.local/bin"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $name ($VERSION)..."
fetch "$base/$name" "$tmp/$name" || die "could not download $base/$name"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/SHA256SUMS"

want="$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "$name is not listed in SHA256SUMS"
[ "$(sha "$tmp/$name")" = "$want" ] || die "checksum mismatch for $name; nothing was installed"

mkdir -p "$dir" 2>/dev/null || die "cannot create $dir (set REKEY_INSTALL_DIR, or run with sudo)"
[ -w "$dir" ] || die "cannot write to $dir (set REKEY_INSTALL_DIR, or run with sudo)"
chmod 755 "$tmp/$name"
mv "$tmp/$name" "$dir/rekey"

say "Installed $dir/rekey ($("$dir/rekey" --version 2>/dev/null || echo unknown))"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, e.g.: export PATH=\"$dir:\$PATH\"" ;;
esac
say "Next: rekey login --server https://<your rekey host>"
