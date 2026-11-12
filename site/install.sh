#!/bin/sh
# Keywarden installer for Linux (x86_64) and macOS (Apple Silicon):
#   curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
# Downloads the release archive from GitHub, checks it against SHA256SUMS and installs
# into ~/.local/bin without root. A specific version: ... | KEYWARDEN_VERSION=v0.1.0 sh
# Everything is inside main() so a download cut off halfway runs nothing.
set -eu

main() {
  repo=onokashino/keywarden
  base=${KEYWARDEN_MIRROR:-https://github.com/$repo/releases/download}
  bin=${BIN:-$HOME/.local/bin}

  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=linux-x86_64 ;;
    Darwin-arm64) target=macos-arm64 ;;
    *) die "no ready build for $(uname -s) $(uname -m). Build from source: https://onokashino.github.io/keywarden/docs/#install" ;;
  esac
  need curl
  need tar
  if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then sum="shasum -a 256"
  else die "needs sha256sum or shasum"; fi

  tag=${KEYWARDEN_VERSION:-}
  if [ -z "$tag" ]; then
    # /releases/latest redirects to /releases/tag/vX.Y.Z; no API call, no rate limit
    tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
    tag=${tag##*/}
  fi
  case "$tag" in v[0-9]*) ;; *) die "no published release yet: https://github.com/$repo/releases" ;; esac

  file=keywarden-$tag-$target.tar.gz
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM
  say "downloading Keywarden $tag for $target"
  fetch "$base/$tag/$file" "$tmp/$file"
  fetch "$base/$tag/SHA256SUMS" "$tmp/SHA256SUMS"
  want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
  got=$(cd "$tmp" && $sum "$file" | awk '{ print $1 }')
  [ -n "$want" ] || die "$file is not listed in SHA256SUMS"
  [ "$want" = "$got" ] || die "checksum mismatch for $file, nothing installed"
  tar xzf "$tmp/$file" -C "$tmp"
  dir=$tmp/keywarden-$tag-$target

  if [ "$target" = linux-x86_64 ]; then
    # the archive's own script: binaries, systemd user service, desktop entry, Firefox host
    (cd "$dir" && BIN="$bin" sh ./install.sh)
  else
    mkdir -p "$bin"
    for b in keywardend kw keywarden-ui keywarden-host; do
      install -m 0755 "$dir/$b" "$bin/$b"
    done
    "$bin/kw" browser-setup || say "browser host not registered, run: kw browser-setup"
    say "installed into $bin. Start the app: keywarden-ui"
  fi

  case ":$PATH:" in *":$bin:"*) ;; *) say "add $bin to PATH, for example: echo 'export PATH=\"$bin:\$PATH\"' >> ~/.profile" ;; esac
}

say() { printf 'keywarden: %s\n' "$*"; }
die() { printf 'keywarden: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "needs $1"; }
# only https from GitHub; a mirror set by hand may be anything curl can read
fetch() {
  proto='=https'
  [ -z "${KEYWARDEN_MIRROR:-}" ] || proto=all
  curl -fL --proto "$proto" --retry 2 -sS -o "$2" "$1" || die "download failed: $1"
}

main "$@"
