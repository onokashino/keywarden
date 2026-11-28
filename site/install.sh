#!/bin/sh
# Keywarden installer for Linux (x86_64) and macOS (Apple Silicon):
#   curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
# Downloads the release archive from GitHub, checks it against SHA256SUMS and installs
# into ~/.local/bin without root. A specific version: ... | KEYWARDEN_VERSION=v0.1.0 sh
# NO_COLOR=1: plain output. KEYWARDEN_NO_LAUNCH=1: do not open the app at the end.
# Everything is inside main() so a download cut off halfway runs nothing.
set -eu

main() {
  repo=onokashino/keywarden
  base=${KEYWARDEN_MIRROR:-https://github.com/$repo/releases/download}
  bin=${BIN:-$HOME/.local/bin}
  amo=https://addons.mozilla.org/firefox/addon/keywarden/

  printf '\n  %s◆ Keywarden%s %sinstaller%s\n\n' "$V$B" "$N" "$D" "$N"
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
    tag=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
    tag=${tag##*/}
  fi
  case "$tag" in v[0-9]*) ;; *) die "no published release yet: https://github.com/$repo/releases" ;; esac
  ok "release ${B}$tag${N} for $target"

  file=keywarden-$tag-$target.tar.gz
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM
  fetch "$base/$tag/$file" "$tmp/$file" &
  spin $! "downloading $file" || die "download failed: $base/$tag/$file"
  fetch "$base/$tag/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: SHA256SUMS"
  ok "downloaded $(du -h "$tmp/$file" | cut -f1 | tr -d ' ')"
  want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
  got=$(cd "$tmp" && $sum "$file" | awk '{ print $1 }')
  [ -n "$want" ] || die "$file is not listed in SHA256SUMS"
  [ "$want" = "$got" ] || die "checksum mismatch for $file, nothing installed"
  ok "checksum matches SHA256SUMS"
  tar xzf "$tmp/$file" -C "$tmp"
  dir=$tmp/keywarden-$tag-$target

  if [ "$target" = linux-x86_64 ]; then
    # the archive's own script: binaries, service, menu entry, browsers, niri, Noctalia
    (cd "$dir" && BIN="$bin" sh ./install.sh)
  else
    mkdir -p "$bin"
    for b in keywardend kw keywarden-ui keywarden-host; do
      install -m 0755 "$dir/$b" "$bin/$b"
    done
    ok "programs in $bin"
    if "$bin/kw" browser-setup >/dev/null 2>&1; then ok "browsers can reach Keywarden"; else warn "browser host not registered, run: kw browser-setup"; fi
    if [ -z "${KEYWARDEN_NO_LAUNCH:-}" ]; then
      (nohup "$bin/keywarden-ui" >/dev/null 2>&1 </dev/null &) && ok "opening Keywarden"
    fi
  fi

  case ":$PATH:" in
    *":$bin:"*) ;;
    *) warn "add $bin to PATH: echo 'export PATH=\"$bin:\$PATH\"' >> ~/.profile" ;;
  esac
  printf '\n  %sKeywarden %s is installed.%s\n' "$G$B" "$tag" "$N"
  printf '  Browser extension: %s\n\n' "$(link "$amo" "Add to Firefox")"
}

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  E=$(printf '\033')
  G="${E}[32m" Y="${E}[33m" V="${E}[38;5;141m" D="${E}[2m" B="${E}[1m" N="${E}[0m"
else
  E="" G="" Y="" V="" D="" B="" N=""
fi
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die() { printf '  %s✗ %s%s\n' "$Y" "$*" "$N" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "needs $1"; }
# clickable in terminals that support OSC 8, plain text with the address otherwise
link() { if [ -n "$E" ]; then printf '%s]8;;%s%s\\%s%s%s%s]8;;%s\\ %s%s%s' "$E" "$1" "$E" "$V" "$2" "$N" "$E" "$E" "$D" "$1" "$N"; else printf '%s %s' "$2" "$1"; fi; }
# a spinner next to the message while process $1 runs; returns its exit status
spin() {
  if [ -z "$E" ]; then wait "$1"; return; fi
  i=0
  while kill -0 "$1" 2>/dev/null; do
    case $((i % 10)) in 0) f=⠋;; 1) f=⠙;; 2) f=⠹;; 3) f=⠸;; 4) f=⠼;; 5) f=⠴;; 6) f=⠦;; 7) f=⠧;; 8) f=⠇;; *) f=⠏;; esac
    printf '\r  %s%s%s %s' "$V" "$f" "$N" "$2"
    i=$((i + 1))
    sleep 0.08
  done
  printf '\r%s\r' "${E}[2K"
  wait "$1"
}
# only https from GitHub; a mirror set by hand may be anything curl can read
fetch() {
  proto='=https'
  [ -z "${KEYWARDEN_MIRROR:-}" ] || proto=all
  curl -fL --proto "$proto" --retry 2 -sS -o "$2" "$1"
}

main "$@"
