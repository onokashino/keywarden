#!/bin/sh
# Keywarden installer for Linux (x86_64) and macOS (Apple Silicon):
#   curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
# Downloads the release archive from GitHub, checks it against SHA256SUMS and installs
# into ~/.local/bin without root. A specific version: ... | KEYWARDEN_VERSION=v0.1.0 sh
# When a release signing key is set below, SHA256SUMS must also carry a valid signature
# (SHA256SUMS.sig, checked with ssh-keygen); KEYWARDEN_UNSIGNED=1 skips that for old releases.
# Run it again any time: with Keywarden already installed it checks the installation and
# offers to fix what is broken, update, or pick the optional parts.
# KEYWARDEN_PARTS picks them without questions, space separated: browser ssh niri noctalia.
# KEYWARDEN_YES=1: no questions, install or update. NO_COLOR=1: plain output.
# KEYWARDEN_NO_LAUNCH=1: do not open the app at the end.
# Everything is inside main() so a download cut off halfway runs nothing.
set -eu

main() {
  repo=onokashino/keywarden
  base=${KEYWARDEN_MIRROR:-https://github.com/$repo/releases/download}
  bin=${BIN:-$HOME/.local/bin}
  amo=https://addons.mozilla.org/firefox/addon/keywarden/
  # public half of the release signing key (packaging/release-key.pub); empty: checksum only
  signer=''

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

  # questions only when a person is at the terminal; the script itself may be coming from a pipe
  talk=
  if [ -t 1 ] && [ -z "${KEYWARDEN_YES:-}" ] && (exec < /dev/tty) 2>/dev/null; then talk=1; fi
  have=
  [ ! -x "$bin/kw" ] || have=$("$bin/kw" --version 2>/dev/null | awk '{ print $NF }')
  if [ -n "$have" ]; then
    diagnose
    if [ -n "$talk" ]; then menu; fi
  elif [ -n "$talk" ]; then
    printf '  %sEnter%s installs everything, %sc%s lets you choose the parts: ' "$B" "$N" "$B" "$N"
    read -r a < /dev/tty || a=
    case "$a" in c|C) choose_parts ;; esac
  fi
  [ -z "${KEYWARDEN_PARTS+x}" ] || export KEYWARDEN_PARTS
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
  # the checksum file sits next to the archive, so on its own it only catches a broken download;
  # the signature proves the list was made by the holder of the release key
  if [ -n "$signer" ] && [ -z "${KEYWARDEN_UNSIGNED:-}" ]; then
    command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is needed to check the release signature (package: openssh)"
    fetch "$base/$tag/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" || die "this release has no signature (SHA256SUMS.sig), nothing installed"
    printf 'release@keywarden %s\n' "$signer" > "$tmp/signers"
    ssh-keygen -Y verify -f "$tmp/signers" -I release@keywarden -n keywarden-release \
      -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" >/dev/null 2>&1 \
      || die "release signature does not match, nothing installed"
    ok "release signature is valid"
  fi
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
    parts=${KEYWARDEN_PARTS-browser}
    case " $parts " in *" browser "*)
      if "$bin/kw" browser-setup >/dev/null 2>&1; then ok "browsers can reach Keywarden"; else warn "browser host not registered, run: kw browser-setup"; fi ;;
    esac
    case " $parts " in *" ssh "*)
      if "$bin/kw" ssh-setup >/dev/null 2>&1; then ok "SSH agent for all programs (after the next login; undo: kw ssh-setup --off)"; else warn "SSH agent not connected, run: kw ssh-setup"; fi ;;
    esac
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

# What is wrong with the installation in $bin; fills $problems with: files service browser
diagnose() {
  problems=
  if [ "v$have" = "$tag" ]; then ok "Keywarden ${B}$have${N} is installed, this is the latest version"
  else warn "Keywarden ${B}$have${N} is installed, the latest is ${B}$tag${N}"; fi
  miss=
  for b in keywardend kw keywarden-ui keywarden-host; do [ -x "$bin/$b" ] || miss="$miss $b"; done
  if [ -n "$miss" ]; then problems="$problems files"; bad "missing programs:$miss"; else ok "programs in $bin"; fi
  if [ "$target" = linux-x86_64 ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl --user is-active --quiet keywardend.service 2>/dev/null \
      && systemctl --user is-enabled --quiet keywardend.service 2>/dev/null; then
      ok "background service is running"
    else
      problems="$problems service"; bad "background service is stopped or does not start with your session"
    fi
  fi
  # the daemon line is left out: it is covered by the service check above
  fails=$(KEYWARDEN_LANG=en "$bin/kw" browser-setup --check 2>/dev/null | grep '^FAIL' | grep -v keywardend || true)
  if [ -n "$fails" ]; then
    problems="$problems browser"
    printf '%s\n' "$fails" | while read -r _ what; do bad "browser link: $what"; done
  else
    ok "browser link"
  fi
  case ":$PATH:" in *":$bin:"*) ;; *) warn "$bin is not in PATH" ;; esac
}

fix() {
  case "$1" in
    service)
      systemctl --user daemon-reload
      if systemctl --user --quiet enable keywardend.service && systemctl --user restart keywardend.service; then
        ok "background service started"
      else warn "the service did not start, see: journalctl --user -u keywardend -e"; fi ;;
    browser)
      if "$bin/kw" browser-setup >/dev/null 2>&1; then ok "browser link registered again"; else warn "browser link still broken, see: kw browser-setup --check"; fi ;;
  esac
}

# Returns to install or update; exits when the choice needs no download.
menu() {
  printf '\n  What to do?\n'
  n=0
  for p in $problems; do
    n=$((n + 1))
    eval "opt_$n=\$p"
    case "$p" in
      files) t="put the missing programs back (downloads $tag)" ;;
      service) t="start the background service and enable it" ;;
      browser) t="register the browser link again" ;;
    esac
    printf '    %s%s)%s %s\n' "$B" "$n" "$N" "$t"
  done
  [ "$n" -lt 2 ] || printf '    %sa)%s fix all of the above\n' "$B" "$N"
  if [ "v$have" = "$tag" ]; then printf '    %sr)%s reinstall %s\n' "$B" "$N" "$tag"
  else printf '    %su)%s update to %s\n' "$B" "$N" "$tag"; fi
  printf '    %sc)%s choose the optional parts (browser link, SSH agent, desktop integration)\n' "$B" "$N"
  printf '    %sq)%s nothing\n  > ' "$B" "$N"
  read -r a < /dev/tty || a=q
  echo
  case "$a" in
    u|U|r|R) return 0 ;;
    c|C) choose_parts; return 0 ;;
    a|A) todo=$problems ;;
    [1-9]) eval "todo=\${opt_$a:-}"; [ -n "$todo" ] || exit 0 ;;
    *) exit 0 ;;
  esac
  # missing programs come back only with a full install, which redoes the rest as well
  case " $todo " in *" files "*) return 0 ;; esac
  for p in $todo; do fix "$p"; done
  echo
  exit 0
}

agree() {
  printf '  %s [%s] ' "$1" "$2"
  read -r a < /dev/tty || a=
  case "${a:-$2}" in y*|Y*) return 0 ;; esac
  return 1
}

choose_parts() {
  KEYWARDEN_PARTS=
  ! agree "Browser link, so the extension can reach Keywarden?" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS browser"
  ! agree "SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?" "y/N" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS ssh"
  if [ "$target" = linux-x86_64 ]; then
    if command -v niri >/dev/null 2>&1; then
      ! agree "niri: shortcuts for the launcher (your config is backed up first)?" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS niri"
    fi
    if [ -f "${XDG_CONFIG_HOME:-$HOME/.config}/noctalia/config.toml" ]; then
      ! agree "Noctalia: follow the shell colors?" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS noctalia"
    fi
  fi
  echo
}

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  E=$(printf '\033')
  G="${E}[32m" Y="${E}[33m" V="${E}[38;5;141m" D="${E}[2m" B="${E}[1m" N="${E}[0m"
else
  E="" G="" Y="" V="" D="" B="" N=""
fi
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
bad() { printf '  %s✗%s %s\n' "$Y" "$N" "$*"; }
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
