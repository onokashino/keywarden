#!/bin/sh
# Installs Keywarden into the home directory (no root). Binaries come from target/release
# (build: make build) or sit next to this script in a release archive.
# niri and Noctalia are connected only if they are installed: the config gets a backup first,
# niri's keys are checked for clashes, the config is validated and restored if niri rejects it.
# KEYWARDEN_NO_LAUNCH=1: do not open the app at the end. NO_COLOR: plain output.
set -eu
BIN=${BIN:-$HOME/.local/bin}
R=${R:-target/release}
CONF=${XDG_CONFIG_HOME:-$HOME/.config}
# from a release archive: the binaries sit next to the script
[ -x "$(dirname "$0")/keywardend" ] && R=$(dirname "$0")

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$(printf '\033[32m') Y=$(printf '\033[33m') D=$(printf '\033[2m') B=$(printf '\033[1m') N=$(printf '\033[0m')
else
  G="" Y="" D="" B="" N=""
fi
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
skip() { printf '  %s·%s %s%s%s\n' "$D" "$N" "$D" "$*" "$N"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
home() { printf '%s' "$1" | sed "s|^$HOME|~|"; }

for b in keywardend kw keywarden-ui keywarden-host; do
  [ -x "$R/$b" ] || { echo "missing $R/$b, run make build first" >&2; exit 1; }
done
mkdir -p "$BIN" "$CONF/systemd/user" "$HOME/.local/share/applications" "$CONF/keywarden/themes"
install -m 0755 "$R/keywardend" "$R/kw" "$R/keywarden-ui" "$R/keywarden-host" "$BIN/"
install -m 0644 dist/systemd/keywardend.service dist/systemd/keywardend@.service "$CONF/systemd/user/"
install -m 0644 dist/keywarden.desktop "$HOME/.local/share/applications/"
install -Dm644 dist/icons/keywarden.svg "$HOME/.local/share/icons/hicolor/scalable/apps/keywarden.svg"
ok "programs in $(home "$BIN")"

systemctl --user daemon-reload
systemctl --user --quiet enable keywardend.service
# restart, not --now: on a re-run the old daemon would keep running the old binary
systemctl --user restart keywardend.service
ok "background service ${B}keywardend${N} is running and starts with your session"
ok "menu entry added"

# native messaging: Firefox and Chromium-based browsers
dir=$HOME/.mozilla/native-messaging-hosts
mkdir -p "$dir"
sed "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" dist/native-messaging/firefox.json > "$dir/dev.keywarden.host.json"
browsers=Firefox
for d in "$CONF/chromium:Chromium" "$CONF/google-chrome:Chrome" "$CONF/BraveSoftware/Brave-Browser:Brave"; do
  path=${d%%:*}
  [ -d "$path" ] || continue
  mkdir -p "$path/NativeMessagingHosts"
  sed -e "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" -e "s|REPLACE_WITH_EXTENSION_ID|${CHROMIUM_EXTENSION_ID:-REPLACE_WITH_EXTENSION_ID}|" \
    dist/native-messaging/chromium.json > "$path/NativeMessagingHosts/dev.keywarden.host.json"
  browsers="$browsers, ${d##*:}"
done
ok "browsers can reach Keywarden: $browsers"

stamp=$(date +%Y%m%d-%H%M%S)

# niri: shortcuts and window rules through one include line
NIRI=$CONF/niri/config.kdl
# Keywarden's keys already bound in the user's niri config (lines that start with the key)
# ponytail: matches the modifier order used in keywarden.kdl only (Mod+Shift+P, not Shift+Mod+P)
niri_taken() {
  grep -rhoE '^[[:space:]]*(Mod\+Shift\+P|Mod\+Shift\+A|Mod\+Shift\+Alt\+L)[[:space:]{]' \
    --include='*.kdl' --exclude=keywarden.kdl "$CONF/niri" 2>/dev/null |
    tr -d ' \t{' | sort -u | sed 's/Mod/Super/' | paste -sd, - | sed 's/,/, /g'
}
if [ -f "$NIRI" ] && command -v niri >/dev/null 2>&1; then
  cp dist/niri/keywarden.kdl "$CONF/niri/keywarden.kdl"
  taken=$(niri_taken)
  if grep -q 'include "keywarden.kdl"' "$NIRI"; then
    ok "niri: ${B}Super+Shift+P${N} opens the launcher"
  elif ! niri validate >/dev/null 2>&1; then
    # the config is already broken: leave it, otherwise nobody can tell whose error it is
    warn "niri: your config does not pass 'niri validate', left as it was. Add later: include \"keywarden.kdl\""
  elif [ -n "$taken" ]; then
    # niri validate accepts a repeated bind and the later one silently wins: check ourselves
    warn "niri: $taken already taken in your config, left as it was. Pick free keys in $(home "$CONF/niri/keywarden.kdl") and add to config.kdl: include \"keywarden.kdl\""
  else
    cp "$NIRI" "$NIRI.bak-keywarden-$stamp"
    printf '\ninclude "keywarden.kdl"\n' >> "$NIRI"
    if niri validate >/dev/null 2>&1; then
      ok "niri: ${B}Super+Shift+P${N} opens the launcher ${D}(backup: $(home "$NIRI").bak-keywarden-$stamp)${N}"
    else
      cp "$NIRI.bak-keywarden-$stamp" "$NIRI"
      rm -f "$NIRI.bak-keywarden-$stamp"
      warn "niri rejected the Keywarden rules, config left as it was. See $(home "$CONF/niri/keywarden.kdl")"
    fi
  fi
else
  skip "niri not found, shortcuts are set in your desktop's settings"
fi

# Noctalia: the app follows the shell's colors
NOC=$CONF/noctalia/config.toml
if [ -f "$NOC" ]; then
  mkdir -p "$CONF/noctalia/templates"
  install -m 0644 dist/noctalia/keywarden.json "$CONF/noctalia/templates/keywarden.json"
  if ! grep -q 'theme.templates.user.keywarden' "$NOC"; then
    cp "$NOC" "$NOC.bak-keywarden-$stamp"
    cat >> "$NOC" <<'EOF'

[theme.templates.user.keywarden]
input_path  = "templates/keywarden.json"
output_path = "$XDG_CONFIG_HOME/keywarden/themes/noctalia.json"
EOF
  fi
  ok "Noctalia: Keywarden follows your shell colors"
fi

# open the app: on the first start it walks through creating or opening a vault
if [ -z "${KEYWARDEN_NO_LAUNCH:-}" ] && { [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${DISPLAY:-}" ]; }; then
  if command -v setsid >/dev/null 2>&1; then
    setsid -f "$BIN/keywarden-ui" >/dev/null 2>&1 </dev/null || true
  else
    nohup "$BIN/keywarden-ui" >/dev/null 2>&1 </dev/null &
  fi
  ok "opening Keywarden"
else
  skip "start the app: keywarden-ui"
fi
