#!/bin/sh
# Installs Keywarden into the home directory (no root). Binaries come from target/release
# (build: make build) or sit next to this script in a release archive.
# niri and Noctalia are connected only if they are installed: the config gets a backup first,
# niri's keys are checked for clashes, the config is validated and restored if niri rejects it.
# KEYWARDEN_PARTS picks the optional parts, space separated: browser ssh niri noctalia
# (default: browser niri noctalia; ssh makes the Keywarden agent the SSH agent of every program).
# KEYWARDEN_LANG=ru|en: language of the messages (default: the session locale).
# KEYWARDEN_NO_LAUNCH=1: do not open the app at the end. NO_COLOR: plain output.
set -eu
PARTS=${KEYWARDEN_PARTS-browser niri noctalia}
part() { case " $PARTS " in *" $1 "*) return 0 ;; esac; return 1; }
# language: KEYWARDEN_LANG=ru|en, otherwise the session locale. m 'English text %s' args...
LNG=${KEYWARDEN_LANG:-}
if [ -z "$LNG" ]; then case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ru*) LNG=ru ;; *) LNG=en ;; esac; fi
m() {
  f=$1; shift
  [ "$LNG" != ru ] || f=$(ru "$f")
  # shellcheck disable=SC2059
  printf "$f" "$@"
}
ru() {
  case "$1" in
    'programs in %s') printf '%s' 'программы в %s' ;;
    'background service %s is running and starts with your session') printf '%s' 'фоновая служба %s работает и запускается вместе с сеансом' ;;
    'menu entry added') printf '%s' 'ярлык в меню добавлен' ;;
    'browser link skipped, later: %s') printf '%s' 'связь с браузером пропущена, позже: %s' ;;
    'browsers can reach Keywarden (check: %s)') printf '%s' 'браузеры видят Keywarden (проверка: %s)' ;;
    'browser host not registered, run: %s') printf '%s' 'связь с браузером не настроена, выполните: %s' ;;
    'SSH agent for all programs %s(after the next login; undo: %s)%s') printf '%s' 'SSH-агент для всех программ %s(после следующего входа в систему; отменить: %s)%s' ;;
    'SSH agent not connected, run: %s') printf '%s' 'SSH-агент не подключён, выполните: %s' ;;
    'niri shortcuts skipped') printf '%s' 'клавиши niri пропущены' ;;
    'niri: %s opens the launcher') printf '%s' 'niri: %s открывает лаунчер' ;;
    'niri: your config does not pass "niri validate", left as it was. Add later: %s') printf '%s' 'niri: ваш конфиг не проходит «niri validate», оставлен как был. Добавьте позже: %s' ;;
    'niri: %s already taken in your config, left as it was. Pick free keys in %s and add to config.kdl: %s') printf '%s' 'niri: %s уже заняты в вашем конфиге, он оставлен как был. Выберите свободные клавиши в %s и добавьте в config.kdl: %s' ;;
    'niri: %s opens the launcher %s(backup: %s)%s') printf '%s' 'niri: %s открывает лаунчер %s(копия: %s)%s' ;;
    'niri rejected the Keywarden rules, config left as it was. See %s') printf '%s' 'niri не принял правила Keywarden, конфиг оставлен как был. Смотрите %s' ;;
    'niri not found, shortcuts are set in the settings of your desktop') printf '%s' 'niri не найден, клавиши задаются в настройках вашего рабочего стола' ;;
    'Noctalia: Keywarden follows your shell colors') printf '%s' 'Noctalia: Keywarden берёт цвета оболочки' ;;
    'opening Keywarden') printf '%s' 'открываю Keywarden' ;;
    'start the app: %s') printf '%s' 'запуск приложения: %s' ;;
    *) printf '%s' "$1" ;;
  esac
}
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
# a cache older than the theme folder is ignored; without this a stale one hides the new icon
touch "$HOME/.local/share/icons/hicolor"
ok "$(m 'programs in %s' "$(home "$BIN")")"

systemctl --user daemon-reload
systemctl --user --quiet enable keywardend.service
# restart, not --now: on a re-run the old daemon would keep running the old binary
systemctl --user restart keywardend.service
ok "$(m 'background service %s is running and starts with your session' "${B}keywardend${N}")"
ok "$(m 'menu entry added')"

# native messaging: Firefox, Chromium-based browsers, their forks and Flatpak builds
if ! part browser; then
  skip "$(m 'browser link skipped, later: %s' 'kw browser-setup')"
elif "$BIN/kw" browser-setup ${CHROMIUM_EXTENSION_ID:+--chrome-id "$CHROMIUM_EXTENSION_ID"} >/dev/null; then
  ok "$(m 'browsers can reach Keywarden (check: %s)' 'kw browser-setup --check')"
else
  warn "$(m 'browser host not registered, run: %s' 'kw browser-setup')"
fi

# the agent socket goes into the session environment: ssh, git and IDEs see the vault's keys
if part ssh; then
  if "$BIN/kw" ssh-setup >/dev/null 2>&1; then
    ok "$(m 'SSH agent for all programs %s(after the next login; undo: %s)%s' "$D" 'kw ssh-setup --off' "$N")"
  else
    warn "$(m 'SSH agent not connected, run: %s' 'kw ssh-setup')"
  fi
fi

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
if ! part niri; then
  skip "$(m 'niri shortcuts skipped')"
elif [ -f "$NIRI" ] && command -v niri >/dev/null 2>&1; then
  cp dist/niri/keywarden.kdl "$CONF/niri/keywarden.kdl"
  taken=$(niri_taken)
  if grep -q 'include "keywarden.kdl"' "$NIRI"; then
    ok "$(m 'niri: %s opens the launcher' "${B}Super+Shift+P${N}")"
  elif ! niri validate >/dev/null 2>&1; then
    # the config is already broken: leave it, otherwise nobody can tell whose error it is
    warn "$(m 'niri: your config does not pass "niri validate", left as it was. Add later: %s' 'include "keywarden.kdl"')"
  elif [ -n "$taken" ]; then
    # niri validate accepts a repeated bind and the later one silently wins: check ourselves
    warn "$(m 'niri: %s already taken in your config, left as it was. Pick free keys in %s and add to config.kdl: %s' "$taken" "$(home "$CONF/niri/keywarden.kdl")" 'include "keywarden.kdl"')"
  else
    cp "$NIRI" "$NIRI.bak-keywarden-$stamp"
    printf '\ninclude "keywarden.kdl"\n' >> "$NIRI"
    if niri validate >/dev/null 2>&1; then
      ok "$(m 'niri: %s opens the launcher %s(backup: %s)%s' "${B}Super+Shift+P${N}" "$D" "$(home "$NIRI").bak-keywarden-$stamp" "$N")"
    else
      cp "$NIRI.bak-keywarden-$stamp" "$NIRI"
      rm -f "$NIRI.bak-keywarden-$stamp"
      warn "$(m 'niri rejected the Keywarden rules, config left as it was. See %s' "$(home "$CONF/niri/keywarden.kdl")")"
    fi
  fi
else
  skip "$(m 'niri not found, shortcuts are set in the settings of your desktop')"
fi

# Noctalia: the app follows the shell's colors
NOC=$CONF/noctalia/config.toml
if [ -f "$NOC" ] && part noctalia; then
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
  ok "$(m 'Noctalia: Keywarden follows your shell colors')"
fi

# open the app: on the first start it walks through creating or opening a vault
if [ -z "${KEYWARDEN_NO_LAUNCH:-}" ] && { [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${DISPLAY:-}" ]; }; then
  if command -v setsid >/dev/null 2>&1; then
    setsid -f "$BIN/keywarden-ui" >/dev/null 2>&1 </dev/null || true
  else
    nohup "$BIN/keywarden-ui" >/dev/null 2>&1 </dev/null &
  fi
  ok "$(m 'opening Keywarden')"
else
  skip "$(m 'start the app: %s' keywarden-ui)"
fi
