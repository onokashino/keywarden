#!/bin/sh
# Стенд для UI: headless sway + программный Vulkan (lavapipe) + демон с базой из фикстуры.
# Использование (в docker): sh scripts/ui-harness.sh <сценарий>
# Сценарий получает переменные B (бинарники), W (временный каталог), SHOT (функция скриншота).
set -eu
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
chmod 700 $XDG_RUNTIME_DIR
B=${BIN:-${CARGO_TARGET_DIR:-target}/debug}
W=$(mktemp -d)
OUT=${SHOTS:-target/shots}
mkdir -p $OUT
# SHOWCASE=1: пустая база, сценарий наполняет её сам (витрина для сайта, scripts/ui-showcase.scenario)
DB=$W/${DB_NAME:-db}.kdbx
if [ -n "${SHOWCASE:-}" ]; then
  # как у настоящего пользователя: база в папке Syncthing
  DB=$HOME/Sync/${DB_NAME:-db}.kdbx
  mkdir -p $HOME/Sync && touch $HOME/Sync/.stfolder
  printf 't\nt\n' | keepassxc-cli db-create -q -p -t 100 $DB >/dev/null
else
  printf 't\nt\n' | keepassxc-cli import -q -p -t 100 crates/keywarden-core/tests/fixtures/kpxc-full.xml $DB >/dev/null
fi
mkdir -p $XDG_CONFIG_HOME/keywarden/themes
printf 'database = "%s"\n' $DB > $XDG_CONFIG_HOME/keywarden/config.toml
# EXTRA_CONFIG: дополнительные строки config.toml для сценария (например, свой terminal)
[ -n "${EXTRA_CONFIG:-}" ] && printf '%s\n' "$EXTRA_CONFIG" >> $XDG_CONFIG_HOME/keywarden/config.toml
[ -n "${THEME_JSON:-}" ] && cp "$THEME_JSON" $XDG_CONFIG_HOME/keywarden/themes/

export WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman
printf "output HEADLESS-1 resolution ${RES:-1280x800}\n"'seat * hide_cursor 100\noutput * bg #1e1e2e solid_color\n' > $W/sway.conf
cp /usr/bin/sway $W/sway-nocap
$W/sway-nocap -c $W/sway.conf >$W/sway.log 2>&1 &
SPID=$!
for i in $(seq 50); do ls $XDG_RUNTIME_DIR/wayland-* >/dev/null 2>&1 && break; sleep 0.1; done
export WAYLAND_DISPLAY=$(basename $(ls $XDG_RUNTIME_DIR/wayland-* | grep -v lock | head -1))
export VK_ICD_FILENAMES=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json | head -1)

$B/keywardend 2>$W/daemon.log &
DPID=$!
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
# вторая база (профиль work) со своим демоном: меню баз и общий поиск лаунчера
printf 'w\nw\n' | keepassxc-cli db-create -q -p $W/work.kdbx >/dev/null 2>&1
printf 'w\nwork-pass\n' | keepassxc-cli add -q -p -u worker --url https://gitlab.com $W/work.kdbx "${WORK_TITLE:-GitLab рабочий}" >/dev/null
$B/kw profile-add work $W/work.kdbx >/dev/null
$B/keywardend --profile work 2>$W/work.log &
WPID=$!
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/profiles/work/daemon.sock ] && break; sleep 0.1; done
echo w | $B/kw --profile work unlock --password-stdin >/dev/null
trap 'kill $DPID $SPID $WPID 2>/dev/null || true' EXIT

shot() { sleep ${2:-0.8}; grim $OUT/$1.png && echo "скриншот: $OUT/$1.png"; }
key() { wtype -s 300 "$@"; }  # пауза: GPUI применяет раскладку виртуальной клавиатуры не сразу
ui() { $B/keywarden-ui "$@" 2>>$W/ui.log & UPID=$!; }
. "$1"
echo "--- ui.log"; grep -v "eye.svg" $W/ui.log | tail -20 2>/dev/null || true; echo "--- daemon.log"; tail -8 $W/daemon.log
