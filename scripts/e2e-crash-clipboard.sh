#!/bin/sh
# Критерии приёмки этапа 1, которые проверяются только живым процессом:
#  1) kill -9 демона во время сохранения: база открывается (старая или новая версия), бэкапы на месте;
#  2) буфер: значение помечено x-kde-passwordManagerHint=secret, очищается через N секунд,
#     но не трогается, если пользователь успел скопировать другое;
#  3) процесс демона недампуемый (PR_SET_DUMPABLE=0): /proc/PID/environ закрыт даже для того же uid.
# Запускать в docker: make e2e-crash
set -eu
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
chmod 700 $XDG_RUNTIME_DIR
B=${CARGO_TARGET_DIR:-target}/debug
W=$(mktemp -d)
printf 't\nt\n' | keepassxc-cli import -q -p -t 100 crates/keywarden-core/tests/fixtures/kpxc-full.xml $W/db.kdbx >/dev/null
mkdir -p $XDG_CONFIG_HOME/keywarden
printf 'database = "%s"\nclipboard_clear_seconds = 2\n' $W/db.kdbx > $XDG_CONFIG_HOME/keywarden/config.toml

start_daemon() {
  rm -f $XDG_RUNTIME_DIR/keywarden/daemon.sock
  $B/keywardend 2>>$W/daemon.log &
  DPID=$!
  for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
  echo t | $B/kw unlock --password-stdin
}

echo "== 1. kill -9 во время записи (10 раундов)"
for round in $(seq 10); do
  start_daemon
  ( for i in $(seq 20); do $B/kw edit GitHub --field "Round=$round-$i" >/dev/null 2>&1 || break; done ) &
  EPID=$!
  # убиваем в случайный момент: часть раундов попадает внутрь записи
  sleep "0.$(shuf -i 1-9 -n 1)$(shuf -i 0-9 -n 1)"
  kill -9 $DPID; wait $DPID 2>/dev/null || true
  wait $EPID 2>/dev/null || true
  echo t | keepassxc-cli ls -q $W/db.kdbx >/dev/null || { echo "раунд $round: база повреждена"; exit 1; }
  ls $W/.db.kdbx.kw-tmp-* >/dev/null 2>&1 && echo "  (раунд $round: остался временный файл, база цела)"
  rm -f $W/.db.kdbx.kw-tmp-*
done
# одна правка до конца: бэкап предыдущей версии обязан появиться
start_daemon
$B/kw edit GitHub --field "Final=1" >/dev/null
kill $DPID; wait $DPID 2>/dev/null || true
N=$(ls $XDG_STATE_HOME/keywarden/backups/*/ | wc -l)
echo "база цела во всех раундах, бэкапов: $N"
test "$N" -ge 1
for f in $XDG_STATE_HOME/keywarden/backups/*/*.kdbx; do echo t | keepassxc-cli ls -q "$f" >/dev/null; done
echo "все бэкапы открываются"

echo "== 2. буфер обмена (headless sway)"
export WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman
printf 'output HEADLESS-1 resolution 800x600\n' > $W/sway.conf
cp /usr/bin/sway $W/sway-nocap  # у пакетного sway file capability cap_sys_nice, в контейнере exec даёт EPERM
$W/sway-nocap -c $W/sway.conf >$W/sway.log 2>&1 &
SPID=$!
for i in $(seq 50); do ls $XDG_RUNTIME_DIR/wayland-* >/dev/null 2>&1 && break; sleep 0.1; done
export WAYLAND_DISPLAY=$(basename $(ls $XDG_RUNTIME_DIR/wayland-* | grep -v lock | head -1))
start_daemon

$B/kw copy GitHub -f username
test "$(wl-paste -n)" = "octo"
wl-paste --list-types | grep -qx "x-kde-passwordManagerHint" || { echo "нет пометки секрета"; exit 1; }
test "$(wl-paste -n -t x-kde-passwordManagerHint)" = "secret"
echo "значение в буфере, помечено как secret"
sleep 3
test -z "$(wl-paste -n 2>/dev/null || true)" || { echo "буфер не очистился"; exit 1; }
echo "через 2 с буфер очищен"

$B/kw copy GitHub -f username
printf 'моё' | wl-copy
sleep 3
test "$(wl-paste -n)" = "моё" || { echo "демон стёр чужое значение"; exit 1; }
echo "чужое значение не тронуто"

echo "== 3. локальный API: секреты только через буфер"
api() { node -e 'const s=require("net").connect(process.argv[1]);s.write(process.argv[2]+"\n");s.on("data",d=>{process.stdout.write(d);s.end()})' $XDG_RUNTIME_DIR/keywarden/api.sock "$1"; }
printf 'wifi-Pa55' | wl-copy
R=$(api '{"method":"save_from_clipboard","title":"Wi-Fi дома","type":"login"}')
echo "$R" | grep -q '"ok":true' && ! echo "$R" | grep -q wifi-Pa55
ID=$(echo "$R" | sed 's/.*"id":"\([^"]*\)".*/\1/')
api '{"method":"list","query":"wi-fi"}' | grep -q "Wi-Fi дома"
printf 'другое' | wl-copy
R=$(api "{\"method\":\"secret_copy\",\"id\":\"$ID\"}")
echo "$R" | grep -q '"ok":true' && ! echo "$R" | grep -q wifi-Pa55
test "$(wl-paste -n)" = "wifi-Pa55"
echo "save_from_clipboard и secret_copy работают, значения в ответах нет"

echo "== 4. демон недампуемый"
if cat /proc/$DPID/environ >/dev/null 2>&1; then echo "/proc/$DPID/environ читается: PR_SET_DUMPABLE не сработал"; exit 1; fi
echo "/proc/PID/environ закрыт"

kill $DPID $SPID 2>/dev/null || true
! grep -E "octo|s3cr3t" $W/daemon.log
echo; echo "E2E CRASH+CLIPBOARD OK"
exit 0
