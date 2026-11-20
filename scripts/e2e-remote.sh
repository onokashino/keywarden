#!/bin/sh
# Сквозная проверка синхронизации без папки: WebDAV (сервер dav) и напрямую в сети.
# Два контейнера, роли a и b, общий каталог /shared для очерёдности. Запуск: make e2e-remote
set -eu
ROLE=$1
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
export KEYWARDEN_WEBDAV_POLL=3
B=${CARGO_TARGET_DIR:-target}/debug
W=$(mktemp -d)
S=/shared
DAV=${DAV_URL:-http://dav/dav/vault.kdbx}
DU=${DAV_USER:-kw} DP=${DAV_PASS:-secret}

$B/keywardend 2>$W/daemon.log &
DPID=$!
trap 'kill $DPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done

step() { printf '\n== [%s] %s\n' "$ROLE" "$*"; }
# ждать условия до 90 с; не дождались: лог демона и ошибка
waitfor() {
  for i in $(seq 90); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "FAIL [$ROLE]: $*"; tail -60 $W/daemon.log; exit 1
}
has() { $B/kw search "$1" | grep -q "$2"; }

if [ "$ROLE" = a ]; then
  step "WebDAV: новая база, подключить сервер"
  printf 'pw\npw\n' | keepassxc-cli db-create -q -p $W/vault.kdbx
  echo pw | $B/kw unlock --db $W/vault.kdbx --password-stdin
  $B/kw add --title from-a -u alice
  ! echo wrong | $B/kw sync webdav $DAV -u $DU --password-stdin
  echo $DP | $B/kw sync webdav $DAV -u $DU --password-stdin
  waitfor curl -fsS -u $DU:$DP -o /dev/null $DAV
  touch $S/dav-ready
  step "WebDAV: правка с другого компьютера дошла"
  waitfor has from-b bob
  step "WebDAV: правки с двух сторон одновременно"
  $B/kw add --title a-second -u a2
  touch $S/a-edited
  waitfor has b-second b2
  waitfor has a-second a2
  $B/kw sync status

  step "сеть: вторая база"
  printf 'pw2\npw2\n' | keepassxc-cli db-create -q -p $W/lan.kdbx
  cp $W/lan.kdbx $S/lan.kdbx
  touch $S/lan-ready
  $B/kw lock
  echo pw2 | $B/kw unlock --db $W/lan.kdbx --password-stdin
  $B/kw sync lan on
  $B/kw add --title lan-a -u la
  waitfor has lan-b lb
  $B/kw sync status | grep -q "компьютер"
  $B/kw sync status
  touch $S/a-done
  waitfor test -e $S/b-done

  step "первая передача: неверный код отменяет передачу"
  $B/kw sync offer > $S/code-burnt
  $B/kw sync status | grep -q "$(cat $S/code-burnt)"
  touch $S/offer1
  waitfor test -e $S/wrong-tried
  ! $B/kw sync status | grep -q "$(cat $S/code-burnt)"
  step "первая передача: новый код, база уходит на пустой компьютер"
  $B/kw sync offer > $S/code
  touch $S/offer2
  waitfor test -e $S/received
  # код одноразовый: после удачной передачи его больше нет
  ! $B/kw sync status | grep -q "$(cat $S/code)"
  $B/kw add --title after-pair -u ap
  touch $S/a-paired
  waitfor test -e $S/b-paired
else
  waitfor test -e $S/dav-ready
  step "WebDAV: база с сервера, настройка пришла вместе с ней"
  curl -fsS -u $DU:$DP -o $W/vault.kdbx $DAV
  echo pw | $B/kw unlock --db $W/vault.kdbx --password-stdin
  $B/kw sync status | grep -q "^WebDAV"
  has from-a alice
  $B/kw add --title from-b -u bob
  waitfor test -e $S/a-edited
  $B/kw add --title b-second -u b2
  waitfor has a-second a2

  waitfor test -e $S/lan-ready
  step "сеть: копия базы, обмен напрямую"
  cp $S/lan.kdbx $W/lan.kdbx
  $B/kw lock
  echo pw2 | $B/kw unlock --db $W/lan.kdbx --password-stdin
  $B/kw sync lan on
  $B/kw add --title lan-b -u lb
  waitfor has lan-a la
  touch $S/b-done
  waitfor test -e $S/a-done

  step "первая передача: получить можно только с верным кодом и не поверх своего файла"
  waitfor test -e $S/offer1
  $B/kw lock
  mkdir $W/recv && echo mine > $W/recv/lan.kdbx
  ! $B/kw sync receive 00000000 --dir $W/recv
  touch $S/wrong-tried
  waitfor test -e $S/offer2
  $B/kw sync receive "$(cat $S/code)" --dir $W/recv
  [ "$(cat $W/recv/lan.kdbx)" = mine ]
  test -s "$W/recv/lan 2.kdbx"
  touch $S/received
  step "первая передача: полученная база открывается и дальше обменивается сама"
  echo pw2 | $B/kw unlock --password-stdin
  has lan-a la
  waitfor test -e $S/a-paired
  waitfor has after-pair ap
  touch $S/b-paired
fi
grep -c "База синхронизирована" $W/daemon.log || true
echo "OK [$ROLE]"
