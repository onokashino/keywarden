#!/bin/sh
# Windows-сборка под Wine: демон и kw через именованный канал (make e2e-wine).
set -u
export WINEDEBUG=-all HOME=/tmp/home WINEPREFIX=/tmp/home/wp LANG=C.UTF-8 LC_ALL=C.UTF-8
mkdir -p $HOME/wp
B=/app/target/x86_64-pc-windows-gnu/release
wineboot -i >/dev/null 2>&1
echo "== старт демона"
RUST_LOG=info wine $B/keywardend.exe > /tmp/d.log 2>&1 &
for i in $(seq 1 60); do wine $B/kw.exe ping >/dev/null 2>&1 && break; sleep 0.5; done
wine $B/kw.exe ping
echo "== разблокировка"
printf 'pw\n' | wine $B/kw.exe unlock --db 'Z:\app\target\wine\test.kdbx' --password-stdin 2>&1 | tail -2
wine $B/kw.exe status 2>&1 | head -4
echo "== поиск"
wine $B/kw.exe search git 2>&1 | head -3
echo "== новая запись"
wine $B/kw.exe add --title "Почта" -u me@example.com --generate 2>&1 | tail -1
wine $B/kw.exe search 2>&1 | head -5
echo "== ssh-env"
wine $B/kw.exe ssh-env
echo "== блокировка"
wine $B/kw.exe lock 2>&1; wine $B/kw.exe status 2>&1 | head -2
echo "== журнал демона"
tail -8 /tmp/d.log
