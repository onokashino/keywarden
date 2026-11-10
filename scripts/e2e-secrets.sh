#!/bin/sh
# Secret Service: настоящий secret-tool (libsecret, сессия dh-ietf1024) против keywardend
# на отдельной сессионной шине. Запуск в docker: make e2e-secrets
set -eu
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  exec dbus-run-session -- sh "$0" "$@"
fi
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
chmod 700 $XDG_RUNTIME_DIR
B=${CARGO_TARGET_DIR:-target}/debug
W=$(mktemp -d)
printf 't\nt\n' | keepassxc-cli import -q -p -t 100 crates/keywarden-core/tests/fixtures/kpxc-full.xml $W/db.kdbx >/dev/null
mkdir -p $XDG_CONFIG_HOME/keywarden
cat > $XDG_CONFIG_HOME/keywarden/config.toml <<CFG
database = "$W/db.kdbx"
secret_service = true
confirm_command = ["sh", "-c", "echo \$1 >> $W/asked; exit 11", "confirm"]
CFG
$B/keywardend 2>$W/daemon.log &
DPID=$!
trap 'kill $DPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
step() { printf '\n== %s\n' "$*"; }
echo t | $B/kw unlock --password-stdin
for i in $(seq 50); do grep -q "обслуживает org.freedesktop.secrets" $W/daemon.log && break; sleep 0.1; done
grep "Secret Service" $W/daemon.log

step "store"
printf 'ghp_secret_token' | secret-tool store --label="GitHub token" service git user octo
step "lookup"
test "$(secret-tool lookup service git user octo)" = "ghp_secret_token"
echo "ok: lookup вернул секрет"
step "окно подтверждения спрошено один раз"
test "$(wc -l < $W/asked)" = 1
secret-tool lookup service git user octo >/dev/null
test "$(wc -l < $W/asked)" = 1 && echo "ok: «всегда» запомнено до блокировки"
step "replace: тот же набор атрибутов перезаписывается"
printf 'new_token' | secret-tool store --label="GitHub token" service git user octo
test "$(secret-tool lookup service git user octo)" = "new_token"
step "search"
secret-tool search --all service git 2>$W/search.err | grep -q "secret = new_token"
! grep -q "expected" $W/search.err
step "запись видна в KeePassXC в папке Secret Service"
echo t | keepassxc-cli show -q -s -a Password $W/db.kdbx "/Secret Service/GitHub token" | grep -x new_token
echo t | keepassxc-cli show -q -a service $W/db.kdbx "/Secret Service/GitHub token" | grep -x git
step "записи вне папки приложениям не видны"
! secret-tool search --all Title GitHub 2>/dev/null | grep -q octo
step "clear"
secret-tool clear service git user octo
! secret-tool lookup service git user octo
step "в логе демона нет секретов"
! grep -E "ghp_secret_token|new_token" $W/daemon.log

step "перенос из чужой связки ключей"
kill $DPID; wait $DPID 2>/dev/null || true
# «старая связка»: второй экземпляр со своей базой держит имя на шине
OLD_RT=$(mktemp -d); chmod 700 $OLD_RT; OLD_CFG=$(mktemp -d); mkdir -p $OLD_CFG/keywarden
printf 'o\no\n' | keepassxc-cli db-create -q -p $W/old.kdbx >/dev/null 2>&1 || cp $W/db.kdbx $W/old.kdbx
cat > $OLD_CFG/keywarden/config.toml <<CFG
database = "$W/old.kdbx"
secret_service = true
secret_service_confirm = false
CFG
XDG_RUNTIME_DIR=$OLD_RT XDG_CONFIG_HOME=$OLD_CFG $B/keywardend 2>$W/old.log &
OPID=$!
trap 'kill $DPID $OPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $OLD_RT/keywarden/daemon.sock ] && break; sleep 0.1; done
(echo o | XDG_RUNTIME_DIR=$OLD_RT XDG_CONFIG_HOME=$OLD_CFG $B/kw unlock --password-stdin) || (echo t | XDG_RUNTIME_DIR=$OLD_RT XDG_CONFIG_HOME=$OLD_CFG $B/kw unlock --password-stdin)
for i in $(seq 50); do grep -q "обслуживает" $W/old.log && break; sleep 0.1; done
printf 'wifi-pass' | secret-tool store --label="Домашний Wi-Fi" setting-name 802-11-wireless-security setting-key psk
printf 'docker-token' | secret-tool store --label="docker" server registry.example.com
# основной Keywarden без своего Secret Service переносит из старой связки
sed -i 's/^secret_service = true/secret_service = false/' $XDG_CONFIG_HOME/keywarden/config.toml
$B/keywardend 2>>$W/daemon.log &
DPID=$!
trap 'kill $DPID $OPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
echo t | $B/kw unlock --password-stdin
$B/kw secrets-import | tee $W/migrated.txt
grep -q "Перенесено секретов: 2" $W/migrated.txt
$B/kw lock
echo t | keepassxc-cli show -q -s -a Password $W/db.kdbx "/Secret Service/Домашний Wi-Fi" | grep -x wifi-pass
echo t | keepassxc-cli show -q -a setting-key $W/db.kdbx "/Secret Service/Домашний Wi-Fi" | grep -x psk
echo; echo "E2E SECRETS OK"
