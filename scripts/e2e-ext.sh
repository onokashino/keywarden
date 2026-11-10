#!/bin/sh
# E2E расширения в docker: демон + host + headless Chromium. make e2e-ext
set -eu
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
chmod 700 $XDG_RUNTIME_DIR
B=${CARGO_TARGET_DIR:-$(pwd)/target}/debug
W=$(mktemp -d)
printf 't\nt\n' | keepassxc-cli import -q -p -t 100 crates/keywarden-core/tests/fixtures/kpxc-full.xml $W/db.kdbx >/dev/null
mkdir -p $XDG_CONFIG_HOME/keywarden
# окна подтверждения нет (headless): «разрешить всегда» отвечает скрипт
printf 'database = "%s"\nconfirm_command = ["sh", "-c", "exit 11"]\n' $W/db.kdbx > $XDG_CONFIG_HOME/keywarden/config.toml
$B/keywardend 2>$W/daemon.log &
DPID=$!
trap 'kill $DPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
echo t | $B/kw unlock --password-stdin
$B/kw add --title "Test site" -u tester --url http://127.0.0.1:8765 --field "Password=S3cret-from-db" >/dev/null
$B/kw add --title "OTP site" -u otpuser --url http://127.0.0.2:8765 --field "Password=Otp-site-pass" --field "otp=otpauth://totp/OTP:otpuser?secret=JBSWY3DPEHPK3PXP&issuer=OTP" >/dev/null
$B/kw add --type wallet --title "Cold wallet" --field "Seed=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --field "Addresses=основной: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" >/dev/null
cd tests/e2e-ext && npm install --silent --no-audit --no-fund >/dev/null && node test.mjs ../../extension/.output/chrome-mv3 $B/keywarden-host
cd ../..
echo "--- KeePassXC видит ключ доступа в своём формате:"
echo t | keepassxc-cli show -q -s -a KPEX_PASSKEY_RELYING_PARTY $W/db.kdbx "/Из браузера/Local Test"
echo t | keepassxc-cli show -q -s -a KPEX_PASSKEY_PRIVATE_KEY_PEM $W/db.kdbx "/Из браузера/Local Test" | head -1
echo "--- daemon.log без секретов:"
! grep -E "S3cret|Brand-new|PRIVATE KEY" $W/daemon.log
