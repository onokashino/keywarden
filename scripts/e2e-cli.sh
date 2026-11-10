#!/bin/sh
# Сквозная проверка демона и kw на базе из KeePassXC. Запускать в docker: make e2e
set -eu
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
B=${CARGO_TARGET_DIR:-target}/debug
W=$(mktemp -d)
printf 't\nt\n' | keepassxc-cli import -q -p -t 100 crates/keywarden-core/tests/fixtures/kpxc-full.xml $W/db.kdbx >/dev/null

$B/keywardend 2>$W/daemon.log &
DPID=$!
trap 'kill $DPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done

step() { printf '\n== %s\n' "$*"; }
step status; $B/kw status
step "unlock (неверный пароль)"; ! echo wrong | $B/kw unlock --db $W/db.kdbx --password-stdin
step unlock; echo t | $B/kw unlock --db $W/db.kdbx --password-stdin
step "search git"; $B/kw search git
step "show GitHub"; $B/kw show GitHub
step "totp GitHub"; $B/kw totp GitHub
step "totp Old 2FA (TOTP Seed)"; $B/kw totp "Old 2FA"
step "add card"; $B/kw mkgroup Finance/Cards
$B/kw add -t card --title "Mir" -g Finance/Cards --field "Cardholder=PETR" --field "Card Number=2200111122223333"
$B/kw show Mir
step "edit"; $B/kw edit GitHub --url https://github.com/login --field "Recovery code=NEW-CODE"
step "generate"; $B/kw generate -l 24; $B/kw generate -p -w 5
step "attach"; echo "hello" > $W/note.txt; $B/kw attach GitHub $W/note.txt --name extra.txt; $B/kw attachment GitHub extra.txt
step "импорт Bitwarden"; $B/kw import-bitwarden crates/keywarden-core/tests/fixtures/bitwarden.json
echo t | keepassxc-cli show -q -s -a Password $W/db.kdbx "/Bitwarden/Dev/Work/GitHub" | grep -x gh-pass
echo t | keepassxc-cli show -q -s -a "Card Number" $W/db.kdbx "/Bitwarden/Финансы/Visa" | grep -x 4111111111111111
step "rm"; $B/kw rm Visa --first
step "синхронизация: KeePassXC пишет в файл, пока база открыта в Keywarden"
printf 't\nвнешний-пароль\n' | keepassxc-cli add -q -p -u from-kpxc $W/db.kdbx "/Из KeePassXC" >/dev/null
for i in $(seq 30); do $B/kw search "Из KeePassXC" 2>/dev/null | grep -q "from-kpxc" && break; sleep 0.2; done
$B/kw search "Из KeePassXC" | grep from-kpxc
$B/kw edit 00000000-0000-0000-0000-000000000003 --field "После синхронизации=да" # правка поверх слитой базы
echo t | keepassxc-cli show -q $W/db.kdbx "/Из KeePassXC" | grep "UserName: from-kpxc"
grep -q "База синхронизирована" $W/daemon.log && echo "в логе: база синхронизирована"
step "теги, срок действия, поиск, дубль, перемещение, ссылки"
$B/kw edit "url:github.com/login -group:Bitwarden" --tag dev --tag git --expires 2000-01-01
$B/kw tags | grep -x "#dev  \[1\]"
$B/kw search "is:expired" | grep -q GitHub
$B/kw search "#dev user:octo" | grep -q GitHub
! $B/kw search "#dev -#git" | grep -q GitHub
$B/kw dup "url:github.com/login -group:Bitwarden" >/dev/null
$B/kw search '"GitHub (копия)"' | grep -q "копия"
$B/kw mv "GitHub (копия)" Finance/Cards
$B/kw search "group:Cards" | grep -q "копия"
$B/kw add --title "Ссылка" -u "{REF:U@N:многострочная}"
$B/kw show "Ссылка" | grep -q octo
$B/kw edit "url:github.com/login -group:Bitwarden -копия" --expires none
! $B/kw search "is:expired" | grep -q GitHub
echo t | keepassxc-cli show -q $W/db.kdbx "/Finance/Cards/GitHub (копия)" | grep -q "UserName: octo"
step "2FA: задать секретом, QR в терминале, экспорт и импорт 2FAS"
$B/kw add --title "Новый 2FA" -u me
$B/kw otp set "Новый 2FA" "jbsw y3dp ehpk 3pxp"
$B/kw totp "Новый 2FA" | grep -Eq "^[0-9]{6}"
echo t | keepassxc-cli show -q -s -a otp $W/db.kdbx "/Новый 2FA" 2>/dev/null | grep -q "otpauth://totp/%D0%9D%D0%BE%D0%B2%D1%8B%D0%B9%202FA:me?secret=JBSWY3DPEHPK3PXP" || echo t | keepassxc-cli show -q -s -a otp $W/db.kdbx "/Новый 2FA" | grep -q "secret=JBSWY3DPEHPK3PXP"
$B/kw otp qr "Новый 2FA" 2>/dev/null | grep -q "█"
! $B/kw otp set "Новый 2FA" "не секрет"
$B/kw export -f 2fas $W/codes.2fas
grep -q '"schemaVersion": 4' $W/codes.2fas
$B/kw import $W/codes.2fas
$B/kw search "group:2FAS" | grep -q "Новый 2FA"
step "проверка паролей"
$B/kw health | tee $W/health.txt | head -3
grep -q "Проверено" $W/health.txt
grep -q "слабый" $W/health.txt
if curl -sf -m 5 https://api.pwnedpasswords.com/range/21BD1 >/dev/null 2>&1; then
  $B/kw health --breaches | grep -q "в утечках"
  echo "HIBP: проверено вживую"
else
  echo "HIBP недоступен из контейнера: проверка утечек пропущена"
fi
step "иконка сайта"
if curl -sf -m 5 -o /dev/null https://github.com/; then
  $B/kw icon "url:github.com/login -group:Bitwarden -копия"
  echo t | keepassxc-cli show -q -s $W/db.kdbx /GitHub >/dev/null
  $B/kw icon --clear "url:github.com/login -group:Bitwarden -копия"
  echo "favicon: проверено вживую"
else
  echo "github.com недоступен из контейнера: favicon пропущен"
fi
step "настройки базы"
$B/kw db-settings --name "E2E" --history 5 --memory 16 --iterations 2
$B/kw db-settings | grep -x "Имя:        E2E"
! $B/kw db-settings --memory 1
step "экспорт CSV и импорт обратно"
$B/kw export $W/out.csv
head -1 $W/out.csv | grep -q '"Group","Title","Username","Password"'
test "$(stat -c %a $W/out.csv)" = 600
$B/kw import $W/out.csv
$B/kw groups | grep -q "Импорт out"
step "копия .kdbx с другим паролем и слияние с ней"
echo copy-pw | $B/kw export -f kdbx --password-stdin $W/copy.kdbx
echo copy-pw | keepassxc-cli ls -q $W/copy.kdbx | grep -q GitHub
printf 'copy-pw\nиз-копии\n' | keepassxc-cli add -q -p -u merged-user $W/copy.kdbx "/Из копии" >/dev/null
echo copy-pw | $B/kw merge --password-stdin $W/copy.kdbx
$B/kw search "Из копии" | grep -q merged-user
step "смена ключа: новый пароль + файл-ключ, потом обратно"
$B/kw keyfile $W/new.keyx
! $B/kw keyfile $W/new.keyx
! printf 'wrong\nx\n' | $B/kw passwd --password-stdin
printf 't\nnew-pw\n' | $B/kw passwd --password-stdin -k $W/new.keyx
echo new-pw | keepassxc-cli ls -q -k $W/new.keyx $W/db.kdbx | grep -q GitHub
! echo t | keepassxc-cli ls -q $W/db.kdbx 2>/dev/null
$B/kw lock
! echo t | $B/kw unlock --password-stdin
echo new-pw | $B/kw unlock --password-stdin
printf 'new-pw\nt\n' | $B/kw passwd --password-stdin
echo t | keepassxc-cli ls -q $W/db.kdbx | grep -q GitHub
step "несколько баз: профиль work со своим демоном"
printf 'w\nw\n' | keepassxc-cli db-create -q -p $W/work.kdbx >/dev/null 2>&1
printf 'w\nрабочий-пароль\n' | keepassxc-cli add -q -p -u worker $W/work.kdbx "Jira рабочая" >/dev/null
$B/kw profile-add work $W/work.kdbx
! $B/kw profile-add work $W/work.kdbx
$B/keywardend --profile work 2>$W/work.log &
WPID=$!
trap 'kill $DPID $WPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/profiles/work/daemon.sock ] && break; sleep 0.1; done
echo w | $B/kw --profile work unlock --password-stdin
$B/kw --profile work search jira | grep -q worker
! $B/kw search "Jira рабочая" | grep -q worker
KEYWARDEN_PROFILE=work $B/kw search jira | grep -q worker
$B/kw profiles | tee $W/profiles.txt
grep -q "^default  открыта" $W/profiles.txt
grep -q "^work  открыта" $W/profiles.txt
$B/kw --profile work edit "Jira рабочая" -u worker2
echo w | keepassxc-cli show -q $W/work.kdbx "/Jira рабочая" | grep -q "UserName: worker2"
$B/kw --profile work lock
grep -q "^work  заблокирована" <<EOT
$($B/kw profiles)
EOT
kill $WPID; wait $WPID 2>/dev/null || true
step "lock"; $B/kw lock; ! $B/kw search git
step "конфиг запомнил базу"; cat $XDG_CONFIG_HOME/keywarden/config.toml | grep database
step "бэкапы"; ls $XDG_STATE_HOME/keywarden/backups/*/ | head
kill $DPID; wait $DPID 2>/dev/null || true

step "KeePassXC видит правки"
echo t | keepassxc-cli show -q -s $W/db.kdbx /GitHub | grep "URL: https://github.com/login"
echo t | keepassxc-cli show -q -s -a "Recovery code" $W/db.kdbx /GitHub | grep NEW-CODE
echo t | keepassxc-cli show -q -s -a "Card Number" "$W/db.kdbx" "/Finance/Cards/Mir"
echo t | keepassxc-cli ls -q -R $W/db.kdbx | grep -A2 "Recycle"
step "в логе демона нет секретов"
test -s $W/daemon.log
! grep -E "s3cr3t|2200111122223333|NEW-CODE|JBSWY3DP|^t$" $W/daemon.log
cat $W/daemon.log
echo; echo "E2E OK"
exit 0
