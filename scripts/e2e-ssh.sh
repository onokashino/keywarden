#!/bin/sh
# SSH-ключ из базы работает через агент Keywarden и перестаёт работать после kw lock.
# Без сети: подпись `ssh-keygen -Y sign` через агент и проверка `ssh-keygen -Y verify`.
set -eu
export XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_STATE_HOME=$(mktemp -d) HOME=$(mktemp -d)
chmod 700 $XDG_RUNTIME_DIR
B=${CARGO_TARGET_DIR:-$(pwd)/target}/debug
W=$(mktemp -d)
mkdir -p $XDG_CONFIG_HOME/keywarden
# окно подтверждения: ответ из файла answer, сам запрос (JSON) сохраняется в prompt.json
printf 'confirm_command = ["sh", "-c", "printf %%s \\"$0\\" > %s/prompt.json; exit $(cat %s/answer)"]\n' $W $W > $XDG_CONFIG_HOME/keywarden/config.toml
echo 10 > $W/answer
$B/keywardend 2>$W/daemon.log &
DPID=$!
trap 'kill $DPID 2>/dev/null || true' EXIT
for i in $(seq 50); do [ -S $XDG_RUNTIME_DIR/keywarden/daemon.sock ] && break; sleep 0.1; done
echo "== новая база (только файл-ключ)"
printf 'test-keyfile-bytes' > $W/key.keyx
$B/kw new $W/db.kdbx --no-password -k $W/key.keyx
eval "$($B/kw ssh-env)"
echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"

echo "== ключи: ed25519 с паролем, ecdsa, rsa"
ssh-keygen -q -t ed25519 -N 'key-pass' -C ed@test -f $W/ed
ssh-keygen -q -t ecdsa -b 256 -N '' -C ec@test -f $W/ec
ssh-keygen -q -t rsa -b 3072 -N '' -C rsa@test -f $W/rsa
echo key-pass | $B/kw ssh-import $W/ed --title "ED key" --passphrase-stdin
$B/kw ssh-import $W/ec --title "EC key" --confirm
$B/kw ssh-import $W/rsa --title "RSA key"
ssh-add -L | sort
test "$(ssh-add -L | wc -l)" = 3

echo "== подпись через агент и проверка"
echo "данные для подписи" > $W/msg
for k in ed ec rsa; do
  ssh-keygen -q -Y sign -f $W/$k.pub -n test $W/msg
  echo "$k@test $(cat $W/$k.pub | cut -d' ' -f1,2)" > $W/allowed
  ssh-keygen -q -Y verify -f $W/allowed -I $k@test -n test -s $W/msg.sig < $W/msg
  echo "$k: подпись верна"
  rm $W/msg.sig
done

echo "== ключ с подтверждением: отказ"
echo 1 > $W/answer
! ssh-keygen -q -Y sign -f $W/ec.pub -n test $W/msg 2>/dev/null
echo "ec: подпись без подтверждения не прошла"
echo "== «разрешить на 15 минут»: дальше без вопроса, после блокировки снова спрашивает"
echo 11 > $W/answer
ssh-keygen -q -Y sign -f $W/ec.pub -n test $W/msg
echo 1 > $W/answer
rm -f $W/msg.sig
ssh-keygen -q -Y sign -f $W/ec.pub -n test $W/msg
echo "ec: в течение 15 минут подпись без окна"
$B/kw lock >/dev/null
$B/kw unlock --db $W/db.kdbx -k $W/key.keyx --no-password >/dev/null
rm -f $W/msg.sig
! ssh-keygen -q -Y sign -f $W/ec.pub -n test $W/msg 2>/dev/null
echo "ec: после блокировки разрешение сброшено"
echo 10 > $W/answer

echo "== ключ под каждый хост: ~/.ssh/keywarden/config"
mkdir -p $HOME/.ssh && printf 'Host mine\n  User me\n' > $HOME/.ssh/config
cp $HOME/.ssh/config $W/ssh-config.orig
$B/kw edit "RSA key" --url "git@github.com" >/dev/null
$B/kw edit "EC key" --url "ssh://git@gitlab.example.org:2222, github.com" >/dev/null
$B/kw ssh-setup --hosts
for i in $(seq 50); do [ -f $HOME/.ssh/keywarden/config ] && break; sleep 0.1; done
cat $HOME/.ssh/keywarden/config
grep -qx "Include ~/.ssh/keywarden/config" $HOME/.ssh/config
test "$(ls $HOME/.ssh/keywarden/*.pub | wc -l)" = 2
# ssh берёт ~ из /etc/passwd, а не из $HOME: файл Keywarden подаём явно через -F
ssh -F $HOME/.ssh/keywarden/config -G github.com > $W/g
grep -qi "^identitiesonly yes" $W/g
grep -qi "^identityfile .*keywarden/rsa-key.pub" $W/g
grep -qi "^identityfile .*keywarden/ec-key.pub" $W/g
grep -qi "^identityagent .*ssh.sock" $W/g
ssh -F $HOME/.ssh/keywarden/config -G gitlab.example.org | grep -qi "^identityfile .*keywarden/ec-key.pub"
grep -q "^Host mine" $HOME/.ssh/config
echo "ssh выбирает ключи по хосту, свои настройки пользователя целы"
$B/kw ssh --list | tee $W/hosts
grep -q "git@github.com" $W/hosts
grep -q "git@gitlab.example.org:2222" $W/hosts
grep -qP "^~/.ssh/config\tmine\tme@mine$" $W/hosts
test "$($B/kw ssh --list gitlab | wc -l)" = 1
echo "kw ssh видит хосты ключей из базы и ~/.ssh/config"
$B/kw ssh-setup --no-hosts
sleep 0.3
! test -e $HOME/.ssh/keywarden
cmp $HOME/.ssh/config $W/ssh-config.orig
echo "выключение вернуло ~/.ssh/config как было"

echo "== перенос ключей из ~/.ssh"
ssh-keygen -q -t ed25519 -N '' -C home@test -f $HOME/.ssh/id_ed25519
ssh-keygen -q -t ed25519 -N 'secret' -C enc@test -f $HOME/.ssh/id_enc
cp $W/rsa $HOME/.ssh/id_rsa
$B/kw ssh-migrate | tee $W/mig
grep "id_ed25519 " $W/mig | grep -q "kw ssh-migrate --import"
grep "id_enc " $W/mig | grep -q "kw ssh-import"
grep "id_rsa " $W/mig | grep -qE "в базе$"
$B/kw ssh-migrate --import --delete
! test -e $HOME/.ssh/id_ed25519
test -e $HOME/.ssh/id_ed25519.pub
test -e $HOME/.ssh/id_enc && test -e $HOME/.ssh/id_rsa
ssh-add -L | grep -q "$(cut -d' ' -f2 $HOME/.ssh/id_ed25519.pub)"
echo "новый ключ перенесён и удалён с диска, зашифрованный и уже известный не тронуты"

echo "== новый ключ ed25519 прямо в базе"
$B/kw ssh-generate --title "Gen key" --host example.test > $W/gen.pub
cat $W/gen.pub
grep -q "^ssh-ed25519 .* Gen key$" $W/gen.pub
ssh-add -L | grep -q "$(cut -d' ' -f2 $W/gen.pub)"
echo gen > $W/msg2
ssh-keygen -q -Y sign -f $W/gen.pub -n test $W/msg2
printf 'gen@test %s\n' "$(cut -d' ' -f1,2 $W/gen.pub)" > $W/allowed2
ssh-keygen -q -Y verify -f $W/allowed2 -I gen@test -n test -s $W/msg2.sig < $W/msg2
echo "созданный ключ подписывает через агент, приватный ключ на диск не попал"
$B/kw ssh-generate --title "Gen ecdsa" -t ecdsa | grep -q "^ecdsa-sha2-nistp256 .* Gen ecdsa$"
t0=$(date +%s)
$B/kw ssh-generate --title "Gen rsa" -t rsa | grep -q "^ssh-rsa .* Gen rsa$"
ssh-add -l | grep -q "4096 .* Gen rsa (RSA)"
echo "ECDSA P-256 и RSA 4096 ($(($(date +%s) - t0)) с) тоже создаются"

echo "== настоящий вход по ssh: session-bind, имя сервера в окне подтверждения"
mkdir -p $W/sshd
ssh-keygen -q -t ed25519 -N '' -f $W/sshd/host
cut -d' ' -f1,2 $W/ec.pub > $W/sshd/authorized_keys
cat > $W/sshd/config <<CFG
Port 22022
ListenAddress 127.0.0.1
HostKey $W/sshd/host
PidFile $W/sshd/pid
AuthorizedKeysFile $W/sshd/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
CFG
$(command -v sshd || echo /usr/bin/sshd) -f $W/sshd/config -E $W/sshd/log
for i in $(seq 50); do [ -f $W/sshd/pid ] && break; sleep 0.1; done
echo 10 > $W/answer
ssh -F none -p 22022 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile=$HOME/.ssh/known_hosts -o IdentitiesOnly=yes -i $W/ec.pub 127.0.0.1 true \
  || { echo "--- sshd"; cat $W/sshd/log; echo "--- daemon"; tail -15 $W/daemon.log; echo "--- prompt"; cat $W/prompt.json 2>/dev/null; exit 1; }
cat $W/prompt.json; echo
grep -q '127.0.0.1:22022' $W/prompt.json
echo "вход по ssh через агент прошёл, в окне видно, куда входят"

echo "== серверы из ~/.ssh/config в базе: импорт, свой конфиг, port knocking"
printf 'Host lab\n  HostName 127.0.0.1\n  Port 22022\n  IdentityFile %s/ec\n  ServerAliveInterval 30\n' $W > $HOME/.ssh/config
$B/kw ssh-import-config | tee $W/imp
grep -q "1, .* 0" $W/imp
$B/kw ssh-import-config | grep -q "0, .* 1"
$B/kw show lab | tee $W/lab
grep -q "EC key" $W/lab
$B/kw edit lab --field "Port Knock=22023 22024:udp" >/dev/null
$B/kw ssh --list | tee $W/hosts
test "$(grep -c "	lab	" $W/hosts)" = 1
grep -qP "^SSH\tlab\t127.0.0.1:22022$" $W/hosts
$B/kw ssh-setup --hosts
for i in $(seq 50); do grep -q "Host lab" $HOME/.ssh/keywarden/config 2>/dev/null && break; sleep 0.1; done
cat $HOME/.ssh/keywarden/config
grep -q "^Match originalhost lab exec \"'.*/kw' knock lab\"$" $HOME/.ssh/keywarden/config
grep -q "^  ServerAliveInterval 30$" $HOME/.ssh/keywarden/config
# кто стучал: TCP 22023, потом UDP 22024
python3 -I - $W/knocks <<'PY' &
import socket, sys, select
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1", 22023)); t.listen()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 22024))
got = []
while len(got) < 2:
    r, _, _ = select.select([t, u], [], [], 20)
    if not r: break
    for s in r:
        if s is t: s.accept(); got.append("tcp")
        else: s.recvfrom(16); got.append("udp")
open(sys.argv[1], "w").write(" ".join(got))
PY
KPID=$!
sleep 0.5
echo 10 > $W/answer
ssh -F $HOME/.ssh/keywarden/config -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile=$HOME/.ssh/known_hosts -i $HOME/.ssh/keywarden/ec-key.pub lab true \
  || { echo "--- sshd"; cat $W/sshd/log; echo "--- daemon"; tail -15 $W/daemon.log; exit 1; }
wait $KPID
test "$(cat $W/knocks)" = "tcp udp"
echo "ssh lab: стук tcp, udp по порядку, вход ключом из базы"
$B/kw lock >/dev/null
! $B/kw knock lab 2>/dev/null
$B/kw unlock --db $W/db.kdbx -k $W/key.keyx --no-password >/dev/null
$B/kw ssh-setup --no-hosts
echo "заблокированная база не стучит"
kill $(cat $W/sshd/pid)

echo "== подпись коммитов git ключом из базы"
git config --global user.name "E2E"
git config --global user.email e2e@test
$B/kw ssh-git-sign "Gen key"
git init -q $W/repo
git -C $W/repo commit -q --allow-empty -m signed
git -C $W/repo log --show-signature -1 2>&1 | tee $W/sig | head -3
grep -q 'Good "git" signature for e2e@test' $W/sig
$B/kw ssh-git-sign --off
test -z "$(git config --global --get gpg.format || true)"
echo "коммит подписан ключом из базы, выключение убрало настройки git"

echo "== после kw lock ключей нет"
$B/kw lock
! ssh-add -L >/dev/null 2>&1
! ssh-keygen -q -Y sign -f $W/ed.pub -n test $W/msg 2>/dev/null
echo "после блокировки агент пуст, подпись невозможна"

echo "== KeePassXC видит ключи как KeeAgent"
echo | keepassxc-cli ls -q -k $W/key.keyx --no-password $W/db.kdbx
echo | keepassxc-cli attachment-export -q -k $W/key.keyx --no-password --stdout $W/db.kdbx "ED key" KeeAgent.settings | grep -q "<AttachmentName>ed</AttachmentName>"
echo "KeeAgent.settings на месте"
! grep -E "key-pass|PRIVATE KEY" $W/daemon.log
echo "E2E SSH OK"
