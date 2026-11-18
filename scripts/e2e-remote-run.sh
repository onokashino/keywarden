#!/bin/sh
# Запускает e2e-remote.sh в двух контейнерах рядом с сервером WebDAV (Apache mod_dav;
# сборка на Debian: в alpine нет DBM для базы блокировок, и PUT отвечает 500).
# Аргументы: образ разработки, лимит памяти, метка контейнеров, каталог кэша cargo.
set -eu
IMAGE=$1 MEM=$2 LABEL=$3 CACHE=$4
NET=keywarden-e2e-remote
SHARED=$(mktemp -d)
NET2=keywarden-e2e-remote2
cleanup() {
  # KEEP=1: сервер и сеть остаются для разбора
  [ "${KEEP:-}" = 1 ] && [ -n "${DONE:-}" ] && return 0
  docker rm -f keywarden-e2e-dav keywarden-e2e-a keywarden-e2e-b >/dev/null 2>&1 || true
  docker network rm $NET $NET2 >/dev/null 2>&1 || true
  rm -rf "$SHARED"
}
trap cleanup EXIT
cleanup
SHARED=$(mktemp -d)
chmod 777 "$SHARED"
# свой диапазон: стандартные пулы docker бывают исчерпаны
docker network create --subnet 10.247.47.0/24 $NET >/dev/null
# SPLIT=1: b только во второй сети, a в обеих (путь по умолчанию у a через первую). Маяк a
# дойдёт до b, только если рассылается в каждую сеть, а не на один 255.255.255.255
docker network create --subnet 10.247.48.0/24 $NET2 >/dev/null
DAV_ENV=
if [ "${DAV_KIND:-apache}" = nextcloud ]; then
  # настоящий Nextcloud (SQLite): свои ETag, OC-ETag и пароли приложений
  docker run -d --name keywarden-e2e-dav --network $NET --network-alias dav --label $LABEL \
    --memory 1g --memory-swap 1g -e SQLITE_DATABASE=nextcloud -e NEXTCLOUD_ADMIN_USER=kw \
    -e NEXTCLOUD_ADMIN_PASSWORD=kw-secret-pass -e NEXTCLOUD_TRUSTED_DOMAINS=dav nextcloud:apache >/dev/null
  for i in $(seq 120); do
    docker exec keywarden-e2e-dav curl -fsS -o /dev/null -u kw:kw-secret-pass -X PROPFIND http://localhost/remote.php/dav/files/kw/ 2>/dev/null && break
    sleep 2
  done
  DAV_ENV="-e DAV_URL=http://dav/remote.php/dav/files/kw/vault.kdbx -e DAV_USER=kw -e DAV_PASS=kw-secret-pass"
else
docker run -d --name keywarden-e2e-dav --network $NET --network-alias dav --label $LABEL \
  --memory 256m --memory-swap 256m httpd:2.4 sh -c '
    cd /usr/local/apache2
    mkdir -p htdocs/dav var && chown www-data htdocs/dav var
    htpasswd -bc conf/htpasswd kw secret
    cat >> conf/httpd.conf <<CONF
LoadModule dav_module modules/mod_dav.so
LoadModule dav_fs_module modules/mod_dav_fs.so
DavLockDB /usr/local/apache2/var/DavLock
<Directory "/usr/local/apache2/htdocs/dav">
  Dav On
  AuthType Basic
  AuthName dav
  AuthUserFile /usr/local/apache2/conf/htpasswd
  Require valid-user
</Directory>
CONF
    exec httpd-foreground' >/dev/null
fi
docker network connect --alias dav $NET2 keywarden-e2e-dav
run() {
  net=$NET
  [ "${SPLIT:-}" = 1 ] && [ $1 = b ] && net=$NET2
  docker create --name keywarden-e2e-$1 --network $net --label $LABEL --memory $MEM --memory-swap $MEM \
    --user "$(id -u):$(id -g)" -v "$PWD":/app -w /app -v "$SHARED":/shared \
    -v "$CACHE/cargo":/cargo -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/app/target -e KEYWARDEN_LANG=ru \
    $DAV_ENV "$IMAGE" sh scripts/e2e-remote.sh $1 >/dev/null
  [ "${SPLIT:-}" = 1 ] && [ $1 = a ] && docker network connect $NET2 keywarden-e2e-$1
  docker start -a keywarden-e2e-$1
}
run a > "$SHARED/a.log" 2>&1 &
A=$!
run b > "$SHARED/b.log" 2>&1 &
BP=$!
ok=0
wait $A || ok=1
wait $BP || ok=1
cat "$SHARED/a.log" "$SHARED/b.log"
DONE=1
exit $ok
