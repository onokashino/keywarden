#!/bin/sh
# Установка Keywarden в домашний каталог (без root). Бинарники берутся из target/release
# (собрать: make build). Ничего не перезаписывает в чужих конфигах: для niri и Noctalia
# печатает, что добавить вручную.
set -eu
BIN=${BIN:-$HOME/.local/bin}
R=${R:-target/release}
# из архива релиза: бинарники лежат рядом со скриптом
[ -x "$(dirname "$0")/keywardend" ] && R=$(dirname "$0")
for b in keywardend kw keywarden-ui keywarden-host; do
  [ -x $R/$b ] || { echo "нет $R/$b, сначала make build"; exit 1; }
done
mkdir -p "$BIN" ~/.config/systemd/user ~/.local/share/applications ~/.config/keywarden/themes
install -m 0755 $R/keywardend $R/kw $R/keywarden-ui $R/keywarden-host "$BIN/"
install -m 0644 dist/systemd/keywardend.service dist/systemd/keywardend@.service ~/.config/systemd/user/
install -m 0644 dist/keywarden.desktop ~/.local/share/applications/

# native messaging: Firefox и Chromium-браузеры
for dir in ~/.mozilla/native-messaging-hosts; do
  mkdir -p "$dir"
  sed "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" dist/native-messaging/firefox.json > "$dir/dev.keywarden.host.json"
done
for dir in ~/.config/chromium/NativeMessagingHosts ~/.config/google-chrome/NativeMessagingHosts ~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts; do
  [ -d "$(dirname "$dir")" ] || continue
  mkdir -p "$dir"
  sed -e "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" -e "s|REPLACE_WITH_EXTENSION_ID|${CHROMIUM_EXTENSION_ID:-REPLACE_WITH_EXTENSION_ID}|" dist/native-messaging/chromium.json > "$dir/dev.keywarden.host.json"
done

# шаблон темы для Noctalia
if [ -d ~/.config/noctalia ]; then
  mkdir -p ~/.config/noctalia/templates
  install -m 0644 dist/noctalia/keywarden.json ~/.config/noctalia/templates/keywarden.json
fi

systemctl --user daemon-reload
systemctl --user enable --now keywardend.service
echo
echo "Готово. Дальше вручную:"
echo " 1) niri: include \"keywarden.kdl\" (файл: dist/niri/keywarden.kdl → ~/.config/niri/)"
echo " 2) Noctalia: в ~/.config/noctalia/config.toml добавить"
echo '    [theme.templates.user.keywarden]'
echo '    input_path  = "templates/keywarden.json"'
echo '    output_path = "$XDG_CONFIG_HOME/keywarden/themes/noctalia.json"'
echo " 3) kw unlock --db ~/путь/к/базе.kdbx  (или kw new ~/путь/новая.kdbx)"
