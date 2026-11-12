#!/bin/sh
# Installs Keywarden into the home directory (no root). Binaries come from target/release
# (build: make build). Never overwrites other programs' configs: for niri and Noctalia it
# prints what to add by hand.
set -eu
BIN=${BIN:-$HOME/.local/bin}
R=${R:-target/release}
# from a release archive: the binaries sit next to the script
[ -x "$(dirname "$0")/keywardend" ] && R=$(dirname "$0")
for b in keywardend kw keywarden-ui keywarden-host; do
  [ -x $R/$b ] || { echo "missing $R/$b, run make build first"; exit 1; }
done
mkdir -p "$BIN" ~/.config/systemd/user ~/.local/share/applications ~/.config/keywarden/themes
install -m 0755 $R/keywardend $R/kw $R/keywarden-ui $R/keywarden-host "$BIN/"
install -m 0644 dist/systemd/keywardend.service dist/systemd/keywardend@.service ~/.config/systemd/user/
install -m 0644 dist/keywarden.desktop ~/.local/share/applications/

# native messaging: Firefox and Chromium-based browsers
for dir in ~/.mozilla/native-messaging-hosts; do
  mkdir -p "$dir"
  sed "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" dist/native-messaging/firefox.json > "$dir/dev.keywarden.host.json"
done
for dir in ~/.config/chromium/NativeMessagingHosts ~/.config/google-chrome/NativeMessagingHosts ~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts; do
  [ -d "$(dirname "$dir")" ] || continue
  mkdir -p "$dir"
  sed -e "s|/usr/bin/keywarden-host|$BIN/keywarden-host|" -e "s|REPLACE_WITH_EXTENSION_ID|${CHROMIUM_EXTENSION_ID:-REPLACE_WITH_EXTENSION_ID}|" dist/native-messaging/chromium.json > "$dir/dev.keywarden.host.json"
done

# theme template for Noctalia
if [ -d ~/.config/noctalia ]; then
  mkdir -p ~/.config/noctalia/templates
  install -m 0644 dist/noctalia/keywarden.json ~/.config/noctalia/templates/keywarden.json
fi

systemctl --user daemon-reload
systemctl --user enable --now keywardend.service
echo
echo "Done. Start the app: keywarden-ui. Optional:"
echo " 1) niri: include \"keywarden.kdl\" (copy dist/niri/keywarden.kdl to ~/.config/niri/)"
echo " 2) Noctalia: add to ~/.config/noctalia/config.toml"
echo '    [theme.templates.user.keywarden]'
echo '    input_path  = "templates/keywarden.json"'
echo '    output_path = "$XDG_CONFIG_HOME/keywarden/themes/noctalia.json"'
echo " 3) kw unlock --db ~/path/to/vault.kdbx  (or kw new ~/path/new.kdbx)"
