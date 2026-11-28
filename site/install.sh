#!/bin/sh
# Keywarden installer for Linux (x86_64) and macOS (Apple Silicon):
#   curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
# Downloads the release archive from GitHub, checks it against SHA256SUMS and installs
# into ~/.local/bin without root. A specific version: ... | KEYWARDEN_VERSION=v0.1.0 sh
# When a release signing key is set below, SHA256SUMS must also carry a valid signature
# (SHA256SUMS.sig, checked with ssh-keygen); KEYWARDEN_UNSIGNED=1 skips that for old releases.
# Run it again any time: with Keywarden already installed it checks the installation and
# offers to fix what is broken, update, or pick the optional parts.
# KEYWARDEN_PARTS picks them without questions, space separated: browser ssh niri noctalia.
# KEYWARDEN_YES=1: no questions, install or update. NO_COLOR=1: plain output.
# KEYWARDEN_NO_LAUNCH=1: do not open the app at the end.
# Everything is inside main() so a download cut off halfway runs nothing.
set -eu

main() {
  repo=onokashino/keywarden
  # language: KEYWARDEN_LANG=ru|en, otherwise the session locale; "l" in the menu switches it
  lang=${KEYWARDEN_LANG:-}
  if [ -z "$lang" ]; then case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ru*) lang=ru ;; *) lang=en ;; esac; fi
  # a terminal that is not UTF-8 would show boxes instead of marks and Cyrillic
  case "$(locale charmap 2>/dev/null || printf '%s' "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}")" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) ;;
    *) OKM='+' BADM='x' DIA='*'; SPIN=; [ -n "${KEYWARDEN_LANG:-}" ] || lang=en ;;
  esac
  switch_lang; switch_lang
  said=; tmp=
  trap 'on_exit $?' EXIT
  trap 'said=1; exit 130' INT TERM
  base=${KEYWARDEN_MIRROR:-https://github.com/$repo/releases/download}
  bin=${BIN:-$HOME/.local/bin}
  amo=https://addons.mozilla.org/firefox/addon/keywarden/
  # public half of the release signing key (packaging/release-key.pub); empty: checksum only
  signer=''

  printf '\n  %s%s Keywarden%s %s%s%s\n\n' "$V$B" "$DIA" "$N" "$D" "$(m 'installer')" "$N"
  # everything goes into the home directory of the person who runs this; root has another one
  if [ "$(id -u)" = 0 ] && [ -z "${KEYWARDEN_ROOT:-}" ]; then
    die "$(m 'run this as your own user, without sudo: Keywarden installs into your home directory')"
  fi
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=linux-x86_64 ;;
    Darwin-arm64) target=macos-arm64 ;;
    *) die "$(m 'no ready build for %s. Build from source: %s' "$(uname -s) $(uname -m)" https://onokashino.github.io/keywarden/docs/#install)" ;;
  esac
  need curl
  need tar
  if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then sum="shasum -a 256"
  else die "$(m 'needs %s' 'sha256sum / shasum')"; fi

  tag=${KEYWARDEN_VERSION:-}
  if [ -z "$tag" ]; then
    # /releases/latest redirects to /releases/tag/vX.Y.Z; no API call, no rate limit
    tag=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") \
      || die "$(m 'cannot reach github.com to find the latest release. Check the connection or a proxy (https_proxy), or name the version: %s' 'KEYWARDEN_VERSION=v0.2.10')"
    tag=${tag##*/}
  fi
  case "$tag" in v[0-9]*) ;; *) die "$(m 'no published release yet: %s' "https://github.com/$repo/releases")" ;; esac

  mkdir -p "$bin" 2>/dev/null && [ -w "$bin" ] || die "$(m 'cannot write to %s. Pick another folder: %s' "$bin" 'BIN=~/bin')"

  # questions only when a person is at the terminal; the script itself may be coming from a pipe
  talk=
  if [ -t 1 ] && [ -z "${KEYWARDEN_YES:-}" ] && (exec < /dev/tty) 2>/dev/null; then talk=1; fi
  have=
  [ ! -x "$bin/kw" ] || have=$("$bin/kw" --version 2>/dev/null | awk '{ print $NF }')
  if [ -n "$have" ]; then
    diagnose
    if [ -n "$talk" ]; then menu; fi
  elif [ -n "$talk" ]; then
    while :; do
      printf '  %s ' "$(m '%sEnter%s installs everything, %sc%s lets you choose the parts, %sl%s: %s' "$B" "$N" "$B" "$N" "$B" "$N" "$other")"
      read -r a < /dev/tty || a=
      case "$a" in l|L) switch_lang ;; c|C) choose_parts; break ;; *) break ;; esac
    done
  fi
  export KEYWARDEN_LANG="$lang"
  [ -z "${KEYWARDEN_PARTS+x}" ] || export KEYWARDEN_PARTS
  ok "$(m 'release %s for %s' "$B$tag$N" "$target")"

  file=keywarden-$tag-$target.tar.gz
  tmp=$(mktemp -d) || die "$(m 'cannot create a temporary folder (is the disk full?)')"
  fetch "$base/$tag/$file" "$tmp/$file" &
  spin $! "$(m 'downloading %s' "$file")" || die "$(m 'download failed: %s' "$base/$tag/$file")"
  fetch "$base/$tag/SHA256SUMS" "$tmp/SHA256SUMS" || die "$(m 'download failed: %s' SHA256SUMS)"
  ok "$(m 'downloaded %s' "$(du -h "$tmp/$file" | cut -f1 | tr -d ' ')")"
  want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
  got=$(cd "$tmp" && $sum "$file" | awk '{ print $1 }')
  [ -n "$want" ] || die "$(m '%s is not listed in SHA256SUMS' "$file")"
  [ "$want" = "$got" ] || die "$(m 'checksum mismatch for %s, nothing installed' "$file")"
  ok "$(m 'checksum matches SHA256SUMS')"
  # the checksum file sits next to the archive, so on its own it only catches a broken download;
  # the signature proves the list was made by the holder of the release key
  if [ -n "$signer" ] && [ -z "${KEYWARDEN_UNSIGNED:-}" ]; then
    command -v ssh-keygen >/dev/null 2>&1 || die "$(m 'ssh-keygen is needed to check the release signature (package: openssh)')"
    fetch "$base/$tag/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" || die "$(m 'this release has no signature (SHA256SUMS.sig), nothing installed')"
    printf 'release@keywarden %s\n' "$signer" > "$tmp/signers"
    ssh-keygen -Y verify -f "$tmp/signers" -I release@keywarden -n keywarden-release \
      -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" >/dev/null 2>&1 \
      || die "$(m 'release signature does not match, nothing installed')"
    ok "$(m 'release signature is valid')"
  fi
  tar xzf "$tmp/$file" -C "$tmp" || die "$(m 'cannot unpack the archive (is the disk full?)')"
  dir=$tmp/keywarden-$tag-$target
  # the programs must start here before anything is replaced: an older system library (glibc),
  # another C library (musl) or a system without the usual loader (NixOS) shows up right now
  why=$("$dir/kw" --version 2>&1) || die "$(m 'the downloaded programs do not start on this system, nothing was changed. The system says: %s. Usually the system is older than this build needs. Build from source: %s' "$(printf '%s' "$why" | head -n 1)" https://onokashino.github.io/keywarden/docs/#install)"
  running=
  [ -z "$have" ] || ! command -v pgrep >/dev/null 2>&1 || ! pgrep -x keywarden-ui >/dev/null 2>&1 || running=1

  if [ "$target" = linux-x86_64 ]; then
    # the archive's own script: binaries, service, menu entry, browsers, niri, Noctalia
    (cd "$dir" && BIN="$bin" sh ./install.sh)
  else
    mkdir -p "$bin"
    for b in keywardend kw keywarden-ui keywarden-host; do
      install -m 0755 "$dir/$b" "$bin/$b"
    done
    ok "$(m 'programs in %s' "$bin")"
    parts=${KEYWARDEN_PARTS-browser}
    case " $parts " in *" browser "*)
      if "$bin/kw" browser-setup >/dev/null 2>&1; then ok "$(m 'browsers can reach Keywarden')"; else warn "$(m 'browser host not registered, run: %s' 'kw browser-setup')"; fi ;;
    esac
    case " $parts " in *" ssh "*)
      if "$bin/kw" ssh-setup >/dev/null 2>&1; then ok "$(m 'SSH agent for all programs (after the next login; undo: %s)' 'kw ssh-setup --off')"; else warn "$(m 'SSH agent not connected, run: %s' 'kw ssh-setup')"; fi ;;
    esac
    if [ -z "${KEYWARDEN_NO_LAUNCH:-}" ]; then
      (nohup "$bin/keywarden-ui" >/dev/null 2>&1 </dev/null &) && ok "$(m 'opening Keywarden')"
    fi
  fi

  [ -z "$running" ] || warn "$(m 'the Keywarden window that is open is still the old version: close it and open it again')"
  case ":$PATH:" in
    *":$bin:"*)
      # an older copy somewhere else would keep answering to "kw"
      first=$(command -v kw 2>/dev/null || true)
      [ -z "$first" ] || [ "$first" = "$bin/kw" ] || warn "$(m 'another kw comes first in PATH: %s. Remove it or put %s earlier' "$first" "$bin")" ;;
    *)
      case "${SHELL##*/}" in
        fish) hint="fish_add_path $bin" ;;
        zsh) hint="echo 'export PATH=\"$bin:\$PATH\"' >> ~/.zshrc" ;;
        bash) hint="echo 'export PATH=\"$bin:\$PATH\"' >> ~/.bashrc" ;;
        *) hint="echo 'export PATH=\"$bin:\$PATH\"' >> ~/.profile" ;;
      esac
      warn "$(m 'the terminal does not see kw yet. Add %s to PATH and open a new terminal: %s' "$bin" "$hint")" ;;
  esac
  printf '\n  %s%s%s\n' "$G$B" "$(m 'Keywarden %s is installed.' "$tag")" "$N"
  printf '  %s %s\n\n' "$(m 'Browser extension:')" "$(link "$amo" "$(m 'Add to Firefox')")"
}

switch_lang() {
  if [ "$lang" = ru ]; then lang=en; other='Русский'; else lang=ru; other='English'; fi
}

# A message in the chosen language: m 'English text with %s' args...
# The English text is the key; a line missing from ru() is shown in English.
m() {
  f=$1; shift
  [ "$lang" != ru ] || f=$(ru "$f")
  # shellcheck disable=SC2059
  printf "$f" "$@"
}

ru() {
  case "$1" in
    'installer') printf '%s' '· установка' ;;
    'no ready build for %s. Build from source: %s') printf '%s' 'готовой сборки для %s нет. Сборка из исходников: %s' ;;
    'needs %s') printf '%s' 'нужна программа %s' ;;
    'no published release yet: %s') printf '%s' 'релизов пока нет: %s' ;;
    'release %s for %s') printf '%s' 'релиз %s для %s' ;;
    'downloading %s') printf '%s' 'загрузка %s' ;;
    'download failed: %s') printf '%s' 'не удалось скачать: %s' ;;
    'downloaded %s') printf '%s' 'скачано %s' ;;
    '%s is not listed in SHA256SUMS') printf '%s' '%s нет в списке SHA256SUMS' ;;
    'checksum mismatch for %s, nothing installed') printf '%s' 'контрольная сумма %s не совпала, ничего не установлено' ;;
    'checksum matches SHA256SUMS') printf '%s' 'контрольная сумма совпала с SHA256SUMS' ;;
    'ssh-keygen is needed to check the release signature (package: openssh)') printf '%s' 'для проверки подписи релиза нужен ssh-keygen (пакет openssh)' ;;
    'this release has no signature (SHA256SUMS.sig), nothing installed') printf '%s' 'у этого релиза нет подписи (SHA256SUMS.sig), ничего не установлено' ;;
    'release signature does not match, nothing installed') printf '%s' 'подпись релиза не сошлась, ничего не установлено' ;;
    'release signature is valid') printf '%s' 'подпись релиза верна' ;;
    'programs in %s') printf '%s' 'программы в %s' ;;
    'browsers can reach Keywarden') printf '%s' 'браузеры видят Keywarden' ;;
    'browser host not registered, run: %s') printf '%s' 'связь с браузером не настроена, выполните: %s' ;;
    'SSH agent for all programs (after the next login; undo: %s)') printf '%s' 'SSH-агент для всех программ (после следующего входа в систему; отменить: %s)' ;;
    'SSH agent not connected, run: %s') printf '%s' 'SSH-агент не подключён, выполните: %s' ;;
    'opening Keywarden') printf '%s' 'открываю Keywarden' ;;
    'Keywarden %s is installed.') printf '%s' 'Keywarden %s установлен.' ;;
    'Browser extension:') printf '%s' 'Расширение для браузера:' ;;
    'Add to Firefox') printf '%s' 'Добавить в Firefox' ;;
    'Keywarden %s is installed, this is the latest version') printf '%s' 'Keywarden %s установлен, это последняя версия' ;;
    'Keywarden %s is installed, the latest is %s') printf '%s' 'Keywarden %s установлен, последняя версия %s' ;;
    'missing programs:%s') printf '%s' 'не хватает программ:%s' ;;
    'background service is running') printf '%s' 'фоновая служба работает' ;;
    'background service is stopped or does not start with your session') printf '%s' 'фоновая служба остановлена или не запускается вместе с сеансом' ;;
    'browser link: %s') printf '%s' 'связь с браузером: %s' ;;
    'browser link') printf '%s' 'связь с браузером' ;;
    '%s is not in PATH') printf '%s' '%s нет в PATH' ;;
    'background service started') printf '%s' 'фоновая служба запущена' ;;
    'the service did not start, see: %s') printf '%s' 'служба не запустилась, смотрите: %s' ;;
    'browser link registered again') printf '%s' 'связь с браузером настроена заново' ;;
    'browser link still broken, see: %s') printf '%s' 'связь с браузером всё ещё не работает, смотрите: %s' ;;
    'What to do?') printf '%s' 'Что сделать?' ;;
    'put the missing programs back (downloads %s)') printf '%s' 'вернуть пропавшие программы (скачает %s)' ;;
    'start the background service and enable it') printf '%s' 'запустить фоновую службу и включить её автозапуск' ;;
    'register the browser link again') printf '%s' 'настроить связь с браузером заново' ;;
    'fix all of the above') printf '%s' 'исправить всё перечисленное' ;;
    'reinstall %s') printf '%s' 'переустановить %s' ;;
    'update to %s') printf '%s' 'обновить до %s' ;;
    'choose the optional parts (browser link, SSH agent, desktop integration)') printf '%s' 'выбрать дополнительные части (связь с браузером, SSH-агент, интеграция с рабочим столом)' ;;
    'nothing') printf '%s' 'ничего' ;;
    'Browser link, so the extension can reach Keywarden?') printf '%s' 'Связь с браузером, чтобы расширение видело Keywarden?' ;;
    'SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?') printf '%s' 'SSH-агент для всех программ (ssh, git и IDE видят ключи из базы)?' ;;
    'niri: shortcuts for the launcher (your config is backed up first)?') printf '%s' 'niri: клавиши для лаунчера (сначала делается копия конфига)?' ;;
    'Noctalia: follow the shell colors?') printf '%s' 'Noctalia: брать цвета оболочки?' ;;
    '%sEnter%s installs everything, %sc%s lets you choose the parts, %sl%s: %s') printf '%s' '%sEnter%s ставит всё, %sc%s даёт выбрать части, %sl%s: %s' ;;
    'run this as your own user, without sudo: Keywarden installs into your home directory') printf '%s' 'запустите от своего пользователя, без sudo: Keywarden ставится в вашу домашнюю папку' ;;
    'cannot reach github.com to find the latest release. Check the connection or a proxy (https_proxy), or name the version: %s') printf '%s' 'не удаётся связаться с github.com, чтобы узнать последний релиз. Проверьте соединение или прокси (https_proxy) либо укажите версию: %s' ;;
    'cannot write to %s. Pick another folder: %s') printf '%s' 'нет прав на запись в %s. Выберите другую папку: %s' ;;
    'cannot create a temporary folder (is the disk full?)') printf '%s' 'не удаётся создать временную папку (диск заполнен?)' ;;
    'cannot unpack the archive (is the disk full?)') printf '%s' 'не удаётся распаковать архив (диск заполнен?)' ;;
    'the downloaded programs do not start on this system, nothing was changed. The system says: %s. Usually the system is older than this build needs. Build from source: %s') printf '%s' 'скачанные программы не запускаются на этой системе, ничего не изменено. Ответ системы: %s. Обычно система старше, чем нужно этой сборке. Сборка из исходников: %s' ;;
    'the Keywarden window that is open is still the old version: close it and open it again') printf '%s' 'открытое окно Keywarden ещё старой версии: закройте его и откройте заново' ;;
    'another kw comes first in PATH: %s. Remove it or put %s earlier') printf '%s' 'в PATH раньше стоит другой kw: %s. Удалите его или поставьте %s раньше' ;;
    'the terminal does not see kw yet. Add %s to PATH and open a new terminal: %s') printf '%s' 'терминал пока не видит kw. Добавьте %s в PATH и откройте новый терминал: %s' ;;
    'the installer stopped on an unexpected error. Please report it with the lines above: %s') printf '%s' 'установщик остановился на неожиданной ошибке. Сообщите о ней, приложив строки выше: %s' ;;
    *) printf '%s' "$1" ;;
  esac
}

# What is wrong with the installation in $bin; fills $problems with: files service browser
diagnose() {
  problems=
  if [ "v$have" = "$tag" ]; then ok "$(m 'Keywarden %s is installed, this is the latest version' "$B$have$N")"
  else warn "$(m 'Keywarden %s is installed, the latest is %s' "$B$have$N" "$B$tag$N")"; fi
  miss=
  for b in keywardend kw keywarden-ui keywarden-host; do [ -x "$bin/$b" ] || miss="$miss $b"; done
  if [ -n "$miss" ]; then problems="$problems files"; bad "$(m 'missing programs:%s' "$miss")"; else ok "$(m 'programs in %s' "$bin")"; fi
  if [ "$target" = linux-x86_64 ] && command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    if systemctl --user is-active --quiet keywardend.service 2>/dev/null \
      && systemctl --user is-enabled --quiet keywardend.service 2>/dev/null; then
      ok "$(m 'background service is running')"
    else
      problems="$problems service"; bad "$(m 'background service is stopped or does not start with your session')"
    fi
  fi
  # the daemon line is left out: it is covered by the service check above
  fails=$(KEYWARDEN_LANG=$lang "$bin/kw" browser-setup --check 2>/dev/null | grep '^FAIL' | grep -v keywardend || true)
  if [ -n "$fails" ]; then
    problems="$problems browser"
    printf '%s\n' "$fails" | while read -r _ what; do bad "$(m 'browser link: %s' "$what")"; done
  else
    ok "$(m 'browser link')"
  fi
  case ":$PATH:" in *":$bin:"*) ;; *) warn "$(m '%s is not in PATH' "$bin")" ;; esac
}

# Leaves no temporary files; a stop nobody explained gets one plain line instead of silence.
on_exit() {
  [ -z "$tmp" ] || rm -rf "$tmp"
  [ "$1" = 0 ] || [ -n "$said" ] || printf '  %s%s %s%s\n' "$Y" "$BADM" "$(m 'the installer stopped on an unexpected error. Please report it with the lines above: %s' "https://github.com/$repo/issues")" "$N" >&2
}

fix() {
  case "$1" in
    service)
      systemctl --user daemon-reload
      if systemctl --user --quiet enable keywardend.service && systemctl --user restart keywardend.service; then
        ok "$(m 'background service started')"
      else warn "$(m 'the service did not start, see: %s' 'journalctl --user -u keywardend -e')"; fi ;;
    browser)
      if "$bin/kw" browser-setup >/dev/null 2>&1; then ok "$(m 'browser link registered again')"; else warn "$(m 'browser link still broken, see: %s' 'kw browser-setup --check')"; fi ;;
  esac
}

# Returns to install or update; exits when the choice needs no download.
menu() {
  printf '\n  %s\n' "$(m 'What to do?')"
  n=0
  for p in $problems; do
    n=$((n + 1))
    eval "opt_$n=\$p"
    case "$p" in
      files) t=$(m 'put the missing programs back (downloads %s)' "$tag") ;;
      service) t=$(m 'start the background service and enable it') ;;
      browser) t=$(m 'register the browser link again') ;;
    esac
    printf '    %s%s)%s %s\n' "$B" "$n" "$N" "$t"
  done
  [ "$n" -lt 2 ] || printf '    %sa)%s %s\n' "$B" "$N" "$(m 'fix all of the above')"
  if [ "v$have" = "$tag" ]; then printf '    %sr)%s %s\n' "$B" "$N" "$(m 'reinstall %s' "$tag")"
  else printf '    %su)%s %s\n' "$B" "$N" "$(m 'update to %s' "$tag")"; fi
  printf '    %sc)%s %s\n' "$B" "$N" "$(m 'choose the optional parts (browser link, SSH agent, desktop integration)')"
  printf '    %sl)%s %s\n' "$B" "$N" "$other"
  printf '    %sq)%s %s\n  > ' "$B" "$N" "$(m 'nothing')"
  read -r a < /dev/tty || a=q
  echo
  case "$a" in
    l|L) switch_lang; echo; diagnose; menu; return 0 ;;
    u|U|r|R) return 0 ;;
    c|C) choose_parts; return 0 ;;
    a|A) todo=$problems ;;
    [1-9]) eval "todo=\${opt_$a:-}"; [ -n "$todo" ] || exit 0 ;;
    *) exit 0 ;;
  esac
  # missing programs come back only with a full install, which redoes the rest as well
  case " $todo " in *" files "*) return 0 ;; esac
  for p in $todo; do fix "$p"; done
  echo
  exit 0
}

agree() {
  printf '  %s [%s] ' "$1" "$2"
  read -r a < /dev/tty || a=
  case "${a:-$2}" in y*|Y*) return 0 ;; esac
  return 1
}

choose_parts() {
  KEYWARDEN_PARTS=
  ! agree "$(m 'Browser link, so the extension can reach Keywarden?')" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS browser"
  ! agree "$(m 'SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?')" "y/N" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS ssh"
  if [ "$target" = linux-x86_64 ]; then
    if command -v niri >/dev/null 2>&1; then
      ! agree "$(m 'niri: shortcuts for the launcher (your config is backed up first)?')" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS niri"
    fi
    if [ -f "${XDG_CONFIG_HOME:-$HOME/.config}/noctalia/config.toml" ]; then
      ! agree "$(m 'Noctalia: follow the shell colors?')" "Y/n" || KEYWARDEN_PARTS="$KEYWARDEN_PARTS noctalia"
    fi
  fi
  echo
}

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  E=$(printf '\033')
  G="${E}[32m" Y="${E}[33m" V="${E}[38;5;141m" D="${E}[2m" B="${E}[1m" N="${E}[0m"
else
  E="" G="" Y="" V="" D="" B="" N=""
fi
OKM='✓' BADM='✗' DIA='◆' SPIN=1
ok() { printf '  %s%s%s %s\n' "$G" "$OKM" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
bad() { printf '  %s%s%s %s\n' "$Y" "$BADM" "$N" "$*"; }
die() { said=1; printf '  %s%s %s%s\n' "$Y" "$BADM" "$*" "$N" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$(m 'needs %s' "$1")"; }
# clickable in terminals that support OSC 8, plain text with the address otherwise
link() { if [ -n "$E" ]; then printf '%s]8;;%s%s\\%s%s%s%s]8;;%s\\ %s%s%s' "$E" "$1" "$E" "$V" "$2" "$N" "$E" "$E" "$D" "$1" "$N"; else printf '%s %s' "$2" "$1"; fi; }
# a spinner next to the message while process $1 runs; returns its exit status
spin() {
  if [ -z "$E" ] || [ -z "$SPIN" ]; then wait "$1"; return; fi
  i=0
  while kill -0 "$1" 2>/dev/null; do
    case $((i % 10)) in 0) f=⠋;; 1) f=⠙;; 2) f=⠹;; 3) f=⠸;; 4) f=⠼;; 5) f=⠴;; 6) f=⠦;; 7) f=⠧;; 8) f=⠇;; *) f=⠏;; esac
    printf '\r  %s%s%s %s' "$V" "$f" "$N" "$2"
    i=$((i + 1))
    sleep 0.08
  done
  printf '\r%s\r' "${E}[2K"
  wait "$1"
}
# only https from GitHub; a mirror set by hand may be anything curl can read
fetch() {
  proto='=https'
  [ -z "${KEYWARDEN_MIRROR:-}" ] || proto=all
  curl -fL --proto "$proto" --retry 2 -sS -o "$2" "$1"
}

main "$@"
