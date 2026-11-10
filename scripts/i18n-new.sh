#!/bin/sh
# Заготовка нового языка: make i18n-new CODE=de NAME=Deutsch
# Приложение: locales/<код>/ (пустые каталоги по компонентам + _meta.json с названием).
# Расширение: extension/public/_locales/<код>/messages.json (код через «_»: pt_BR).
set -eu
code=${1:?код языка, например de или pt-BR}
name=${2:-$code}
case "$code" in *[!A-Za-z-]*) echo "код языка: буквы и дефис (de, pt-BR)"; exit 1;; esac
dir=locales/$code
[ -e "$dir" ] && { echo "$dir уже есть"; exit 1; }
mkdir -p "$dir"
printf '{\n  "name": "%s"\n}\n' "$name" > "$dir/_meta.json"
for f in locales/en/*.json; do
  b=$(basename "$f")
  [ "$b" = _meta.json ] || printf '{}\n' > "$dir/$b"
done
ext=extension/public/_locales/$(echo "$code" | tr - _)
mkdir -p "$ext"
[ -e "$ext/messages.json" ] || printf '{}\n' > "$ext/messages.json"
echo "Готово: $dir и $ext. Переводите с английского образца (locales/en, _locales/en), см. docs/translating.md"
