#!/bin/sh
# Битые относительные ссылки в site/ (href и src). Внешние адреса и якоря не проверяются.
set -eu
cd "${1:-site}"
bad=$(find . -name '*.html' | while read -r f; do
  d=$(dirname "$f")
  grep -oE '(href|src)="[^"]+"' "$f" | sed -E 's/^(href|src)="//; s/"$//; s/[#?].*//' | sort -u |
    while read -r l; do
      case "$l" in ''|*:*) continue ;; esac
      t="$d/$l"; [ -d "$t" ] && t="$t/index.html"
      [ -e "$t" ] || echo "$f: нет $l"
    done
done)
[ -z "$bad" ] || { echo "$bad"; exit 1; }
