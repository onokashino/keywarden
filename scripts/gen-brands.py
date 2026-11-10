#!/usr/bin/env python3
"""Сборка crates/keywarden-ui/assets/brands.tsv.gz из пакета simple-icons (npm, CC0).

Использование: python3 -I scripts/gen-brands.py <распакованный package/> <выходной .tsv.gz>
Строка: slug, цвет, название, псевдонимы через запятую, d пути (иконки 24x24, один путь).
"""
import gzip
import json
import re
import sys

pkg, out = sys.argv[1], sys.argv[2]
data = json.load(open(f"{pkg}/data/simple-icons.json", encoding="utf-8"))
rows = []
for icon in data:
    svg = open(f"{pkg}/icons/{icon['slug']}.svg", encoding="utf-8").read()
    m = re.search(r'<path d="([^"]+)"', svg)
    if not m:
        continue
    aliases = icon.get("aliases", {})
    names = list(aliases.get("aka", [])) + [d.get("title", "") for d in aliases.get("dup", [])]
    names += list(aliases.get("loc", {}).values())
    clean = lambda s: s.replace("\t", " ").replace("\n", " ").replace(",", " ")
    rows.append("\t".join([icon["slug"], icon["hex"], clean(icon["title"]), ",".join(clean(n) for n in names if n), m.group(1)]))
with gzip.open(out, "wt", encoding="utf-8", compresslevel=9) as f:
    f.write("\n".join(rows) + "\n")
print(f"{len(rows)} иконок -> {out}")
