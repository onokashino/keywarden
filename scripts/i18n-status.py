"""Сколько переведено в каждом языке: make i18n-status (образец: английский)."""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent


def load(d: pathlib.Path) -> dict:
    out = {}
    for f in sorted(d.glob("*.json")):
        if f.name != "_meta.json":
            out.update({k: v for k, v in json.loads(f.read_text()).items() if v})
    return out


en = load(root / "locales/en")
ext_en = json.loads((root / "extension/public/_locales/en/messages.json").read_text())
print(f"{'язык':10} {'приложение':>12} {'расширение':>12}")
for d in sorted(p for p in (root / "locales").iterdir() if p.is_dir()):
    cat = load(d)
    done = sum(1 for k in en if k in cat)
    ext = root / "extension/public/_locales" / d.name.replace("-", "_") / "messages.json"
    ext_done = len(json.loads(ext.read_text())) if ext.exists() else 0
    print(f"{d.name:10} {done * 100 // max(len(en), 1):>11}% {ext_done * 100 // max(len(ext_en), 1):>11}%")
print("ru        исходный язык строк в коде")
