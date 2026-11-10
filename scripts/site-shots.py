"""Кадры витрины (make site-shots) -> site/assets/shots/*.webp для сайта.
Окна sway: срезаем заголовок и рамку; оверлеи (лаунчер, подтверждение): по содержимому."""
import os
import sys
from PIL import Image

# снимает make site-shots: scripts/ui-showcase.scenario на двух языках
SETS = [("target/showcase-en", "site/assets/shots"), ("target/showcase-ru", "site/assets/shots/ru")]
WINDOW = {  # имя на сайте: снимок стенда
    "main": "sc-main", "otp": "sc-otp", "health": "sc-health", "wallet": "sc-wallet",
    "sync": "sc-sync", "edit": "sc-edit", "generator": "sc-generator",
    "system": "sc-system", "locked": "sc-locked", "security": "sc-security", "ssh": "sc-ssh",
}
OVERLAY = {"launcher": "sc-launcher-all", "confirm": "sc-confirm"}

for SRC, DST in SETS:
    os.makedirs(DST, exist_ok=True)
    for name, shot in WINDOW.items():
        im = Image.open(f"{SRC}/{shot}.png").convert("RGB").crop((2, 27, 1278, 798))
        im.save(f"{DST}/{name}.webp", quality=88, method=6)
        if name == "locked":
            # для документации: только карточка разблокировки, без пустого окна вокруг
            bg = im.getpixel((8, 8))
            diff = Image.new("L", im.size)
            px, dp = im.load(), diff.load()
            for y in range(im.height):
                for x in range(im.width):
                    if sum(abs(a - b) for a, b in zip(px[x, y], bg)) > 24:
                        dp[x, y] = 255
            l, t, r, b = diff.getbbox()
            card = im.crop((max(l - 48, 0), max(t - 40, 0), min(r + 48, im.width), min(b + 40, im.height)))
            card.save(f"{DST}/unlock-card.webp", quality=90, method=6)
    for name, shot in OVERLAY.items():
        im = Image.open(f"{SRC}/{shot}.png").convert("RGB")
        box = Image.eval(im, lambda v: 255 if v > 3 else 0).getbbox()
        im.crop(box).save(f"{DST}/{name}.webp", quality=90, method=6)
print("ok", file=sys.stderr)
