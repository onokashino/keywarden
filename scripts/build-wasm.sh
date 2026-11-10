#!/bin/sh
# Rust -> WASM -> extension/wasm (импортируется из background.ts). Общий для Makefile и CI.
set -eu
cargo build -p keywarden-ext --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir extension/wasm \
  "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/keywarden_ext.wasm"
mkdir -p extension/public && cp extension/wasm/keywarden_ext_bg.wasm extension/public/
# путь к .wasm передаём явно; запасной import.meta.url заставил бы Vite встроить 1,6 МБ в background.js
sed -i.bak "s|new URL('keywarden_ext_bg.wasm', import.meta.url)|undefined|" extension/wasm/keywarden_ext.js
rm -f extension/wasm/keywarden_ext.js.bak
