# Building the Keywarden browser extension from source

For Firefox Add-ons and Chrome Web Store reviewers. The extension is TypeScript and Svelte
(`extension/`) plus a WebAssembly module compiled from Rust (`crates/keywarden-ext`). Nothing
in the package is minified third-party code without a source here.

## Option A: Docker (exact toolchain)

```sh
make image          # builds docker/Dockerfile.dev (Arch Linux, rustup stable, wasm-bindgen-cli 0.2.130, Node)
make ext-firefox    # Rust -> WASM, then npm install && wxt build -b firefox
make ext            # the same for Chromium
```

## Option B: by hand

Requirements: Rust (stable, `rustup target add wasm32-unknown-unknown`),
`cargo install wasm-bindgen-cli --version 0.2.130 --locked`, Node.js 22 or newer.

```sh
sh scripts/build-wasm.sh          # crates/keywarden-ext -> extension/wasm and extension/public
cd extension
npm ci
npm run build:firefox             # or: npm run build
```

The result is in `extension/.output/firefox-mv3` (or `chrome-mv3`).

## What the WASM module does

URL matching by registrable domain (Public Suffix List), login form classification, the
encrypted message protocol with the desktop app (crypto_box, as in KeePassXC-Browser) and
ES256 key generation for passkeys. Source: `crates/keywarden-ext/src`.
