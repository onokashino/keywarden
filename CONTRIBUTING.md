# Contributing

Code comments and the interface are in Russian for now; issues and pull requests in English
or Russian are both welcome.

## Checks

Every check runs in Docker with a memory limit (`docker/Dockerfile.dev`, Arch Linux):

```sh
make image        # once: build the keywarden-dev image
make test         # unit and integration tests, including keepassxc-cli compatibility
make clippy
make e2e          # daemon + kw on a KeePassXC database: sync, import
make e2e-crash    # kill -9 during writes, clipboard (headless sway), local API, core dumps
make e2e-ssh      # SSH agent
make e2e-ext      # browser extension in headless Chromium, including passkeys
make e2e-secrets  # Secret Service against secret-tool
make ui-shots     # launcher and main window in headless sway, screenshots in target/shots
make ui-ssh       # SSH in the window: unlock on demand, connect from the launcher, settings
make check-cross  # clippy for Windows and macOS from Linux
make e2e-wine     # Windows daemon and kw under Wine
make ext ext-firefox   # extension builds in extension/.output
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests and a release build on Linux,
Windows and macOS, plus the extension type check.

## Translations

Anyone can add a language: see [docs/translating.md](docs/translating.md).
`make i18n-new CODE=de NAME=Deutsch` creates the files, `make i18n-status` shows progress.

## Releases

Bump the version in `Cargo.toml` (`[workspace.package]`) and `extension/package.json`,
then push a tag:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` builds archives for the three systems and the extension,
and publishes the release with `SHA256SUMS` and the notes from `.github/release-notes.md`.
Then it starts `packages.yml` and `extension-stores.yml`, which update the package managers and
submit the extension to the browser stores. Step by step:
[docs/publishing.md](docs/publishing.md).

## Website

The site lives in `site/` (plain HTML, English at the root, Russian in `site/ru/`) and is
deployed to GitHub Pages by `.github/workflows/pages.yml` on every push to `main` that
touches it. Preview locally: `python3 -m http.server -d site 8000`. Screenshots come from a
showcase vault in both languages: `make site-shots` (scenario `scripts/ui-showcase.scenario`).
