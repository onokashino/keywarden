Keywarden is a local password manager for KeePass (KDBX 4) databases with a desktop app, a CLI, a browser extension, an SSH agent and TOTP codes. Nothing leaves your computer.

## Install

**Linux (x86_64) and macOS (Apple Silicon)**

```sh
curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
```

The script downloads the archive for your system, checks it against `SHA256SUMS` and installs into `~/.local/bin` without root. On Linux it also adds a systemd user service and a menu entry. Read the script first if you like: https://onokashino.github.io/keywarden/install.sh

**Windows (x86_64)**

Unpack `keywarden-{TAG}-windows-x86_64.zip` to a folder you keep, for example `%LOCALAPPDATA%\Programs\Keywarden`, run `keywarden-ui.exe`, then register the browser host:

```powershell
.\kw.exe browser-setup
```

**Browser extension**

Firefox: https://addons.mozilla.org/firefox/addon/keywarden/. The extension talks only to the Keywarden app on the same computer.

## Verify

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

The macOS build is not notarized yet. If you download the archive with a browser instead of the script, run `xattr -dr com.apple.quarantine keywarden-*` before starting it.

Docs: https://onokashino.github.io/keywarden/docs/ · Privacy: https://onokashino.github.io/keywarden/privacy/
