Keywarden is a local password manager for KeePass (KDBX 4) databases with a desktop app, a CLI, a browser extension, an SSH agent and TOTP codes. Nothing leaves your computer.

## Install

**Linux (x86_64) and macOS (Apple Silicon)**

```sh
curl -fsSL https://onokashino.github.io/keywarden/install.sh | sh
```

The script downloads the archive for your system, checks it against `SHA256SUMS` and installs into `~/.local/bin` without root. On Linux it also adds a systemd user service and a menu entry. Read the script first if you like: https://onokashino.github.io/keywarden/install.sh

**Windows (x86_64)**

```powershell
irm https://onokashino.github.io/keywarden/install.ps1 | iex
```

Installs into `%LOCALAPPDATA%\Programs\Keywarden` without administrator rights, adds `kw` to PATH, a Start menu shortcut and the browser link.

**Later, on any system**

Run the same command again. It checks the installation, offers to fix what is broken, updates to the latest release, and lets you choose the optional parts (browser link, SSH agent for all programs). The installer speaks English and Russian.

**Browser extension**

Firefox: https://addons.mozilla.org/firefox/addon/keywarden/. The extension talks only to the Keywarden app on the same computer.

## Upgrading to 0.2.10

- Autotype types straight away only into a window listed in the entry. When the entry is found by a word in the window title, it asks you to confirm first.
- Extra sign-in fields (a last name, a client number) are filled only from entry fields named with the `KPH:` prefix, for example `KPH: Last Name`.
- A site on a non-default port asks for your permission once more: the permission is now remembered per host and port.
- The AUR, Homebrew and winget packages were never published and are no longer planned: the install command above is the single source.

## Verify

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

The macOS build is not notarized yet. If you download the archive with a browser instead of the script, run `xattr -dr com.apple.quarantine keywarden-*` before starting it.

Docs: https://onokashino.github.io/keywarden/docs/ · Privacy: https://onokashino.github.io/keywarden/privacy/
