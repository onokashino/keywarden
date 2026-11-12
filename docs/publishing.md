# Publishing: GitHub, site, releases, extension stores

## 1. Once: the repository

1. Create an empty repository `onokashino/keywarden` (no README or license, they already exist).
2. `git remote add origin git@github.com:onokashino/keywarden.git && git push -u origin main`.
3. Settings, Pages, Source: **GitHub Actions**. After the first push to `site/` the site appears at
   https://onokashino.github.io/keywarden/.
4. Settings, Code security: turn on **Private vulnerability reporting** (SECURITY.md links to it)
   and Dependabot alerts.
5. Settings, Environments: create the **stores** environment and put the store secrets there
   (section 4). You can turn on "Required reviewers": store submission then waits for approval.

## 2. Releasing a version

1. Bump the version in `Cargo.toml` (`[workspace.package] version`) and `extension/package.json`.
   They must match, otherwise the release stops at the first step.
2. Commit, tag, push:
   ```sh
   git tag v0.2.0 && git push origin main v0.2.0
   ```
3. `release.yml` builds archives for Linux, Windows and macOS, extension zips for Chrome and Firefox,
   the source archive for AMO and `SHA256SUMS`, and publishes the release at once. The release text
   comes from `.github/release-notes.md` (`{TAG}` is replaced with the tag); GitHub appends the
   list of changes below it.
4. After publishing, `release.yml` starts `packages.yml` (AUR, Homebrew, winget) and
   `extension-stores.yml`: the extension goes to review in every store that has its secrets set.
   The others are skipped with a warning.

Test a build before releasing it: tag with a hyphen, for example `v0.2.0-rc.1`, while `Cargo.toml`
says `0.2.0`. The release comes out marked Pre-release: `/releases/latest`, the installer and the
update check do not see it, packages and stores are not started. Install and test it:
`curl -fsSL https://onokashino.github.io/keywarden/install.sh | KEYWARDEN_VERSION=v0.2.0-rc.1 sh`.
If everything works, put `v0.2.0` on the same commit.

Check the secrets without submitting: Actions, extension-stores, Run workflow, enter the tag,
keep "Only check the secrets" ticked (the default).

## 3. Once: first submission to the stores (by hand)

The automation can only update an existing listing. The first upload is manual.
Take the zips from the first release.

### Firefox (addons.mozilla.org)

1. Sign in at https://addons.mozilla.org/developers/ and press "Submit a New Add-on".
2. Choose "On this site" (listed in the catalog).
3. Upload `keywarden-extension-X.Y.Z-firefox.zip`.
4. When asked about source code, answer "Yes" and upload `keywarden-vX.Y.Z-sources.zip`.
   The extension contains WASM built from Rust, so the whole repository is needed; instructions
   for reviewers are in `SOURCE_CODE_REVIEW.md`.
5. Fill in the listing: description, category "Privacy & Security", screenshots, website link,
   privacy policy ("collects nothing", the manifest says the same).
6. The extension id is set in the manifest: `keywarden@onokashino.github.io`. That is the
   `FIREFOX_EXTENSION_ID` secret.
7. API keys: https://addons.mozilla.org/developers/addon/api/key/. The JWT issuer goes to
   `FIREFOX_JWT_ISSUER`, the JWT secret to `FIREFOX_JWT_SECRET`.

### Chrome Web Store

1. Developer registration: https://chrome.google.com/webstore/devconsole, one-time $5 fee.
2. "New item", upload `keywarden-extension-X.Y.Z-chrome.zip`.
3. Fill in the listing and the Privacy tab. Every permission (`nativeMessaging`, `tabs`,
   `scripting`, `favicon`, `storage`, `activeTab`) needs a justification. The main one: "talks to
   the local Keywarden app to fill passwords". Data usage: nothing is collected.
4. After review the extension id appears (32 letters). That is `CHROME_EXTENSION_ID`. Also set it
   as the default in `crates/keywarden-cli/src/browser.rs` and
   `dist/native-messaging/chromium.json`, so `kw browser-setup` works without `--chrome-id`.
5. CI access (API v2, service account):
   - in Google Cloud create a project, enable "Chrome Web Store API", create a service account
     and a JSON key;
   - in the Developer Dashboard, Account, add the service account email;
   - secrets: `CHROME_PUBLISHER_ID` (publisher id from the Dashboard),
     `CHROME_SERVICE_ACCOUNT_CLIENT_EMAIL`, `CHROME_SERVICE_ACCOUNT_PRIVATE_KEY` (the whole
     `private_key` field from the JSON, including `-----BEGIN PRIVATE KEY-----`).

### Microsoft Edge Add-ons

1. Partner Center: https://partner.microsoft.com/dashboard/microsoftedge (free).
2. Create an extension and upload the same Chrome zip.
3. After publishing: Publish API, "Create API credentials". Secrets: `EDGE_PRODUCT_ID`,
   `EDGE_CLIENT_ID`, `EDGE_API_KEY`.

## 4. Secrets, summary

| Secret | Where from |
| --- | --- |
| `FIREFOX_EXTENSION_ID` | `keywarden@onokashino.github.io` |
| `FIREFOX_JWT_ISSUER`, `FIREFOX_JWT_SECRET` | AMO, Manage API Keys |
| `CHROME_EXTENSION_ID` | Chrome Web Store, after the first publication |
| `CHROME_PUBLISHER_ID` | Chrome Developer Dashboard, Account |
| `CHROME_SERVICE_ACCOUNT_CLIENT_EMAIL`, `CHROME_SERVICE_ACCOUNT_PRIVATE_KEY` | Google Cloud, service account |
| `EDGE_PRODUCT_ID`, `EDGE_CLIENT_ID`, `EDGE_API_KEY` | Partner Center, Publish API |

Secrets go into the `stores` environment (Settings, Environments, stores, Add secret).

## 5. What users get

- An extension from a store is updated by the browser.
- AMO also lists it for Firefox for Android, but without the app on the phone the extension has
  nothing to talk to: on the AMO listing tick desktop Firefox only.

## 6. App updates: AUR, Homebrew, winget

When a release is published, `packages.yml` updates the packages in three channels. A channel
without its secret is skipped. Secrets go into the `packages` environment (Settings, Environments).
Prereleases (a tag with a hyphen, for example `v0.2.0-rc.1`) never reach the packages.

### AUR (`keywarden-bin`)

1. An account on https://aur.archlinux.org with a public SSH key in the profile
   (a separate one, for AUR only: `ssh-keygen -t ed25519 -f aur -C aur`).
2. The package is created by the first push, nothing to register in advance.
3. Secret `AUR_SSH_PRIVATE_KEY`: the contents of the `aur` file (the private key).
4. Template: `packaging/aur/PKGBUILD`. CI fills in the version and the archive sha256.

Install: `paru -S keywarden-bin`, updates come with the system.

### Homebrew (macOS)

1. Create a public repository `onokashino/homebrew-tap` (empty).
2. A fine-grained token with Contents: Read and write on `homebrew-tap` only,
   secret `HOMEBREW_TAP_TOKEN`.
3. Template: `packaging/homebrew/keywarden.rb`.

Install: `brew install onokashino/tap/keywarden`, update: `brew upgrade`. Homebrew downloads the
archive itself, so macOS sets no quarantine and `xattr` is not needed.

### winget (Windows)

1. Submit the first version by hand:
   `wingetcreate new https://github.com/onokashino/keywarden/releases/download/v0.1.0/keywarden-v0.1.0-windows-x86_64.zip`
   (installer type zip, nested portable, identifier `onokashino.Keywarden`), then wait for the PR
   to microsoft/winget-pkgs to be merged.
2. Fork `microsoft/winget-pkgs` into your account.
3. A classic token with the `public_repo` scope, secret `WINGET_TOKEN`.

From then on every version reaches winget by itself: `winget install onokashino.Keywarden`,
update `winget upgrade`.

## 7. Community translations: Weblate

Translations can come as pull requests (guide for translators: `docs/translating.md`), but Weblate
is the easiest: translators work in the browser, Weblate checks placeholders and sends the changes
to the repository.

1. https://hosted.weblate.org, "Add new translation project" (free for open projects; needs a
   public repository and a license, GPL is fine).
2. An "App" component per catalog file (`core`, `daemon`, `cli`, `ui`, `ui_settings`):
   - format: **JSON file**, monolingual;
   - file mask: `locales/*/ui.json` (and so on for each file);
   - monolingual base: `locales/en/ui.json`;
   - project source language: **English** (translators see the English text, the Russian key
     stays a key);
   - template for a new language: empty, `{}`.
3. An "Extension" component:
   - format: **WebExtension JSON**;
   - mask: `extension/public/_locales/*/messages.json`, base `extension/public/_locales/en/messages.json`.
4. In the project settings: "Push on commit", pull requests to `main`; add the GitHub webhook from
   the Weblate instructions so new strings show up there at once.
5. A Weblate translation status badge can go into the README.

A new language created in Weblate shows up in the app right away: catalogs are found at build time
(`crates/keywarden-core/build.rs`), no code changes. Tests (`cargo test`) reject a translation
with a lost placeholder or stale strings.
