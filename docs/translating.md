# Translating Keywarden

Keywarden is translated by its users. Any language is welcome, and a partial translation is
useful too: whatever is not translated yet is shown in English.

There are two parts to translate:

| Part | Files | Source to translate from |
| --- | --- | --- |
| App (window, launcher, `kw`, daemon messages) | `locales/<code>/*.json` | `locales/en/*.json` |
| Browser extension | `extension/public/_locales/<code>/messages.json` | `extension/public/_locales/en/messages.json` |

## The easy way: in the browser

If the project has a Weblate page (see the README), pick your language there and translate
string by string. Weblate shows the English text, checks placeholders and sends the result to
the repository. Nothing to install.

## The direct way: a pull request

1. Create the files for your language (code like `de`, `pt-BR`, `zh-Hans`):
   ```sh
   make i18n-new CODE=de NAME=Deutsch
   ```
   Without Docker: copy the structure by hand: `locales/de/_meta.json` with
   `{"name": "Deutsch"}` (the language name in the language itself), empty `{}` files named like
   the ones in `locales/en/`, and `extension/public/_locales/de/messages.json` (note the
   underscore in folder names there: `pt_BR`).
2. Translate. Open `locales/en/ui.json` next to `locales/de/ui.json` and copy the entries you
   translate:
   ```json
   {
     "Новая запись": "Neuer Eintrag",
     "Удалено {n} из {all}": "{n} von {all} gelöscht"
   }
   ```
   The **key** (left) is the original string from the code, which happens to be Russian. Copy it
   exactly as it is in the English file; translate only the **value** (right), using the English
   value as your source.
3. Check: `make test` (or `cargo test -p keywarden-core --lib i18n`). The tests fail if a
   placeholder like `{n}` got lost or renamed, or if a key no longer exists.
4. See how far you are: `make i18n-status`. Then open a pull request.

## Rules

- **Placeholders** in braces (`{n}`, `{title}`) stay exactly as they are; move them where your
  grammar needs them.
- **Keys with `§`** (`поле§Логин`) carry a context before the `§`: the same Russian word means
  different things in different places. Look at the English value to see which meaning it is.
- **Plurals.** A counted noun has three Russian keys, for example `запись` (1), `записи` (2-4),
  `записей` (5+). Languages with one/other forms (English, German, French, Spanish...) translate
  the first as singular and the third as plural; the second can be the same as the third.
  Ukrainian, Belarusian, Polish, Czech, Slovak, Serbian and Croatian use all three.
- **Keyboard keys** (`Ctrl+U`, `Enter`) and product names (KeePassXC, Syncthing, GitHub) are not
  translated.
- Keep it short: most strings are buttons, labels and hints.
- The language is picked from the system, or in Settings, General, Interface language. To try a
  translation without changing the system: `KEYWARDEN_LANG=de keywarden-ui`.

## Extension

The extension uses the standard WebExtension format: each message has a `message` and, for
variables, `placeholders`:

```json
{
  "fill_login": { "message": "Anmeldedaten ausfüllen" },
  "copied_field": {
    "message": "$FIELD$ kopiert",
    "placeholders": { "field": { "content": "$1" } }
  }
}
```

Copy the structure from `extension/public/_locales/en/messages.json`; translate only `message`.
The browser picks the language of its own interface.
