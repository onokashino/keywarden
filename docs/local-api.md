# Keywarden local API (assistants and scripts)

Socket: `$XDG_RUNTIME_DIR/keywarden/api.sock` (mode 0600, only processes of the same user are
accepted). One line of JSON per request, one line of JSON per response; the connection can be
reused.

**The API never returns secret values**: not in responses, not in errors. A secret can only be
put into the clipboard (it clears itself after 30 s and is marked as a secret for clipboard
history managers) or taken from the clipboard when creating an entry.

## list

```json
{"method": "list", "query": "mail"}
```
```json
{"ok": true, "items": [{"id": "6f2a…", "title": "Mail", "type": "login"}]}
```
Fuzzy search by title, username, address. An empty `query` returns recently used entries.
Types: `login`, `card`, `identity`, `note`, `ssh_key`, `passkey`.

## secret_copy

```json
{"method": "secret_copy", "id": "6f2a…"}
```
```json
{"ok": true}
```
Copies the main secret of the entry: password (`login`, `ssh_key`), card number (`card`),
note text (`note`), passport number (`identity`). A `passkey` has no secret to copy.

## save_from_clipboard

```json
{"method": "save_from_clipboard", "title": "Home Wi-Fi", "type": "login"}
```
```json
{"ok": true, "id": "9c01…"}
```
Creates an entry whose main secret is taken from the clipboard (the password for `login`, the
text for `note` and so on, see above). The value is not returned.

## Errors

```json
{"ok": false, "error": "vault is locked"}
```
The error text follows the app language.

## Example (shell)

```sh
printf '%s\n' '{"method":"list","query":"git"}' | socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/keywarden/api.sock
```
