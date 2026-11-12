# Keywarden

[English](README.md) · **Русский** · [Сайт и документация](https://onokashino.github.io/keywarden/ru/)

Менеджер паролей поверх KeePass (KDBX 4) для Linux, Windows и macOS. Та же база без
конвертации открывается в KeePassXC, KeePassDX и KeePassium; синхронизация файлом через
Syncthing, Nextcloud, Dropbox или любую другую папку.

## Что умеет

| Возможность | Что сделано | Как проверено |
| --- | --- | --- |
| Совместимость с KeePassXC | запись через keepass-rs с проверкой «записал → расшифровал → сравнил» перед каждым сохранением | `make test`: база из KeePassXC → Keywarden → полный XML-экспорт `keepassxc-cli` совпадает; правки Keywarden видны в KeePassXC |
| Сохранность | бэкап перед каждой записью (последние N), атомарная запись (tmp → fsync → rename → fsync каталога), отказ затирать файл, изменённый снаружи | `make e2e-crash`: 10 раз `kill -9` во время записи, база и бэкапы открываются |
| Типы записей | логин, карта, личная информация, заметка, ключ SSH, ключ доступа; тип в custom data `keywarden.type`, поля шаблонов как обычные поля KDBX | unit-тесты `model` |
| TOTP | `otp` (otpauth://, KeeOtp), старые `TOTP Seed`/`TOTP Settings`, Steam | векторы RFC 6238 |
| Разблокировка | пароль, файл-ключ, YubiKey challenge-response (как KeePassXC), в сочетаниях | тесты `vault` (YubiKey через эмуляцию HMAC-секретом) |
| Автоблокировка | простой, блокировка экрана и сон (logind, delay-inhibitor), `kw lock` | таймер в тестах; logind на живой системе |
| Память и утечки | `zeroize`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall` при достаточном `RLIMIT_MEMLOCK`, `MemorySwapMax=0` в unit, секреты не печатаются в Debug/логах | e2e: в логах демона нет секретов, `/proc/PID/environ` закрыт |
| Буфер обмена | Wayland data-control, `x-kde-passwordManagerHint: secret`, очистка через 30 с только если там всё ещё наше | `make e2e-crash` в headless sway |
| Лаунчер | layer-shell поверх всего, нечёткий поиск, живые коды 2FA, Enter/Ctrl+U/Ctrl+T, сначала пароль, если заблокировано | `make ui-shots`; 230-400 мс от запуска до пароля в буфере даже на программном рендере |
| Главное окно | папки, типы, список, карточка, правка по шаблонам, свои поля, вложения, история с восстановлением, генератор, корзина; всё с клавиатуры | `make ui-shots` |
| Тема | цвета Noctalia через её шаблоны, перекраска на лету | скриншоты с палитрой из шаблона |
| Расширение | Firefox и Chromium (MV3, WXT), логика на Rust → WASM; канал crypto_box как у KeePassXC-Browser, подключение и каждый новый сайт подтверждаются в окне Keywarden; заполнение, выбор учётки, 2FA, сохранение и обновление пароля, генератор в поле регистрации; домены по Public Suffix List, невидимые поля и фреймы не заполняются | `make e2e-ext`: headless Chromium + настоящие host и демон |
| Ключи доступа | перехват `navigator.credentials`, ES256, хранение в формате KeePassXC (`KPEX_PASSKEY_*`) | `make e2e-ext`: регистрация и вход, подпись проверяется на странице через WebCrypto, `keepassxc-cli` видит ключ |
| SSH-агент | свой `SSH_AUTH_SOCK`, ключи из записей с настройками KeeAgent, ed25519/ecdsa/rsa, зашифрованные ключи паролем из записи, подтверждение использования, импорт ключа, новый ключ Ed25519/ECDSA/RSA, `kw ssh`: выбор сервера в терминале по папкам | `make e2e-ssh`: `ssh-keygen -Y sign/verify` через агент; после `kw lock` ключей нет |
| Синхронизация | inotify, слияние по UUID и времени правки, DeletedObjects, конфликтные копии Syncthing сливаются и убираются в бэкапы, уведомление | тесты `merge`, `state`; e2e: KeePassXC пишет в файл, пока база открыта |
| Импорт | Bitwarden JSON → типы Keywarden, отчёт «перенесено / проверить вручную» | тесты `bitwarden`, e2e |
| Смена ключа и настройки базы | мастер-пароль, файл-ключ (создаётся в формате KeePassXC), YubiKey; имя, корзина, лимиты истории, шифр, Argon2 с подбором под компьютер; старые KDBX 3.1 и 4.0 при сохранении становятся 4.1 | тесты `vault`, `settings`; `keepassxc-cli` открывает новым ключом и не открывает старым |
| Перенос | экспорт CSV (формат KeePassXC) и копия .kdbx с другим паролем; импорт CSV из KeePassXC, Chrome, Firefox, Bitwarden, 1Password, Proton Pass, другой базы .kdbx/.kdb, JSON Bitwarden, бэкапа 2FAS; слияние с копией базы | тесты `transfer`, e2e |
| Записи | теги (панель и `#тег`), срок действия с подсветкой, дублирование (Ctrl+D), перетаскивание записей и папок, сортировка, ссылки `{REF:…}` и `{USERNAME}` | тесты `model`, e2e |
| Поиск | `user:` `url:` `title:` `notes:` `group:` `tag:` `pass:` `is:expired` `is:otp`, `-исключение`, `"фраза"`, `/регулярка/` | тесты `search` |
| 2FA как в 2FAS | страница кодов, следующий код, мастер (секрет, otpauth, QR из буфера или картинки), QR для телефона, импорт и экспорт `.2fas`, `kw otp qr` в терминале | тесты `totp`, `twofas`, распознавание QR |
| Проверка паролей | слабые (zxcvbn), повторы, старше года, истёкшие, утечки Have I Been Pwned по кнопке (k-анонимность); «исключить из отчётов» как в KeePassXC | тесты `health`, e2e с живым HIBP |
| Иконки | логотипы Simple Icons (3466, CC0, офлайн) по названию и домену, монограммы; favicon по кнопке в иконку базы | тесты `brands`, e2e с живым favicon |
| Связка ключей | Secret Service (`org.freedesktop.secrets`) вместо gnome-keyring: отдельная папка базы, подтверждение чтения программой, сессии dh-ietf1024, перенос из текущей связки | `make e2e-secrets`: настоящий `secret-tool` |
| Несколько баз | по демону на базу (`keywardend --profile ИМЯ`, `keywardend@.service`), переключатель и Ctrl+Tab в окне, лаунчер ищет по всем открытым | e2e, `make ui-shots` |
| Автоввод | `kw autotype` на горячей клавише niri: окно из IPC niri, набор через `wtype` (пароль через stdin), последовательности KeePass и ассоциации окон, проверка фокуса перед набором | тесты `autotype`, `make ui-shots` |
| Локальный API | `list`, `secret_copy`, `save_from_clipboard` на отдельном сокете, секреты не выдаются никогда | тесты `api`, e2e с буфером |

## Состав

| Путь | Что это |
| --- | --- |
| `crates/keywarden-core` | KDBX, модель записей, TOTP, поиск, генератор, слияние, KeeAgent, passkeys, импорт Bitwarden, протокол IPC |
| `crates/keywarden-daemon` | `keywardend`: база в памяти, сохранение, автоблокировка, буфер, браузер, SSH-агент, синхронизация, API |
| `crates/keywarden-cli` | `kw` |
| `crates/keywarden-ui` | `keywarden-ui` (главное окно), `--launcher`, `--confirm` (окно подтверждения); GPUI / gpui-kit |
| `crates/keywarden-host` | native messaging host: пересылает зашифрованные сообщения расширения демону |
| `crates/keywarden-ext` | логика расширения на Rust (WASM) и её же правила в демоне: адреса, поля формы, протокол, шифрование |
| `extension/` | WXT + Svelte 5: background (WASM), content script, ключи доступа (MAIN world), popup |
| `vendor/keepass` | keepass-rs 0.17.0 с исправлениями, см. `vendor/keepass/KEYWARDEN-PATCH.md` |
| `dist/` | systemd unit, манифесты native messaging, niri, Noctalia, .desktop |
| `docs/local-api.md` | протокол локального API для ассистентов и скриптов |

## Сборка и проверки

Всё запускается в Docker с лимитом 8 ГБ без свопа (`docker/Dockerfile.dev`, Arch).

```sh
make image        # один раз: образ keywarden-dev
make test         # unit и интеграционные тесты, в т.ч. совместимость с keepassxc-cli
make clippy
make e2e          # демон + kw на базе из KeePassXC, синхронизация, импорт
make e2e-crash    # kill -9 при записи, буфер обмена (headless sway), локальный API, дампы
make e2e-ssh      # SSH-агент
make e2e-ext      # расширение в headless Chromium, включая ключи доступа
make e2e-secrets  # связка ключей: secret-tool против keywardend
make ui-shots     # лаунчер и главное окно в headless sway, скриншоты в target/shots
make build        # release-бинарники в target/release
make ext ext-firefox   # расширение: extension/.output/{chrome,firefox}-mv3
make check-cross  # clippy под Windows и macOS из Linux
make e2e-wine     # демон и kw для Windows под Wine
```

## CI и релизы

- `.github/workflows/ci.yml`: на каждый push в main и PR. Формат, clippy, тесты и сборка
  на Linux, Windows и macOS (интерфейс GPUI собирается только на своей системе), сборка и
  проверка типов расширения.
- `.github/workflows/release.yml`: по тегу `vX.Y.Z`. Архивы под Linux x86_64, Windows x86_64,
  macOS arm64, zip расширения для Chrome и Firefox, `SHA256SUMS`. Релиз публикуется сразу,
  текст берётся из `.github/release-notes.md`.

Выпуск версии:

```sh
# версия в Cargo.toml ([workspace.package]) и extension/package.json должна совпадать с тегом
git tag v0.1.0 && git push origin v0.1.0
```

Бинарники пока без подписи: Windows SmartScreen предупредит при первом запуске, на macOS
снять карантин: `xattr -dr com.apple.quarantine keywarden-*`.

## Установка (домашний каталог, без root)

```sh
make build ext-firefox
sh scripts/install.sh          # бинарники в ~/.local/bin, systemd user unit, манифесты браузеров
```

Затем вручную (скрипт напомнит):

1. **niri**: `include "keywarden.kdl"` (файл `dist/niri/keywarden.kdl`): `Mod+Shift+P` лаунчер.
   Для SSH-агента в окружение сессии: `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keywarden/ssh.sock`
   (или `eval "$(kw ssh-env)"` в оболочке).
2. **Noctalia**: в `~/.config/noctalia/config.toml`
   ```toml
   [theme.templates.user.keywarden]
   input_path  = "templates/keywarden.json"
   output_path = "$XDG_CONFIG_HOME/keywarden/themes/noctalia.json"
   ```
3. **База**: `kw unlock --db ~/Sync/keepass/main.kdbx` (путь запомнится) или `kw new ПУТЬ`.
4. **Firefox**: `about:debugging` → «Загрузить временное дополнение» → `extension/.output/firefox-mv3/manifest.json`
   (для постоянной установки дополнение нужно подписать в AMO), затем в настройках дополнения
   разрешить доступ к сайтам. **Chromium**: «Загрузить распакованное» → `extension/.output/chrome-mv3`,
   затем `CHROMIUM_EXTENSION_ID=<id> sh scripts/install.sh`. В popup расширения нажать «Подключить».

## kw

```
kw unlock [--db ПУТЬ] [-k ФАЙЛ-КЛЮЧ] [-y СЛОТ[:СЕРИЙНЫЙ]]   kw lock   kw status
kw search ЗАПРОС        kw show ЗАПРОС [-r]     kw copy ЗАПРОС [-f password|username|totp|ПОЛЕ]
kw totp ЗАПРОС [-c]     kw add -t login|card|identity|note|ssh-key --title …   kw edit …   kw rm …
kw generate [-l 24] [-p -w 6] [-c]     kw groups   kw mkgroup A/B   kw attach / kw attachment
kw ssh-import ФАЙЛ [--confirm]   kw ssh-env   kw import-bitwarden ФАЙЛ.json   kw yubikeys   kw new ПУТЬ
kw passwd [-k ФАЙЛ-КЛЮЧ]   kw keyfile ПУТЬ   kw db-settings [--tune …]   kw health [--breaches]
kw export ПУТЬ [-f csv|kdbx|2fas]   kw import ФАЙЛ   kw merge ФАЙЛ.kdbx   kw dup / kw mv / kw tags
kw otp set|scan|qr   kw icon ЗАПРОС [--clear]   kw autotype [ЗАПРОС]   kw secrets-import
kw --profile ИМЯ …   kw profiles   kw profile-add ИМЯ ФАЙЛ.kdbx
```

## Известные ограничения

- YubiKey проверен эмуляцией HMAC-секретом, с настоящим ключом нет (в контейнере его нет).
- Блокировка по экрану и сну проверяется только на живой системе (в контейнере нет logind).
  Если локер Noctalia не сообщает logind о блокировке, повесьте `kw lock` на его запуск.
- Сохранение вложения на диск и выбор файлов идут через xdg-desktop-portal; в стенде не проверялись.
- Фреймы расширение не заполняет вообще (заполнение во фреймах только по разрешению, а само разрешение пока не сделано).
- Автоввод: niri и Sway (`wtype`), X11 (`xdotool`), Windows и macOS (enigo). В GNOME под Wayland
  не работает: система не даёт печатать в чужие окна. Активное окно на Wayland знает только niri.
- Связка ключей (Secret Service) только в Linux; YubiKey на Windows и macOS в бете.
- Интерфейс под Windows и macOS собирается в CI, вживую на этих системах ещё не проверялся.
- Связка ключей: имя `org.freedesktop.secrets` занимает gnome-keyring; Keywarden его не отнимает. Сначала «Перенести из текущей связки», затем отключить компонент secrets у gnome-keyring и перезапустить keywardend.
- Импорт `.2fas` проверен на собственном экспорте, а не на файле из приложения 2FAS; зашифрованные бэкапы 2FAS не читаются.
- Расширение и Secret Service работают с основной базой; дополнительные базы доступны в окне, лаунчере и `kw`.
- Перетаскивание мышью и системный выбор файлов в стенде не проверялись (там только клавиатура).
- Ключи доступа: только ES256 (как у большинства сайтов); для остальных работает обычный WebAuthn браузера.

## Переводы

Новый язык добавляется без правок кода: инструкция для переводчиков в
[docs/translating.md](docs/translating.md), подключение Weblate в [docs/publishing.md](docs/publishing.md).

## Лицензия

[GPL-3.0-or-later](LICENSE).
