# Публикация: GitHub, сайт, релизы, магазины расширений

## 1. Один раз: репозиторий

1. Создать пустой репозиторий `onokashino/keywarden` (без README и лицензии, они уже есть).
2. `git remote add origin git@github.com:onokashino/keywarden.git && git push -u origin main`.
3. Settings, Pages, Source: **GitHub Actions**. После первого push в `site/` сайт появится на
   https://onokashino.github.io/keywarden/.
4. Settings, Code security: включить **Private vulnerability reporting** (на него ссылается SECURITY.md)
   и Dependabot alerts.
5. Settings, Environments: создать окружение **stores** и положить секреты магазинов туда
   (раздел 4). Можно включить «Required reviewers»: отправка в магазины будет ждать подтверждения.

## 2. Выпуск версии

1. Поднять версию в `Cargo.toml` (`[workspace.package] version`) и `extension/package.json`.
   Они должны совпадать, иначе релиз остановится на первом шаге.
2. Закоммитить, поставить тег, отправить:
   ```sh
   git tag v0.2.0 && git push origin main v0.2.0
   ```
3. `release.yml` соберёт архивы под Linux, Windows и macOS, zip расширения для Chrome и Firefox,
   архив исходников для AMO и `SHA256SUMS`, и создаст **черновик** релиза.
4. Проверить черновик на странице Releases, поправить заметки и нажать **Publish release**.
5. Публикация релиза запускает `extension-stores.yml`: расширение уходит на проверку в те
   магазины, для которых заданы секреты. Остальные пропускаются с предупреждением.

Проверить секреты без отправки: Actions, extension-stores, Run workflow, указать тег,
галочка «Только проверить секреты» (включена по умолчанию).

## 3. Один раз: первая публикация в магазинах (вручную)

Автоматика умеет только обновлять уже существующую карточку. Первый раз загружаем руками.
Zip берём из первого релиза.

### Firefox (addons.mozilla.org)

1. Войти на https://addons.mozilla.org/developers/ и нажать «Submit a New Add-on».
2. Выбрать «On this site» (листинг в каталоге).
3. Загрузить `keywarden-extension-X.Y.Z-firefox.zip`.
4. На вопрос про исходники ответить «Yes» и загрузить `keywarden-vX.Y.Z-sources.zip`.
   Расширение содержит WASM, собранный из Rust, поэтому нужен весь репозиторий, а инструкция
   для ревьюеров лежит в `SOURCE_CODE_REVIEW.md`.
5. Заполнить карточку: описание, категория «Privacy & Security», скриншоты, ссылка на сайт,
   политика приватности («ничего не собирает», это же указано в манифесте).
6. id расширения задан в манифесте: `keywarden@onokashino.github.io`. Это и есть секрет
   `FIREFOX_EXTENSION_ID`.
7. Ключи API: https://addons.mozilla.org/developers/addon/api/key/. JWT issuer идёт в
   `FIREFOX_JWT_ISSUER`, JWT secret в `FIREFOX_JWT_SECRET`.

### Chrome Web Store

1. Регистрация разработчика: https://chrome.google.com/webstore/devconsole, разовый взнос $5.
2. «New item», загрузить `keywarden-extension-X.Y.Z-chrome.zip`.
3. Заполнить карточку и вкладку Privacy. Для каждого разрешения (`nativeMessaging`, `tabs`,
   `scripting`, `favicon`, `storage`, `activeTab`) нужно обоснование. Основное: «связь с локальным
   приложением Keywarden для заполнения паролей». Data usage: ничего не собирается.
4. После проверки появится id расширения (32 буквы). Это `CHROME_EXTENSION_ID`. Его же нужно
   прописать по умолчанию в `crates/keywarden-cli/src/browser.rs` и
   `dist/native-messaging/chromium.json`, чтобы `kw browser-setup` работал без `--chrome-id`.
5. Доступ для CI (API v2, сервисный аккаунт):
   - в Google Cloud создать проект, включить «Chrome Web Store API», создать сервисный аккаунт
     и JSON-ключ;
   - в Developer Dashboard, Account, добавить email сервисного аккаунта;
   - секреты: `CHROME_PUBLISHER_ID` (id издателя из Dashboard),
     `CHROME_SERVICE_ACCOUNT_CLIENT_EMAIL`, `CHROME_SERVICE_ACCOUNT_PRIVATE_KEY` (поле
     `private_key` из JSON целиком, с `-----BEGIN PRIVATE KEY-----`).

### Microsoft Edge Add-ons

1. Partner Center: https://partner.microsoft.com/dashboard/microsoftedge (бесплатно).
2. Создать расширение и загрузить тот же zip для Chrome.
3. После публикации: Publish API, «Create API credentials». Секреты: `EDGE_PRODUCT_ID`,
   `EDGE_CLIENT_ID`, `EDGE_API_KEY`.

## 4. Секреты, итог

| Секрет | Откуда |
| --- | --- |
| `FIREFOX_EXTENSION_ID` | `keywarden@onokashino.github.io` |
| `FIREFOX_JWT_ISSUER`, `FIREFOX_JWT_SECRET` | AMO, Manage API Keys |
| `CHROME_EXTENSION_ID` | Chrome Web Store, после первой публикации |
| `CHROME_PUBLISHER_ID` | Chrome Developer Dashboard, Account |
| `CHROME_SERVICE_ACCOUNT_CLIENT_EMAIL`, `CHROME_SERVICE_ACCOUNT_PRIVATE_KEY` | Google Cloud, сервисный аккаунт |
| `EDGE_PRODUCT_ID`, `EDGE_CLIENT_ID`, `EDGE_API_KEY` | Partner Center, Publish API |

Секреты кладутся в окружение `stores` (Settings, Environments, stores, Add secret).

## 5. Что делает пользователь

- Расширение из магазина обновляется браузером само.
- Firefox для Android магазин тоже покажет, но без приложения на телефоне расширению не с чем
  связаться: в карточке AMO отметить только Firefox для компьютера.

## 6. Обновления приложения: AUR, Homebrew, winget

При публикации релиза `packages.yml` обновляет пакеты в трёх каналах. Канал без секрета
пропускается. Секреты кладутся в окружение `packages` (Settings, Environments). Предрелизы
(тег с дефисом, например `v0.2.0-rc1`) в пакеты не попадают.

### AUR (`keywarden-bin`)

1. Аккаунт на https://aur.archlinux.org, в профиле добавить публичный SSH-ключ
   (отдельный, только для AUR: `ssh-keygen -t ed25519 -f aur -C aur`).
2. Пакет создаётся первым же push, ничего регистрировать заранее не нужно.
3. Секрет `AUR_SSH_PRIVATE_KEY`: содержимое файла `aur` (приватный ключ).
4. Шаблон: `packaging/aur/PKGBUILD`. CI подставляет версию и sha256 архива.

Установка: `paru -S keywarden-bin`, обновления приходят вместе с системой.

### Homebrew (macOS)

1. Создать публичный репозиторий `onokashino/homebrew-tap` (пустой).
2. Fine-grained токен с доступом Contents: Read and write только к `homebrew-tap`,
   секрет `HOMEBREW_TAP_TOKEN`.
3. Шаблон: `packaging/homebrew/keywarden.rb`.

Установка: `brew install onokashino/tap/keywarden`, обновление: `brew upgrade`. Homebrew
качает архив сам, поэтому macOS не ставит карантин и `xattr` не нужен.

### winget (Windows)

1. Первую версию отправить вручную:
   `wingetcreate new https://github.com/onokashino/keywarden/releases/download/v0.1.0/keywarden-v0.1.0-windows-x86_64.zip`
   (тип установщика zip, вложенный portable, идентификатор `onokashino.Keywarden`), дождаться
   принятия PR в microsoft/winget-pkgs.
2. Сделать форк `microsoft/winget-pkgs` в свой аккаунт.
3. Classic-токен со scope `public_repo`, секрет `WINGET_TOKEN`.

Дальше каждая версия уходит в winget сама: `winget install onokashino.Keywarden`,
обновление `winget upgrade`.

## 7. Переводы от сообщества: Weblate

Переводить можно и пулл-реквестами (инструкция для переводчиков: `docs/translating.md`), но удобнее
всего через Weblate: переводчик работает в браузере, Weblate сам проверяет подстановки и присылает
изменения в репозиторий.

1. https://hosted.weblate.org, «Add new translation project» (для открытых проектов бесплатно,
   нужен публичный репозиторий и лицензия, GPL подходит).
2. Компонент «App», по одному на файл каталога (`core`, `daemon`, `cli`, `ui`, `ui_settings`):
   - формат: **JSON file**, одноязычный;
   - маска файлов: `locales/*/ui.json` (и так для каждого файла);
   - одноязычный образец: `locales/en/ui.json`;
   - исходный язык проекта: **English** (переводчик видит английский текст, русский ключ
     остаётся ключом);
   - шаблон для нового языка: пустой, `{}`.
3. Компонент «Extension»:
   - формат: **WebExtension JSON**;
   - маска: `extension/public/_locales/*/messages.json`, образец `extension/public/_locales/en/messages.json`.
4. В настройках проекта: «Push on commit», pull-реквесты в `main`; добавить вебхук GitHub из
   инструкции Weblate, чтобы новые строки появлялись там сразу.
5. Значок со статусом перевода из Weblate можно добавить в README.

Новый язык, созданный в Weblate, сразу виден в приложении: каталоги находятся при сборке
(`crates/keywarden-core/build.rs`), код менять не нужно. Тесты (`cargo test`) не пропустят
перевод с потерянной подстановкой или устаревшими строками.
