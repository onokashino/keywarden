# Патч Keywarden к keepass-rs 0.17.0

`EntryMut::remove_attachment_by_name` и `remove_attachment_by_id` удаляли из вложения все ссылки
записи (`retain(|(entry_id, _)| entry_id != id)`), включая ссылки её исторических версий.
Вложение пропадало из истории, а если других ссылок не было, то и из базы.

Исправление: удаляется только ссылка `(id, history_index)` той версии, у которой убирают вложение.
Тест: `keywarden-core` `model::tests::attachments_roundtrip`.

## 2. CustomData: строка не должна становиться Binary

`CustomDataValue::deserialize` пытался декодировать каждое значение как base64, и строки,
случайно похожие на base64 (`card`, `note`, `1000`), превращались в `Binary`. В файл они
возвращались той же строкой, но в памяти смысл значения менялся. В KDBX XML значение
CustomData всегда строка, поэтому теперь оно всегда `String`.
Тест: `keywarden-core` `model::tests::kind_survives_save`.

## 3. Слияние: вложения

`Database::merge` копировал записи и версии истории из второй базы вместе с номерами вложений,
но номера вложений локальны для базы (`TODO: attachments` в исходнике): запись ссылалась бы
на чужой файл. Теперь перед слиянием вложения второй базы переводятся в номера первой
(`remap_attachments`, одинаковые данные склеиваются), обновлённая запись получает свои
вложения, а в конце `remove_unused_attachments` восстанавливает обратные ссылки.
Тесты: `keywarden-core` `merge::tests`.

## 4. Обратные ссылки пользовательских иконок

`CustomIcon.entries/groups` заполнял только парсер. После слияния и после правок с историей
(новая версия вставляется в начало и сдвигает индексы) ссылки устаревали, и база в памяти
переставала совпадать с собой после записи и чтения. Добавлен публичный
`Database::rebuild_custom_icon_refs()`, слияние вызывает его в конце.
Тест: `keywarden-core` `keepassxc_compat::merge_with_keepassxc_change_saves`.

## 5. Экспорт `Yubikey`

`ChallengeResponseKey::YubikeyChallenge(Yubikey, slot)` публичный, а сам `Yubikey` не был
экспортирован, и собрать такой ключ снаружи было нельзя. Теперь `keepass::Yubikey`.

## 6. Внешний challenge-response (YubiKey через HID)

Библиотека `challenge_response` говорит с YubiKey как с сырым USB-устройством. На Windows и
macOS интерфейс ключа держит системный HID-драйвер, и такой доступ невозможен. Теперь:

- фича `challenge_response` даёт только сам механизм (без USB-библиотеки);
- `yubikey_usb` включает прежний путь (`YubikeyChallenge`, `Yubikey`, `get_available_yubikeys`);
- новый вариант `ChallengeResponseKey::External(ExternalChallenge)`: ответ на challenge считает
  вызывающий код. Keywarden так подключает YubiKey через hidapi (`keywarden-core/src/yubikey.rs`).
