# Правка Keywarden в gpui-component 0.9.0

`src/button/button.rs`: `cursor_pointer()` у всех интерактивных кнопок (в оригинале только у
вариантов link и text, остальные со стрелкой). Убрать, если upstream начнёт делать так же или
даст настройку.
`src/tab/tab.rs`, `src/select.rs`, `src/switch.rs`, `src/menu/popup_menu.rs`: то же для вкладок, выпадающих списков, переключателей и пунктов меню.
`src/menu/popup_menu.rs`: пункт меню 32px вместо 26px, отступы 10px, зазор значок-текст 8px.
