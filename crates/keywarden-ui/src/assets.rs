//! Иконки: 101 стандартная из gpui-kit плюс нужные Keywarden из каталога Lucide.

use gpui_kit::{AssetSource, Result, SharedString};
use std::borrow::Cow;

gpui_kit_assets::icon_assets!(
    ExtraIcons,
    [
        KeyRound,
        CreditCard,
        IdCard,
        StickyNote,
        SquareTerminal,
        FingerprintPattern,
        Lock,
        LockOpen,
        Paperclip,
        RotateCcwClock,
        WandSparkles,
        Trash,
        Pencil,
        Save,
        Timer,
        FolderPlus,
        Shield,
        Key,
        Download,
        Upload,
        Link,
        ShieldCheck,
        LockKeyhole,
        CircleAlert,
        CircleCheck,
        ChevronRight,
        Check,
        Settings,
        FileDown,
        FileUp,
        Merge,
        KeySquare,
        Database,
        Import,
        ShieldAlert,
        SlidersHorizontal,
        ArrowLeftRight,
        Hash,
        CopyPlus,
        CalendarX,
        CalendarClock,
        ArrowUpDown,
        QrCode,
        TriangleAlert,
        ImageOff,
        ImageDown,
        ChevronsUpDown,
        Image,
        FileCode,
        TextWrap,
        Keyboard,
        FileText,
        Monitor,
        Wallet,
        Server
    ]
);

pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        // логотипы сервисов собираются из вшитой таблицы Simple Icons
        if let Some(slug) = path
            .strip_prefix("brand/")
            .and_then(|p| p.strip_suffix(".svg"))
        {
            return Ok(crate::brands::svg_source(slug).map(|s| Cow::Owned(s.into_bytes())));
        }
        // ExtraIcons на незнакомый путь отвечает ошибкой, а не None: тогда идём в стандартный набор
        if let Ok(Some(bytes)) = ExtraIcons.load(path) {
            return Ok(Some(bytes));
        }
        gpui_kit_assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit_assets::Assets.list(path)?;
        paths.extend(ExtraIcons.list(path).unwrap_or_default());
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}
