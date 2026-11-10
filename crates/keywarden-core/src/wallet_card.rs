//! Карточка восстановления для печати: PDF A4 со словами фразы сеткой и, по желанию, SeedQR.
//! Шрифт Inter (OFL, data/Inter-LICENSE) встроен: кириллица печатается на любом компьютере.

use printpdf::{
    Color, IndirectFontRef, Line, Mm, PdfDocument, PdfLayerReference, Point, Rect, Rgb,
    path::PaintMode,
};

const FONT: &[u8] = include_bytes!("../data/Inter-Regular.ttf");

pub struct Card {
    /// название кошелька
    pub title: String,
    /// «BIP39, 24 слова», «SLIP-39, доля 2 из 3»
    pub format: String,
    pub words: Vec<String>,
    /// SeedQR: сторона и клетки (true = тёмная)
    pub qr: Option<(usize, Vec<bool>)>,
    pub date: String,
}

fn gray(v: f32) -> Color {
    Color::Rgb(Rgb::new(v, v, v, None))
}

fn frame(l: &PdfLayerReference, x: f32, y: f32, w: f32, h: f32) {
    let pts = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
        .into_iter()
        .map(|(a, b)| (Point::new(Mm(a), Mm(b)), false))
        .collect();
    l.add_line(Line {
        points: pts,
        is_closed: true,
    });
}

pub fn card_pdf(c: &Card) -> Result<Vec<u8>, String> {
    let (doc, page, layer) = PdfDocument::new(
        crate::tr!("Keywarden: карточка восстановления"),
        Mm(210.0),
        Mm(297.0),
        "card",
    );
    let font: IndirectFontRef = doc
        .add_external_font(std::io::Cursor::new(FONT))
        .map_err(|e| e.to_string())?;
    let l = doc.get_page(page).get_layer(layer);
    let (x0, w) = (20.0_f32, 170.0_f32);
    let mut y = 270.0_f32;

    l.set_fill_color(gray(0.0));
    l.use_text(&c.title, 20.0, Mm(x0), Mm(y), &font);
    y -= 7.0;
    l.set_fill_color(gray(0.35));
    l.use_text(
        format!("{}  ·  {}", c.format, c.date),
        10.0,
        Mm(x0),
        Mm(y),
        &font,
    );
    y -= 10.0;

    // слова: три колонки по порядку сверху вниз, крупно и с номерами
    let n = c.words.len();
    let rows = n.div_ceil(3).max(1);
    let row_h = 10.0_f32;
    let grid_h = rows as f32 * row_h + 8.0;
    l.set_outline_color(gray(0.6));
    l.set_outline_thickness(0.6);
    frame(&l, x0, y - grid_h, w, grid_h);
    for (i, word) in c.words.iter().enumerate() {
        let (col, row) = (i / rows, i % rows);
        let x = x0 + 6.0 + col as f32 * (w / 3.0);
        let wy = y - 9.0 - row as f32 * row_h;
        l.set_fill_color(gray(0.45));
        l.use_text(format!("{:>2}.", i + 1), 11.0, Mm(x), Mm(wy), &font);
        l.set_fill_color(gray(0.0));
        l.use_text(word, 14.0, Mm(x + 9.0), Mm(wy), &font);
    }
    y -= grid_h + 10.0;

    if let Some((side, cells)) = &c.qr {
        let size = 60.0_f32;
        let cell = size / *side as f32;
        l.set_fill_color(gray(0.6));
        l.use_text("SeedQR", 10.0, Mm(x0), Mm(y), &font);
        y -= 4.0;
        l.set_fill_color(gray(0.0));
        let top = y;
        for (i, dark) in cells.iter().enumerate() {
            if *dark {
                let (cx, cy) = ((i % side) as f32, (i / side) as f32);
                let rx = x0 + cx * cell;
                let ry = top - (cy + 1.0) * cell;
                l.add_rect(
                    Rect::new(Mm(rx), Mm(ry), Mm(rx + cell), Mm(ry + cell))
                        .with_mode(PaintMode::Fill),
                );
            }
        }
        y -= size + 10.0;
    }

    l.set_fill_color(gray(0.35));
    for line in [
        crate::tr!("Кто владеет этими словами, тот владеет кошельком. Никому их не показывайте"),
        crate::tr!(
            "и не фотографируйте. Храните карточку там же, где документы, отдельно от компьютера."
        ),
        crate::tr!("Ни один сервис и ни одна поддержка не попросят эти слова."),
    ] {
        l.use_text(line, 9.5, Mm(x0), Mm(y), &font);
        y -= 5.0;
    }

    doc.save_to_bytes().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{Card, card_pdf};

    #[test]
    fn card_is_a_pdf() {
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .map(String::from)
            .collect();
        let pdf = card_pdf(&Card {
            title: "Основной кошелёк".into(),
            format: "BIP39, 12 слов".into(),
            qr: crate::wallet::seedqr(&words.join(" "), false),
            words,
            date: "2026-11-09".into(),
        })
        .unwrap();
        // KW_CARD_OUT=путь: сохранить карточку, чтобы посмотреть глазами
        if let Ok(p) = std::env::var("KW_CARD_OUT") {
            std::fs::write(p, &pdf).unwrap();
        }
        assert!(pdf.starts_with(b"%PDF"));
        assert!(pdf.len() > 10_000, "шрифт встроен");
    }
}
