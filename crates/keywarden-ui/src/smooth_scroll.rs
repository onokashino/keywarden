//! Плавная прокрутка колесом мыши. GPUI сдвигает список на целый шаг за щелчок колеса, и
//! на Linux это выглядит рывками. Щелчок (дельта в строках) перехватывается в фазе захвата,
//! до прокручиваемых областей, и отдаётся окну серией пиксельных шагов с замедлением.
//! Тачпад присылает точные пиксели сам: его события не трогаем.

use gpui_kit::*;
use std::cell::RefCell;
use std::time::Instant;

/// Время, за которое проходится ~63% оставшегося пути: щелчок доезжает примерно за 4τ.
const TAU_MS: f32 = 35.;
/// Пикселей на строку колеса: GPUI считает строку высотой строки текста, это мелко для списков.
const LINES_SCALE: f32 = 1.6;

#[derive(Default)]
struct State {
    remaining: Point<Pixels>,
    position: Point<Pixels>,
    modifiers: Modifiers,
    last: Option<Instant>,
    running: bool,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Элемент-невидимка: вставить один раз в корень окна.
pub fn listener() -> impl IntoElement {
    canvas(
        |_, _, _| {},
        |_, _, window, _| {
            window.on_mouse_event(|e: &ScrollEvent, phase, window, cx| {
                if phase != DispatchPhase::Capture || e.source != ScrollSource::Pointer {
                    return;
                }
                let ScrollDelta::Lines(lines) = e.delta else {
                    return;
                };
                cx.stop_propagation();
                let lh = window.line_height() * LINES_SCALE;
                let start = STATE.with_borrow_mut(|s| {
                    // смена направления: остаток прежнего пути отбрасываем
                    if (s.remaining.y.as_f32() * lines.y) < 0. {
                        s.remaining.y = px(0.);
                    }
                    if (s.remaining.x.as_f32() * lines.x) < 0. {
                        s.remaining.x = px(0.);
                    }
                    s.remaining.x += lh * lines.x;
                    s.remaining.y += lh * lines.y;
                    s.position = e.position;
                    s.modifiers = e.modifiers;
                    let start = !s.running;
                    if start {
                        s.running = true;
                        s.last = Some(Instant::now());
                    }
                    start
                });
                if start {
                    // не из обработчика: повторная отправка события посреди разбора текущего
                    window.on_next_frame(step);
                    window.refresh();
                }
            });
        },
    )
    .absolute()
    .size_0()
}

fn step(window: &mut Window, cx: &mut App) {
    let now = Instant::now();
    let event = STATE.with_borrow_mut(|s| {
        let dt = s
            .last
            .map_or(16., |t| (now - t).as_secs_f32() * 1000.)
            .clamp(1., 64.);
        s.last = Some(now);
        let k = 1. - (-dt / TAU_MS).exp();
        let mut d = Point::new(s.remaining.x * k, s.remaining.y * k);
        // хвост меньше полупикселя отдаём целиком и останавливаемся
        if s.remaining.x.abs() - d.x.abs() < px(0.5) && s.remaining.y.abs() - d.y.abs() < px(0.5) {
            d = s.remaining;
            s.running = false;
        }
        s.remaining.x -= d.x;
        s.remaining.y -= d.y;
        ScrollEvent {
            position: s.position,
            delta: ScrollDelta::Pixels(d),
            modifiers: s.modifiers,
            touch_phase: TouchPhase::Moved,
            source: ScrollSource::Pointer,
        }
    });
    window.dispatch_event(PlatformInput::Scroll(event), cx);
    if STATE.with_borrow(|s| s.running) {
        window.on_next_frame(step);
        window.refresh();
    }
}
