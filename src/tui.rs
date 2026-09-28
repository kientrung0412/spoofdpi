//! Terminal UI: logo, live traffic speed and a filterable log view.
//!
//! Keys: `f` filter, `enter` apply, `esc` cancel/unfilter, `R` clear,
//! arrows/PageUp/PageDown/Home/End scroll, `Ctrl+C` quit.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use tokio_util::sync::CancellationToken;

use crate::netutil;

const LOGO: &str = include_str!("../assets/logo.txt");
const MAX_LOGS: usize = 5000;

const SPINNER: &[&str] = &[
    "⢀⠀", "⡀⠀", "⠄⠀", "⢂⠀", "⡂⠀", "⠅⠀", "⢃⠀", "⡃⠀", "⠍⠀", "⢋⠀", "⡋⠀", "⠍⠁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉",
    "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⢈⠩", "⡀⢙", "⠄⡙", "⢂⠩", "⡂⢘", "⠅⡘", "⢃⠨", "⡃⢐", "⠍⡐", "⢋⠠", "⡋⢀", "⠍⡁",
    "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⠈⠩", "⠀⢙", "⠀⡙", "⠀⠩", "⠀⢘", "⠀⡘", "⠀⠨",
    "⠀⢐", "⠀⡐", "⠀⠠", "⠀⢀", "⠀⡀",
];

pub struct Tui {
    thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Tui {
    /// Starts the UI thread and returns once the terminal is ready. Log lines
    /// sent to the returned channel are displayed.
    pub fn start(cancel: CancellationToken) -> io::Result<(Tui, mpsc::Sender<String>)> {
        let (log_tx, log_rx) = mpsc::channel::<String>();
        let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let thread = std::thread::Builder::new().name("tui".into()).spawn(move || {
            let mut terminal = match ratatui::try_init() {
                Ok(t) => t,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let _ = crossterm::execute!(io::stdout(), crossterm::event::EnableMouseCapture);
            let _ = ready_tx.send(Ok(()));

            let mut app = App::new();
            while !stop2.load(Ordering::Relaxed) {
                while let Ok(line) = log_rx.try_recv() {
                    app.push_log(line);
                }
                app.tick();
                let _ = terminal.draw(|f| app.draw(f));

                if event::poll(Duration::from_millis(40)).unwrap_or(false) {
                    if let Ok(ev) = event::read() {
                        if app.handle_event(ev) {
                            cancel.cancel();
                        }
                    }
                }
            }
            let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
            ratatui::restore();
        })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok((
                Tui {
                    thread: Some(thread),
                    stop,
                },
                log_tx,
            )),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::other("tui thread exited")),
        }
    }

    /// Restores the terminal.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct App {
    logs: Vec<String>,
    filter: String,
    input: String,
    input_mode: bool,
    /// Lines scrolled up from the bottom; 0 follows the tail.
    scroll: usize,
    spinner: usize,
    last_spin: Instant,
    last_tick: Instant,
    last_tx: u64,
    last_rx: u64,
    avg_up: f64,
    avg_down: f64,
    wrapped: Vec<String>,
    wrapped_width: u16,
    dirty: bool,
}

impl App {
    fn new() -> Self {
        Self {
            logs: Vec::new(),
            filter: String::new(),
            input: String::new(),
            input_mode: false,
            scroll: 0,
            spinner: 0,
            last_spin: Instant::now(),
            last_tick: Instant::now(),
            last_tx: netutil::tx_bytes(),
            last_rx: netutil::rx_bytes(),
            avg_up: 0.0,
            avg_down: 0.0,
            wrapped: Vec::new(),
            wrapped_width: 0,
            dirty: true,
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
        if self.logs.len() > MAX_LOGS {
            let excess = self.logs.len() - MAX_LOGS;
            self.logs.drain(..excess);
        }
        self.dirty = true;
    }

    fn tick(&mut self) {
        if self.last_spin.elapsed() >= Duration::from_millis(40) {
            self.spinner = (self.spinner + 1) % SPINNER.len();
            self.last_spin = Instant::now();
        }
        let elapsed = self.last_tick.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            let tx = netutil::tx_bytes();
            let rx = netutil::rx_bytes();
            let up = (tx.saturating_sub(self.last_tx)) as f64 / 1024.0 / elapsed;
            let down = (rx.saturating_sub(self.last_rx)) as f64 / 1024.0 / elapsed;
            self.last_tx = tx;
            self.last_rx = rx;
            self.last_tick = Instant::now();
            const ALPHA: f64 = 0.3;
            self.avg_up = up * ALPHA + self.avg_up * (1.0 - ALPHA);
            self.avg_down = down * ALPHA + self.avg_down * (1.0 - ALPHA);
        }
    }

    /// Returns true when the user asked to quit.
    fn handle_event(&mut self, ev: Event) -> bool {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => {
                if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                    return true;
                }
                if self.input_mode {
                    match k.code {
                        KeyCode::Enter => {
                            self.filter = std::mem::take(&mut self.input);
                            self.input_mode = false;
                            self.scroll = 0;
                            self.dirty = true;
                        }
                        KeyCode::Esc => {
                            self.input_mode = false;
                            self.input.clear();
                        }
                        KeyCode::Backspace => {
                            self.input.pop();
                        }
                        KeyCode::Char(c) => self.input.push(c),
                        _ => {}
                    }
                    return false;
                }
                match k.code {
                    KeyCode::Char('f') => {
                        self.input_mode = true;
                        self.input.clear();
                    }
                    KeyCode::Char('R') => {
                        self.logs.clear();
                        self.scroll = 0;
                        self.dirty = true;
                    }
                    KeyCode::Esc if !self.filter.is_empty() => {
                        self.filter.clear();
                        self.scroll = 0;
                        self.dirty = true;
                    }
                    KeyCode::Up | KeyCode::Char('k') => self.scroll += 1,
                    KeyCode::Down | KeyCode::Char('j') => self.scroll = self.scroll.saturating_sub(1),
                    KeyCode::PageUp => self.scroll += 20,
                    KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(20),
                    KeyCode::Home | KeyCode::Char('g') => self.scroll = usize::MAX / 2,
                    KeyCode::End | KeyCode::Char('G') => self.scroll = 0,
                    _ => {}
                }
            }
            Event::Mouse(m) => match m.kind {
                MouseEventKind::ScrollUp => self.scroll += 3,
                MouseEventKind::ScrollDown => self.scroll = self.scroll.saturating_sub(3),
                _ => {}
            },
            Event::Resize(..) => self.dirty = true,
            _ => {}
        }
        false
    }

    fn rewrap(&mut self, width: u16) {
        if !self.dirty && width == self.wrapped_width {
            return;
        }
        let w = width.max(10) as usize;
        self.wrapped.clear();
        for line in self
            .logs
            .iter()
            .filter(|l| self.filter.is_empty() || l.contains(&self.filter))
        {
            let chars: Vec<char> = line.chars().collect();
            if chars.is_empty() {
                self.wrapped.push(String::new());
                continue;
            }
            for chunk in chars.chunks(w) {
                self.wrapped.push(chunk.iter().collect());
            }
        }
        self.wrapped_width = width;
        self.dirty = false;
    }

    fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        let logo_lines: Vec<&str> = LOGO.trim_start_matches('\n').lines().collect();
        let header_h = logo_lines.len() as u16 + 2;
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(header_h),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .areas(area);

        // Header: logo, speed, divider.
        let mut lines: Vec<Line> = logo_lines
            .iter()
            .map(|l| Line::styled(*l, Style::default().fg(Color::Green)))
            .collect();
        lines.push(Line::from(vec![
            Span::raw(" ".repeat(26)),
            Span::styled(
                format!(
                    "↑ {:8.1} KB/s ┆ ↓ {:8.1} KB/s {}",
                    self.avg_up, self.avg_down, SPINNER[self.spinner]
                ),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::styled(
            "─".repeat(area.width as usize),
            Style::default().fg(Color::DarkGray),
        ));
        f.render_widget(Paragraph::new(lines), header);

        // Log view.
        self.rewrap(body.width);
        let height = body.height as usize;
        let max_scroll = self.wrapped.len().saturating_sub(height);
        self.scroll = self.scroll.min(max_scroll);
        let end = self.wrapped.len() - self.scroll;
        let start = end.saturating_sub(height);
        let view: Vec<Line> = self.wrapped[start..end]
            .iter()
            .map(|l| style_log_line(l))
            .collect();
        f.render_widget(Paragraph::new(view), body);

        // Footer.
        let key = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
        let desc = Style::default().fg(Color::Gray);
        let (left, left_style, right): (String, Style, Vec<Span>) = if self.input_mode {
            (
                format!("filter: {}", self.input),
                Style::default().fg(Color::LightGreen),
                vec![
                    Span::styled("enter", key),
                    Span::styled(" apply  ", desc),
                    Span::styled("esc", key),
                    Span::styled(" cancel", desc),
                ],
            )
        } else {
            let mut r = Vec::new();
            if !self.filter.is_empty() {
                r.push(Span::styled("esc", key));
                r.push(Span::styled(" unfilter  ", desc));
            }
            r.extend([
                Span::styled("f", key),
                Span::styled(" filter  ", desc),
                Span::styled("R", key),
                Span::styled(" clear  ", desc),
                Span::styled("↑↓", key),
                Span::styled(" scroll  ", desc),
                Span::styled("^C", key),
                Span::styled(" quit", desc),
            ]);
            let left = if self.filter.is_empty() {
                String::new()
            } else {
                format!("filter: {}", self.filter)
            };
            (left, Style::default().fg(Color::LightBlue), r)
        };
        let [fl, fr] = Layout::horizontal([
            Constraint::Min(0),
            Constraint::Length(right.iter().map(|s| s.width() as u16).sum()),
        ])
        .areas(footer);
        f.render_widget(Paragraph::new(Line::styled(left, left_style)), fl);
        f.render_widget(Paragraph::new(Line::from(right)), fr);
    }
}

fn style_log_line(line: &str) -> Line<'_> {
    let color = if line.starts_with("TRC") {
        Some(Color::Magenta)
    } else if line.starts_with("DBG") {
        Some(Color::Yellow)
    } else if line.starts_with("INF") {
        Some(Color::Green)
    } else if line.starts_with("WRN") {
        Some(Color::Red)
    } else if line.starts_with("ERR") {
        Some(Color::LightRed)
    } else {
        None
    };
    match (color, line.get(..3), line.get(3..)) {
        (Some(c), Some(tag), Some(rest)) => Line::from(vec![
            Span::styled(tag, Style::default().fg(c).add_modifier(Modifier::BOLD)),
            Span::raw(rest),
        ]),
        _ => Line::raw(line),
    }
}
