use anyhow::Result;

use binwalk::signatures::common::SignatureResult;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, Cell, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Wrap,
    },
};

use std::fs;

use crate::{disassemble, extract, metadata};

const ENTROPY_BLOCK_SIZE: usize = 1024;

const DEFAULT_STATUS: &str = "[Tab] pane   [Space] full   [↑/↓] scroll   [PgUp/PgDn] page   [/] search   [e] extract   [Enter] disasm   [m] meta   [q] quit";

const DISASM_FIELDS: [&str; 4] = [
    "Architecture",
    "Endianness",
    "Base address (hex)",
    "Offset (hex)",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Disasm,
    Files,
    Strings,
    Entropy,
}

struct FlatRow {
    text: String,
    label: String,
    source: extract::ByteSource,
    offset: usize,
    size: usize,
}

struct StringHit {
    text: String,
    offset: u64,
    important: bool,
    /// The extracted file it was pulled from; `None` for the original firmware.
    source: Option<String>,
}

const MAX_STRINGS: usize = 20_000;

struct SearchInput {
    pane: Pane,
    query: String,
}

struct Search {
    pane: Pane,
    query: String,
    matches: Vec<usize>,
    current: usize,
}

struct DisasmForm {
    values: [String; 4],
    active: usize,
    error: Option<String>,
}

impl DisasmForm {
    fn new() -> Self {
        Self {
            // Base address and offset default to 0
            values: [
                String::new(),
                String::new(),
                "0".to_string(),
                "0".to_string(),
            ],
            active: 0,
            error: None,
        }
    }
}

pub struct App {
    filepath: String,
    firmware: Vec<u8>,

    disasm: Vec<disassemble::Insn>,
    disasm_err: Option<String>,

    disasm_source: Option<(String, Vec<u8>)>,
    findings: Option<Vec<SignatureResult>>,

    file_rows: Vec<FlatRow>,
    strings: Vec<StringHit>,
    strings_err: Option<String>,
    entropy: Vec<(usize, f64)>,

    status: String,
    focus: Pane,

    fullscreen: bool,
    disasm_state: TableState,
    files_state: ListState,
    strings_state: ListState,

    disasm_input: Option<DisasmForm>,

    search_input: Option<SearchInput>,

    search: Option<Search>,
    should_quit: bool,
}

pub fn run(firmware: Vec<u8>, filepath: String) -> Result<()> {
    let terminal = ratatui::init();
    let app = App::new(firmware, filepath);
    let result = app.main_loop(terminal);
    ratatui::restore();
    result
}

impl App {
    fn new(firmware: Vec<u8>, filepath: String) -> Self {
        let (disasm, disasm_err) = match disassemble::disassembler(&firmware) {
            Ok(d) => (d, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let findings = extract::scan(&firmware);

        let (strings, strings_err) = match metadata::extract_strings(&firmware) {
            Ok(s) => (
                metadata::prioritize_strings(s)
                    .into_iter()
                    .map(|(text, offset, important)| StringHit {
                        text,
                        offset,
                        important,
                        source: None,
                    })
                    .collect(),
                None,
            ),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        let entropy = metadata::entropy_scan(&firmware, ENTROPY_BLOCK_SIZE);

        let mut disasm_state = TableState::default();
        if !disasm.is_empty() {
            disasm_state.select(Some(0));
        }
        let mut files_state = ListState::default();
        if findings.as_ref().is_some_and(|f| !f.is_empty()) {
            files_state.select(Some(0));
        }
        let mut strings_state = ListState::default();
        if !strings.is_empty() {
            strings_state.select(Some(0));
        }

        Self {
            filepath,
            firmware,
            disasm,
            disasm_err,
            disasm_source: None,
            findings,
            file_rows: Vec::new(),
            strings,
            strings_err,
            entropy,
            status: DEFAULT_STATUS.to_string(),
            focus: Pane::Disasm,
            fullscreen: false,
            disasm_state,
            files_state,
            strings_state,
            disasm_input: None,
            search_input: None,
            search: None,
            should_quit: false,
        }
    }

    fn main_loop(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| self.render(frame))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn handle_events(&mut self) -> Result<()> {
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(());
            }

            if self.disasm_input.is_some() {
                self.handle_form_key(key.code);
                return Ok(());
            }

            if self.search_input.is_some() {
                self.handle_search_key(key.code);
                return Ok(());
            }
            match key.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Esc => {
                    if self.search.is_some() {
                        self.clear_search();
                    } else {
                        self.should_quit = true;
                    }
                }
                KeyCode::Tab => self.cycle_focus(),
                KeyCode::Char(' ') => self.toggle_fullscreen(),
                KeyCode::Char('/') => self.open_search(),
                KeyCode::Down => self.scroll(1),
                KeyCode::Up => self.scroll(-1),
                KeyCode::Char('j') => self.search_or_scroll(1),
                KeyCode::Char('k') => self.search_or_scroll(-1),
                KeyCode::PageDown => self.scroll(10),
                KeyCode::PageUp => self.scroll(-10),
                KeyCode::Char('e') => self.extract(),
                KeyCode::Enter => self.disasm_selected_file(),
                KeyCode::Char('m') => self.open_disasm_form(),
                _ => {}
            }
        }
        Ok(())
    }

    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Pane::Disasm => Pane::Files,
            Pane::Files => Pane::Strings,
            Pane::Strings => Pane::Entropy,
            Pane::Entropy => Pane::Disasm,
        };

        if self.fullscreen {
            self.status = self.controls();
        }
    }

    fn toggle_fullscreen(&mut self) {
        self.fullscreen = !self.fullscreen;
        self.status = self.controls();
    }

    fn controls(&self) -> String {
        if !self.fullscreen {
            return DEFAULT_STATUS.to_string();
        }
        let pane_keys = match self.focus {
            Pane::Disasm => "[↑/↓] scroll   [PgUp/PgDn] page   [/] search   [m] disasm metadata",
            Pane::Files => "[↑/↓] scroll   [PgUp/PgDn] page   [e] extract   [Enter] disasm file",
            Pane::Strings => "[↑/↓] scroll   [PgUp/PgDn] page   [/] search",
            Pane::Entropy => "",
        };
        if pane_keys.is_empty() {
            "[Space] exit fullscreen   [Tab] pane   [q] quit".to_string()
        } else {
            format!("[Space] exit fullscreen   [Tab] pane   {pane_keys}   [q] quit")
        }
    }

    fn is_searchable(pane: Pane) -> bool {
        matches!(pane, Pane::Disasm | Pane::Strings)
    }

    fn open_search(&mut self) {
        if !Self::is_searchable(self.focus) {
            self.status = "Search works in the Disassembly and Strings panes.".to_string();
            return;
        }
        self.search_input = Some(SearchInput {
            pane: self.focus,
            query: String::new(),
        });
        self.status = self.search_input_status();
    }

    fn handle_search_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.search_input = None;
                self.status = self.controls();
            }
            KeyCode::Enter => self.commit_search(),
            KeyCode::Backspace => {
                if let Some(input) = self.search_input.as_mut() {
                    input.query.pop();
                }
                self.status = self.search_input_status();
            }
            KeyCode::Char(c) => {
                if let Some(input) = self.search_input.as_mut() {
                    input.query.push(c);
                }
                self.status = self.search_input_status();
            }
            _ => {}
        }
    }

    fn commit_search(&mut self) {
        let Some(input) = self.search_input.take() else {
            return;
        };
        let query = input.query.trim().to_string();
        if query.is_empty() {
            self.status = self.controls();
            return;
        }

        let matches = self.find_matches(input.pane, &query);
        if matches.is_empty() {
            self.search = None;
            self.status = format!("/{query}  —  pattern not found");
            return;
        }

        let sel = self.selection(input.pane).unwrap_or(0);
        let current = matches.iter().position(|&m| m >= sel).unwrap_or(0);
        let target = matches[current];

        self.search = Some(Search {
            pane: input.pane,
            query,
            matches,
            current,
        });
        self.select(input.pane, target);
        self.status = self.match_status();
    }

    fn find_matches(&self, pane: Pane, query: &str) -> Vec<usize> {
        let needle = query.to_lowercase();
        match pane {
            Pane::Disasm => self
                .disasm
                .iter()
                .enumerate()
                .filter(|(_, (addr, bytes, mnem, ops))| {
                    format!("{addr:08x} 0x{addr:x} {bytes} {mnem} {ops}")
                        .to_lowercase()
                        .contains(&needle)
                })
                .map(|(i, _)| i)
                .collect(),
            Pane::Strings => self
                .strings
                .iter()
                .enumerate()
                .filter(|(_, h)| {
                    format!("{:08x} 0x{:x} {}", h.offset, h.offset, h.text)
                        .to_lowercase()
                        .contains(&needle)
                })
                .map(|(i, _)| i)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn cycle_match(&mut self, dir: isize) {
        let Some(search) = self.search.as_mut() else {
            return;
        };
        if search.matches.is_empty() {
            return;
        }
        let len = search.matches.len() as isize;
        search.current = (search.current as isize + dir).rem_euclid(len) as usize;
        let (pane, target) = (search.pane, search.matches[search.current]);
        self.select(pane, target);
        self.status = self.match_status();
    }

    fn search_or_scroll(&mut self, dir: isize) {
        let active = self
            .search
            .as_ref()
            .is_some_and(|s| s.pane == self.focus && !s.matches.is_empty());
        if active {
            self.cycle_match(dir);
        } else {
            self.scroll(dir);
        }
    }

    fn clear_search(&mut self) {
        self.search = None;
        self.status = self.controls();
    }

    fn discard_search_for(&mut self, pane: Pane) {
        if self.search.as_ref().is_some_and(|s| s.pane == pane) {
            self.search = None;
        }
    }

    fn selection(&self, pane: Pane) -> Option<usize> {
        match pane {
            Pane::Disasm => self.disasm_state.selected(),
            Pane::Strings => self.strings_state.selected(),
            _ => None,
        }
    }

    fn select(&mut self, pane: Pane, idx: usize) {
        match pane {
            Pane::Disasm => self.disasm_state.select(Some(idx)),
            Pane::Strings => self.strings_state.select(Some(idx)),
            _ => {}
        }
    }

    fn search_input_status(&self) -> String {
        match &self.search_input {
            Some(input) => format!("/{}_   [Enter] search  [Esc] cancel", input.query),
            None => self.controls(),
        }
    }

    fn match_status(&self) -> String {
        match &self.search {
            Some(s) => format!(
                "/{}  —  match {}/{}   [j] next  [k] prev  [Esc] clear",
                s.query,
                s.current + 1,
                s.matches.len()
            ),
            None => self.controls(),
        }
    }

    fn scroll(&mut self, delta: isize) {
        match self.focus {
            Pane::Disasm => {
                let n = self.disasm.len();
                let sel = step(self.disasm_state.selected(), delta, n);
                self.disasm_state.select(sel);
            }
            Pane::Files => {
                // Once extracted, the pane shows the nested-contents tree;
                // before that, the top-level signatures.
                let n = if self.file_rows.is_empty() {
                    self.findings.as_ref().map_or(0, |f| f.len())
                } else {
                    self.file_rows.len()
                };
                let sel = step(self.files_state.selected(), delta, n);
                self.files_state.select(sel);
            }
            Pane::Strings => {
                let n = self.strings.len();
                let sel = step(self.strings_state.selected(), delta, n);
                self.strings_state.select(sel);
            }
            Pane::Entropy => {} // static chart, nothing to scroll
        }
    }

    /// Recursively extract the firmware and switch the Files pane over to the
    /// tree of nested contents, which the user can then disassemble.
    fn extract(&mut self) {
        self.status = "Extracting recursively…".to_string();
        match extract::extract_recursive(self.filepath.clone()) {
            Ok(tree) if tree.is_empty() => {
                self.status = "Extraction ran, but nothing was found inside.".to_string();
            }
            Ok(tree) => {
                let mut rows = Vec::new();
                flatten_tree(&tree, "", &mut rows);
                self.file_rows = rows;
                self.files_state.select(Some(0));

                self.reload_strings_from_extractions(&tree);

                self.focus = Pane::Files;
                self.status = format!(
                    "Uncovered {} nested item(s) into ./extracted — select one and press [Enter] to disassemble.",
                    self.file_rows.len()
                );
            }
            Err(e) => self.status = format!("Extraction failed: {e}"),
        }
    }

    fn reload_strings_from_extractions(&mut self, tree: &[extract::FileNode]) {
        let mut hits: Vec<StringHit> = Vec::new();

        const COLLECT_CAP: usize = MAX_STRINGS * 10;

        'outer: for path in extract::extracted_file_paths(tree) {
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            let Ok(bytes) = fs::read(&path) else { continue };
            let Ok(found) = metadata::extract_strings(&bytes) else {
                continue;
            };
            for (text, offset) in found {
                let important = metadata::is_important(&text);
                hits.push(StringHit {
                    text,
                    offset,
                    important,
                    source: Some(name.clone()),
                });
                if hits.len() >= COLLECT_CAP {
                    break 'outer;
                }
            }
        }

        hits.sort_by(|a, b| b.important.cmp(&a.important));
        hits.truncate(MAX_STRINGS);

        self.strings = hits;
        self.strings_err = None;
        self.strings_state = ListState::default();
        if !self.strings.is_empty() {
            self.strings_state.select(Some(0));
        }

        self.discard_search_for(Pane::Strings);
    }

    fn disasm_selected_file(&mut self) {
        if self.focus != Pane::Files {
            self.status = "Focus the Files pane (Tab) and extract ([e]) first.".to_string();
            return;
        }
        if self.file_rows.is_empty() {
            self.status = "Nothing extracted yet — press [e] to extract first.".to_string();
            return;
        }

        let Some(row) = self
            .files_state
            .selected()
            .and_then(|i| self.file_rows.get(i))
        else {
            return;
        };

        let (source, offset, size, label) =
            (row.source.clone(), row.offset, row.size, row.label.clone());

        let bytes: Vec<u8> = match &source {
            extract::ByteSource::Firmware => {
                let end = clamp_end(offset, size, self.firmware.len());
                match self.firmware.get(offset..end) {
                    Some(s) => s.to_vec(),
                    None => {
                        self.status = format!("{label}: byte range is outside the firmware");
                        return;
                    }
                }
            }
            extract::ByteSource::File(path) => {
                let data = match fs::read(path) {
                    Ok(d) => d,
                    Err(e) => {
                        self.status = format!("Failed to read {label}: {e}");
                        return;
                    }
                };
                let end = clamp_end(offset, size, data.len());
                match data.get(offset..end) {
                    Some(s) => s.to_vec(),
                    None => {
                        self.status = format!("{label}: byte range is outside its container");
                        return;
                    }
                }
            }
        };

        let name = format!("{label} @ 0x{offset:08x}");
        let (disasm, disasm_err) = match disassemble::disassembler(&bytes) {
            Ok(d) => (d, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        self.disasm = disasm;
        self.disasm_err = disasm_err;
        self.disasm_source = Some((name.clone(), bytes));
        self.disasm_state = TableState::default();
        if !self.disasm.is_empty() {
            self.disasm_state.select(Some(0));
        }
        self.discard_search_for(Pane::Disasm);
        self.focus = Pane::Disasm;
        self.status = if self.disasm.is_empty() {
            format!("Loaded {name} — auto-disasm failed; press [m] to enter metadata manually.")
        } else {
            format!(
                "Disassembled {name} — {} instruction(s).",
                self.disasm.len()
            )
        };
    }

    fn open_disasm_form(&mut self) {
        if self.focus != Pane::Disasm {
            self.status = "Focus the Disassembly pane (Tab) before entering metadata.".to_string();
            return;
        }
        self.disasm_input = Some(DisasmForm::new());
        self.status =
            "Manual metadata: type values · [Tab]/[↑↓] field · [Enter] run · [Esc] cancel"
                .to_string();
    }

    fn handle_form_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.disasm_input = None;
                self.status = self.controls();
            }
            KeyCode::Enter => self.submit_disasm_form(),
            other => {
                if let Some(form) = self.disasm_input.as_mut() {
                    match other {
                        KeyCode::Tab | KeyCode::Down => {
                            form.active = (form.active + 1) % DISASM_FIELDS.len();
                        }
                        KeyCode::Up => {
                            form.active =
                                (form.active + DISASM_FIELDS.len() - 1) % DISASM_FIELDS.len();
                        }
                        KeyCode::Backspace => {
                            form.values[form.active].pop();
                        }
                        KeyCode::Char(c) => form.values[form.active].push(c),
                        _ => {}
                    }
                }
            }
        }
    }

    fn submit_disasm_form(&mut self) {
        let Some(form) = self.disasm_input.as_ref() else {
            return;
        };

        let meta = match Self::parse_form(form) {
            Ok(meta) => meta,
            Err(msg) => {
                if let Some(form) = self.disasm_input.as_mut() {
                    form.error = Some(msg);
                }
                return;
            }
        };

        let data: &[u8] = match &self.disasm_source {
            Some((_, bytes)) => bytes,
            None => &self.firmware,
        };
        match disassemble::disassemble_manual(data, &meta) {
            Ok(disasm) => {
                self.disasm = disasm;
                self.disasm_err = None;
                self.disasm_input = None;
                self.disasm_state = TableState::default();
                self.disasm_state.select(Some(0));
                self.discard_search_for(Pane::Disasm);
                self.status = format!(
                    "Disassembled {} instruction(s) from manual metadata.",
                    self.disasm.len()
                );
            }
            Err(e) => {
                self.disasm_err = Some(e.clone());
                self.disasm_input = None;
                self.status = format!("Disassembly failed: {e}  —  press [m] to try new data");
            }
        }
    }

    fn parse_form(form: &DisasmForm) -> Result<disassemble::ManualMeta, String> {
        let arch = disassemble::parse_arch(&form.values[0])
            .ok_or_else(|| format!("unknown architecture: '{}'", form.values[0].trim()))?;
        let endian = disassemble::parse_endian(&form.values[1])
            .ok_or("endianness must be 'little'/'le' or 'big'/'be'")?;
        let base_addr = disassemble::parse_hex(&form.values[2])
            .ok_or("base address must be a hex number (e.g. 0x80000000)")?;
        let offset = if form.values[3].trim().is_empty() {
            0
        } else {
            disassemble::parse_hex(&form.values[3]).ok_or("offset must be a hex number")? as usize
        };
        Ok(disassemble::ManualMeta {
            arch,
            endian,
            base_addr,
            offset,
        })
    }

    fn render(&mut self, frame: &mut Frame) {
        // Reserve one line at the bottom for status/help, grid takes the rest.
        let [body, status_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(frame.area());

        if self.fullscreen {
            // Only the focused pane, filling the whole body.
            self.render_pane(frame, self.focus, body);
        } else {
            // 2x2 grid.
            let [top, bottom] =
                Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .areas(body);
            let [top_left, top_right] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .areas(top);
            let [bottom_left, bottom_right] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .areas(bottom);

            self.render_pane(frame, Pane::Disasm, top_left);
            self.render_pane(frame, Pane::Files, top_right);
            self.render_pane(frame, Pane::Strings, bottom_left);
            self.render_pane(frame, Pane::Entropy, bottom_right);
        }

        frame.render_widget(
            Paragraph::new(self.status.as_str()).style(Style::new().fg(Color::DarkGray)),
            status_area,
        );
    }

    fn pane_block(&self, title: &str, pane: Pane) -> Block<'static> {
        let mut block = Block::bordered().title(title.to_string());
        if self.focus == pane {
            block = block.border_style(Style::new().fg(Color::Cyan));
        }
        block
    }

    fn render_pane(&mut self, frame: &mut Frame, pane: Pane, area: Rect) {
        match pane {
            Pane::Disasm => self.render_disasm(frame, area),
            Pane::Files => self.render_files(frame, area),
            Pane::Strings => self.render_strings(frame, area),
            Pane::Entropy => self.render_entropy(frame, area),
        }
    }

    fn render_disasm(&mut self, frame: &mut Frame, area: Rect) {
        let title = match &self.disasm_source {
            Some((name, _)) => format!("Disassembly — {name}"),
            None => "Disassembly Listing".to_string(),
        };
        let block = self.pane_block(&title, Pane::Disasm);

        if let Some(form) = &self.disasm_input {
            let inner = block.inner(area);
            frame.render_widget(block, area);
            frame.render_widget(
                Paragraph::new(disasm_form_lines(form)).wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }

        if self.disasm.is_empty() {
            let mut lines = vec![
                Line::from("No disassembly available."),
                Line::from(""),
                Line::from(
                    "Automatic architecture detection failed (no object header / base address).",
                ),
            ];
            if let Some(err) = &self.disasm_err {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("reason: {err}"),
                    Style::new().fg(Color::Red),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press [m] to enter the binary's metadata manually.",
                Style::new().fg(Color::Cyan),
            )));
            let msg = Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false });
            frame.render_widget(msg, area);
            return;
        }

        let rows = self.disasm.iter().map(|(addr, bytes, mnem, ops)| {
            Row::new(vec![
                Cell::from(format!("{addr:08x}")),
                Cell::from(bytes.clone()).style(Style::new().fg(Color::DarkGray)),
                Cell::from(mnem.clone()).style(Style::new().fg(Color::Yellow)),
                Cell::from(ops.clone()),
            ])
        });
        let widths = [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Fill(1),
        ];
        let table = Table::new(rows, widths)
            .block(block)
            // NOTE: on ratatui < 0.29 this method is `highlight_style`.
            .row_highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, area, &mut self.disasm_state);
    }

    fn render_files(&mut self, frame: &mut Frame, area: Rect) {
        if !self.file_rows.is_empty() {
            let title = format!(
                "Nested Contents  ({} items · [Enter] to disassemble)",
                self.file_rows.len()
            );
            let block = self.pane_block(&title, Pane::Files);

            let items: Vec<ListItem> = self
                .file_rows
                .iter()
                .map(|r| ListItem::new(Line::from(r.text.clone())))
                .collect();

            let list = List::new(items)
                .block(block)
                .highlight_style(
                    Style::new()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");
            frame.render_stateful_widget(list, area, &mut self.files_state);
            return;
        }

        let block = self.pane_block("Files Found  ([e] to extract recursively)", Pane::Files);

        let items: Vec<ListItem> = match self.findings.as_ref() {
            Some(sigs) if !sigs.is_empty() => sigs
                .iter()
                .map(|s| {
                    ListItem::new(Line::from(format!(
                        "0x{:08x}  {:<14}  {}",
                        s.offset, s.name, s.description
                    )))
                })
                .collect(),
            _ => vec![ListItem::new("(no signatures found)")],
        };

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, area, &mut self.files_state);
    }

    fn render_strings(&mut self, frame: &mut Frame, area: Rect) {
        let important_count = self.strings.iter().filter(|h| h.important).count();
        let from_extractions = self.strings.iter().any(|h| h.source.is_some());
        let scope = if from_extractions {
            "Strings (extracted files)"
        } else {
            "Strings Found"
        };
        let title = if important_count > 0 {
            format!("{scope}  (★ {important_count} of interest, shown first)")
        } else {
            scope.to_string()
        };
        let block = self.pane_block(&title, Pane::Strings);

        if let Some(err) = &self.strings_err {
            frame.render_widget(
                Paragraph::new(format!("error extracting strings: {err}"))
                    .block(block)
                    .style(Style::new().fg(Color::Red)),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = if self.strings.is_empty() {
            vec![ListItem::new("(no strings found)")]
        } else {
            self.strings
                .iter()
                .map(|hit| {
                    let marker = if hit.important { "★ " } else { "  " };
                    let src = match &hit.source {
                        Some(name) => format!("[{name}] "),
                        None => String::new(),
                    };
                    let item = ListItem::new(Line::from(format!(
                        "{marker}0x{:08x}  {src}{}",
                        hit.offset, hit.text
                    )));
                    if hit.important {
                        item.style(Style::new().fg(Color::Green).add_modifier(Modifier::BOLD))
                    } else {
                        item
                    }
                })
                .collect()
        };

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, area, &mut self.strings_state);
    }

    fn render_entropy(&mut self, frame: &mut Frame, area: Rect) {
        let block = self.pane_block("Entropy Blocks", Pane::Entropy);

        if self.entropy.is_empty() {
            frame.render_widget(Paragraph::new("(no entropy data)").block(block), area);
            return;
        }

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [info_area, chart_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);

        let file_size = self.firmware.len();
        let block_pct = if file_size > 0 {
            ENTROPY_BLOCK_SIZE as f64 / file_size as f64 * 100.0
        } else {
            0.0
        };
        let info = format!(
            "block {} · file {} · {} blocks (1 block ≈ {:.3}% of file)",
            human_size(ENTROPY_BLOCK_SIZE),
            human_size(file_size),
            self.entropy.len(),
            block_pct,
        );
        frame.render_widget(
            Paragraph::new(info).style(Style::new().fg(Color::DarkGray)),
            info_area,
        );

        let bar_width = 6u16;
        let bar_gap = 1u16;
        let n_bars = ((chart_area.width + bar_gap) / (bar_width + bar_gap)).max(1) as usize;

        let bars = downsample_entropy(&self.entropy, n_bars);
        let chart = BarChart::default()
            .data(BarGroup::default().bars(&bars))
            .bar_width(bar_width)
            .bar_gap(bar_gap)
            .max(800); // entropy 0.0..8.0 scaled by 100
        frame.render_widget(chart, chart_area);
    }
}

fn step(current: Option<usize>, delta: isize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1) as usize;
    Some(next)
}

fn disasm_form_lines(form: &DisasmForm) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            "Automatic detection failed — enter metadata manually:",
            Style::new().fg(Color::Cyan),
        )),
        Line::from(""),
    ];

    for (i, label) in DISASM_FIELDS.iter().enumerate() {
        let active = i == form.active;
        let (marker, cursor, label_style) = if active {
            (
                "▶ ",
                "_",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )
        } else {
            ("  ", "", Style::new().fg(Color::Gray))
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker}{label:<20}"), label_style),
            Span::raw(format!("{}{cursor}", form.values[i])),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "arch: x86_64 i386 aarch64 arm mips mips64 ppc64 riscv32 riscv64",
        Style::new().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "endian: little | big     ·     address & offset are hex",
        Style::new().fg(Color::DarkGray),
    )));

    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            Style::new().fg(Color::Red),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "[Tab]/[↑↓] field   [Enter] run   [Esc] cancel",
        Style::new().fg(Color::DarkGray),
    )));

    lines
}

fn flatten_tree(nodes: &[extract::FileNode], prefix: &str, out: &mut Vec<FlatRow>) {
    let count = nodes.len();
    for (i, node) in nodes.iter().enumerate() {
        let last = i + 1 == count;
        let connector = if last { "└─ " } else { "├─ " };
        let text = format!(
            "{prefix}{connector}0x{:08x}  {:<12}  ({})",
            node.offset,
            node.label,
            human_size(node.size),
        );
        out.push(FlatRow {
            text,
            label: node.label.clone(),
            source: node.source.clone(),
            offset: node.offset,
            size: node.size,
        });

        let child_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
        flatten_tree(&node.children, &child_prefix, out);
    }
}

fn clamp_end(offset: usize, size: usize, container_len: usize) -> usize {
    if size == 0 {
        container_len
    } else {
        (offset + size).min(container_len)
    }
}

// human readable size
fn human_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn downsample_entropy(entropy: &[(usize, f64)], n_bars: usize) -> Vec<Bar<'static>> {
    if entropy.is_empty() || n_bars == 0 {
        return Vec::new();
    }
    let n = n_bars.min(entropy.len());
    let chunk = entropy.len().div_ceil(n);

    entropy
        .chunks(chunk)
        .map(|c| {
            let avg = c.iter().map(|(_, e)| *e).sum::<f64>() / c.len() as f64;
            let color = if avg >= 7.0 {
                Color::Red
            } else if avg >= 5.0 {
                Color::Yellow
            } else {
                Color::Blue
            };
            Bar::default()
                .value((avg * 100.0) as u64)
                .label(Line::from(format!("{avg:.1}")))
                .text_value(String::new()) // hide the raw scaled number inside the bar
                .style(Style::new().fg(color))
        })
        .collect()
}
