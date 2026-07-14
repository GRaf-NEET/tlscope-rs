use crate::capture::{
    filter_suggestions::{
        build_filter_suggestions, current_token, filter_parse_state, FilterParseState,
        FilterSuggestion,
    },
    store::FilterIndex,
};

#[derive(Debug, Clone)]
pub struct FilterEditorState {
    pub text: String,
    pub cursor: usize,
    pub horizontal_offset: usize,
    pub suggestions: Vec<FilterSuggestion>,
    pub selected_suggestion: usize,
    pub suggestion_scroll: usize,
    pub parse_state: FilterParseState,
    pub error: Option<String>,
}

impl Default for FilterEditorState {
    fn default() -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            horizontal_offset: 0,
            suggestions: Vec::new(),
            selected_suggestion: 0,
            suggestion_scroll: 0,
            parse_state: FilterParseState::Valid,
            error: None,
        }
    }
}

impl FilterEditorState {
    pub fn reset_to(&mut self, text: &str, index: &FilterIndex) {
        self.text.clear();
        self.text.push_str(text);
        self.cursor = self.text.len();
        self.horizontal_offset = 0;
        self.error = None;
        refresh(self, index);
    }
}

#[derive(Debug, Clone)]
pub struct FilterView {
    pub text: String,
    pub cursor_column: u16,
}

pub fn refresh(editor: &mut FilterEditorState, index: &FilterIndex) {
    editor.cursor = clamp_to_char_boundary(&editor.text, editor.cursor.min(editor.text.len()));
    editor.parse_state = filter_parse_state(&editor.text);
    editor.suggestions = build_filter_suggestions(&editor.text, editor.cursor, index);
    clamp_suggestion_selection(editor);
}

pub fn insert_char(editor: &mut FilterEditorState, index: &FilterIndex, c: char) {
    editor.text.insert(editor.cursor, c);
    editor.cursor += c.len_utf8();
    editor.error = None;
    refresh(editor, index);
}

pub fn backspace(editor: &mut FilterEditorState, index: &FilterIndex) {
    let Some(previous) = previous_boundary(&editor.text, editor.cursor) else {
        return;
    };
    editor.text.replace_range(previous..editor.cursor, "");
    editor.cursor = previous;
    editor.error = None;
    refresh(editor, index);
}

pub fn delete(editor: &mut FilterEditorState, index: &FilterIndex) {
    let Some(next) = next_boundary(&editor.text, editor.cursor) else {
        return;
    };
    editor.text.replace_range(editor.cursor..next, "");
    editor.error = None;
    refresh(editor, index);
}

pub fn move_left(editor: &mut FilterEditorState) {
    if let Some(previous) = previous_boundary(&editor.text, editor.cursor) {
        editor.cursor = previous;
    }
}

pub fn move_right(editor: &mut FilterEditorState) {
    if let Some(next) = next_boundary(&editor.text, editor.cursor) {
        editor.cursor = next;
    }
}

pub fn move_home(editor: &mut FilterEditorState) {
    editor.cursor = 0;
}

pub fn move_end(editor: &mut FilterEditorState) {
    editor.cursor = editor.text.len();
}

pub fn clear(editor: &mut FilterEditorState, index: &FilterIndex) {
    editor.text.clear();
    editor.cursor = 0;
    editor.error = None;
    refresh(editor, index);
}

pub fn delete_current_token(editor: &mut FilterEditorState, index: &FilterIndex) {
    let range = current_token(&editor.text, editor.cursor);
    if range.start == range.end {
        return;
    }
    editor.text.replace_range(range.start..range.end, "");
    editor.cursor = range.start;
    editor.error = None;
    refresh(editor, index);
}

pub fn select_next_suggestion(editor: &mut FilterEditorState) {
    if editor.suggestions.is_empty() {
        return;
    }
    editor.selected_suggestion = (editor.selected_suggestion + 1).min(editor.suggestions.len() - 1);
    keep_selected_visible(editor);
}

pub fn select_previous_suggestion(editor: &mut FilterEditorState) {
    if editor.suggestions.is_empty() {
        return;
    }
    editor.selected_suggestion = editor.selected_suggestion.saturating_sub(1);
    keep_selected_visible(editor);
}

pub fn apply_selected_suggestion(editor: &mut FilterEditorState, index: &FilterIndex) -> bool {
    let Some(suggestion) = editor.suggestions.get(editor.selected_suggestion).cloned() else {
        return false;
    };
    let range = current_token(&editor.text, editor.cursor);
    editor
        .text
        .replace_range(range.start..range.end, &suggestion.replacement);
    editor.cursor = range.start + suggestion.replacement.len();
    editor.error = None;
    refresh(editor, index);
    true
}

pub fn visible_text(text: &str, cursor: usize, width: usize) -> FilterView {
    let width = width.max(1);
    let cursor = clamp_to_char_boundary(text, cursor.min(text.len()));
    let chars = text.chars().collect::<Vec<_>>();
    let cursor_char = text[..cursor].chars().count();
    if chars.len() <= width {
        return FilterView {
            text: text.to_string(),
            cursor_column: cursor_char.min(width.saturating_sub(1)) as u16,
        };
    }

    let start = cursor_char.saturating_sub(width.saturating_sub(1));
    let end = (start + width).min(chars.len());
    let mut visible = chars[start..end].iter().collect::<String>();
    if start > 0 && !visible.is_empty() {
        visible.replace_range(0..1, "<");
    }
    if end < chars.len() && !visible.is_empty() {
        let last = visible
            .char_indices()
            .last()
            .map(|(index, ch)| (index, ch.len_utf8()))
            .unwrap_or((0, 0));
        visible.replace_range(last.0..last.0 + last.1, ">");
    }
    FilterView {
        text: visible,
        cursor_column: cursor_char
            .saturating_sub(start)
            .min(width.saturating_sub(1)) as u16,
    }
}

fn clamp_suggestion_selection(editor: &mut FilterEditorState) {
    if editor.suggestions.is_empty() {
        editor.selected_suggestion = 0;
        editor.suggestion_scroll = 0;
        return;
    }
    editor.selected_suggestion = editor.selected_suggestion.min(editor.suggestions.len() - 1);
    keep_selected_visible(editor);
}

fn keep_selected_visible(editor: &mut FilterEditorState) {
    const MAX_VISIBLE: usize = 7;
    if editor.selected_suggestion < editor.suggestion_scroll {
        editor.suggestion_scroll = editor.selected_suggestion;
    } else if editor.selected_suggestion >= editor.suggestion_scroll + MAX_VISIBLE {
        editor.suggestion_scroll = editor.selected_suggestion + 1 - MAX_VISIBLE;
    }
}

fn previous_boundary(text: &str, cursor: usize) -> Option<usize> {
    if cursor == 0 {
        return None;
    }
    text[..cursor].char_indices().last().map(|(index, _)| index)
}

fn next_boundary(text: &str, cursor: usize) -> Option<usize> {
    if cursor >= text.len() {
        return None;
    }
    text[cursor..]
        .char_indices()
        .nth(1)
        .map(|(index, _)| cursor + index)
        .or(Some(text.len()))
}

fn clamp_to_char_boundary(text: &str, mut cursor: usize) -> usize {
    while cursor > 0 && !text.is_char_boundary(cursor) {
        cursor -= 1;
    }
    cursor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_selected_suggestion_to_current_token() {
        let mut editor = FilterEditorState::default();
        editor.text = "method:P".to_string();
        editor.cursor = editor.text.len();
        refresh(&mut editor, &FilterIndex::default());
        editor.selected_suggestion = editor
            .suggestions
            .iter()
            .position(|suggestion| suggestion.replacement == "method:POST")
            .unwrap();
        assert!(apply_selected_suggestion(
            &mut editor,
            &FilterIndex::default()
        ));
        assert_eq!(editor.text, "method:POST");
    }
}
