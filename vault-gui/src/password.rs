//! Reject unsupported input as a whole; never silently change a password.
pub(crate) fn allowed(text: &str) -> bool {
    text.bytes().all(|b| (b' '..=b'~').contains(&b))
}
pub(crate) fn allowed_event(event: &eframe::egui::Event) -> bool {
    use eframe::egui::Event;
    match event {
        Event::Text(text) | Event::Paste(text) => allowed(text),
        Event::Ime(_) => false,
        _ => true,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui::{Event, ImeEvent};
    #[test]
    fn rejects_korean_and_mixed_pastes_without_trimming() {
        assert!(allowed("English123 !@#$%^&*()"));
        for text in ["한글", "abc한글123", "한", "a\nb", "é"] {
            assert!(!allowed(text));
            assert!(!allowed_event(&Event::Paste(text.into())));
        }
    }
    #[test]
    fn blocks_ime_composition_but_preserves_navigation() {
        assert!(!allowed_event(&Event::Ime(ImeEvent::Preedit("ㅎ".into()))));
        assert!(!allowed_event(&Event::Ime(ImeEvent::Commit("한".into()))));
        assert!(allowed_event(&Event::Copy));
    }
}
