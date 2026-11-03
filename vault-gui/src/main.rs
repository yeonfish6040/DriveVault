mod app;
mod platform;
mod registry;
mod session;
use app::App;
use eframe::egui::{self, Color32};
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(false)
            .with_inner_size([420.0, 500.0])
            .with_min_inner_size([380.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "VaultDrive",
        options,
        Box::new(|cc| {
            let mut style = (*cc.egui_ctx.style()).clone();
            style.visuals = egui::Visuals::light();
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 8.0);
            style.visuals.selection.bg_fill = Color32::from_rgb(202, 216, 196);
            cc.egui_ctx.set_style(style);
            Ok(Box::new(App::default()))
        }),
    )
}
