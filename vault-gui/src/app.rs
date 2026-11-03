use crate::{
    registry::{portable_base, Registry},
    session::{self, Event},
};
use eframe::egui::{self, Color32, RichText};
use std::{path::PathBuf, sync::mpsc, thread::JoinHandle, time::Duration};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Home,
    Unlock,
    Create,
    CreatePassword,
    Decrypt,
    Connection,
    Forget,
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Idle,
    Working,
    Unlocked,
    Stopping,
}
pub(crate) struct App {
    screen: Screen,
    phase: Phase,
    registry: Option<Registry>,
    selected: Option<PathBuf>,
    password: String,
    confirm: String,
    automatic: bool,
    reveal: bool,
    focus_password: bool,
    notice: Option<String>,
    error: Option<String>,
    url: String,
    credential: Zeroizing<String>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    events: Option<mpsc::Receiver<Event>>,
    worker: Option<JoinHandle<()>>,
}
impl Default for App {
    fn default() -> Self {
        let loaded = portable_base().and_then(Registry::load);
        let (registry, error) = match loaded {
            Ok(r) => (Some(r), None),
            Err(e) => (
                None,
                Some(format!(
                    "Could not read vault list: {e}. The list will not be overwritten."
                )),
            ),
        };
        Self {
            screen: Screen::Home,
            phase: Phase::Idle,
            registry,
            selected: None,
            password: String::new(),
            confirm: String::new(),
            automatic: true,
            reveal: false,
            focus_password: false,
            notice: None,
            error,
            url: String::new(),
            credential: Zeroizing::new(String::new()),
            stop: None,
            events: None,
            worker: None,
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.clear_passwords();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.events.take(); // Dropping a queued Ready event also closes its shutdown sender.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl App {
    fn clear_passwords(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
    fn navigate(&mut self, screen: Screen) {
        self.clear_passwords();
        self.error = None;
        self.notice = None;
        self.screen = screen;
        self.focus_password = matches!(
            screen,
            Screen::Unlock | Screen::CreatePassword | Screen::Decrypt
        );
    }
    fn connect(&mut self) {
        self.notice = Some(match crate::platform::request_connection(&self.url) {
            Ok(()) => {
                "Connection requested. OS authentication may appear. Mount status is not verified."
                    .into()
            }
            Err(e) => e,
        });
    }
    fn lock(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
            self.phase = Phase::Stopping;
            self.credential.zeroize();
            self.reveal = false;
        }
    }
    fn start(&mut self) {
        if self.phase != Phase::Idle {
            return;
        }
        let Some(path) = self.selected.clone() else {
            self.error = Some("Choose a vault folder.".into());
            return;
        };
        if self.password.is_empty() {
            self.error = Some("Enter a password.".into());
            return;
        }
        if self.screen == Screen::CreatePassword && self.password != self.confirm {
            self.error = Some("Passwords do not match.".into());
            return;
        }
        let destination = if self.screen == Screen::Decrypt {
            let Some(parent) = rfd::FileDialog::new()
                .set_title("Choose a destination for plaintext files")
                .pick_folder()
            else {
                return;
            };
            Some(parent)
        } else {
            None
        };
        if let Some(old) = self.worker.take() {
            let _ = old.join();
        }
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.confirm.zeroize();
        let (rx, worker) = if let Some(parent) = destination {
            session::export(path, password, parent)
        } else {
            session::spawn(path, password, self.screen == Screen::CreatePassword)
        };
        self.events = Some(rx);
        self.worker = Some(worker);
        self.phase = Phase::Working;
        self.error = None;
        self.notice = None;
    }
    fn poll(&mut self) {
        let mut events = Vec::new();
        let mut disconnected = false;
        if let Some(rx) = &self.events {
            loop {
                match rx.try_recv() {
                    Ok(e) => events.push(e),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        for event in events {
            match event {
                Event::Ready {
                    url,
                    credential,
                    stop,
                } => {
                    self.url = url;
                    self.credential = credential;
                    self.stop = Some(stop);
                    self.phase = Phase::Unlocked;
                    self.screen = Screen::Connection;
                    if let (Some(registry), Some(path)) = (&mut self.registry, &self.selected) {
                        if let Err(e) = registry.add(path) {
                            self.error = Some(format!(
                                "Vault opened, but the list could not be saved: {e}"
                            ));
                        }
                    }
                    if self.automatic {
                        self.connect();
                    }
                }
                Event::Finished(result) => {
                    self.stop = None;
                    self.phase = Phase::Idle;
                    self.credential.zeroize();
                    self.url.clear();
                    self.reveal = false;
                    match result {
                        Ok(()) => {
                            self.screen = Screen::Home;
                            self.notice = Some("Server stopped. Vault locked.".into());
                        }
                        Err(e) => {
                            self.error = Some(e);
                            if self
                                .selected
                                .as_ref()
                                .is_some_and(|p| p.join("vault.dat").is_file())
                            {
                                self.screen = Screen::Unlock;
                            }
                            self.focus_password = true;
                        }
                    }
                }
                Event::Exported(result) => {
                    self.phase = Phase::Idle;
                    match result {
                        Ok(path) => {
                            self.screen = Screen::Home;
                            self.notice = Some(format!(
                                "Decrypted files exported to {}. Encrypted vault preserved.",
                                path.display()
                            ));
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
            }
        }
        if disconnected {
            self.events = None;
            if let Some(worker) = self.worker.take() {
                if worker.join().is_err() {
                    self.error=Some("The vault worker stopped unexpectedly. Reopen the vault before continuing.".into());
                    self.stop = None;
                    self.credential.zeroize();
                    self.phase = Phase::Idle;
                    self.screen = Screen::Home;
                    self.url.clear();
                }
            }
        }
    }
    fn home(&mut self, ui: &mut egui::Ui) {
        ui.heading("Your vaults");
        ui.add_space(16.0);
        let paths = self
            .registry
            .as_ref()
            .map(Registry::paths)
            .unwrap_or_default();
        if paths.is_empty() {
            ui.label("No vaults yet. Create one or open an existing vault.");
        }
        let unlocked = self.phase == Phase::Unlocked;
        for path in paths {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            ui.push_id(&path, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !unlocked,
                            egui::Button::new(RichText::new(name).size(18.0))
                                .selected(self.selected.as_ref() == Some(&path)),
                        )
                        .clicked()
                    {
                        self.selected = Some(path.clone());
                    }
                    ui.add_enabled_ui(!unlocked, |ui| {
                        ui.menu_button("...", |ui| {
                            if ui.button("Remove from list").clicked() {
                                self.selected = Some(path.clone());
                                self.navigate(Screen::Forget);
                                ui.close_menu();
                            }
                        });
                    });
                });
            });
            ui.label(RichText::new(path.display().to_string()).small().weak());
            if !path.join("vault.dat").is_file() {
                ui.label(
                    RichText::new("Unavailable - reconnect the drive or reopen its new location.")
                        .small()
                        .color(Color32::from_rgb(160, 70, 35)),
                );
            }
            ui.add_space(8.0);
        }
        if self.registry.is_none() {
            ui.label("The vault list is unavailable. New list entries cannot be saved.");
        }
        ui.add_space(20.0);
        let unlocked = self.phase == Phase::Unlocked;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.selected.is_some() && !unlocked,
                    egui::Button::new("Unlock"),
                )
                .clicked()
            {
                self.navigate(Screen::Unlock);
            }
            if ui
                .add_enabled(unlocked, egui::Button::new("Lock"))
                .clicked()
            {
                self.lock();
            }
            if ui
                .add_enabled(!unlocked, egui::Button::new("Create"))
                .clicked()
            {
                self.selected = None;
                self.navigate(Screen::Create);
            }
            if ui
                .add_enabled(
                    self.selected.is_some() && !unlocked,
                    egui::Button::new("Decrypt"),
                )
                .clicked()
            {
                self.navigate(Screen::Decrypt);
            }
        });
        ui.add_space(16.0);
        if ui
            .add_enabled(!unlocked, egui::Button::new("Open existing vault…"))
            .clicked()
        {
            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                self.selected = Some(path);
                self.navigate(Screen::Unlock);
            }
        }
        if unlocked && ui.button("Connection details").clicked() {
            self.screen = Screen::Connection;
        }
    }
    fn forget(&mut self, ui: &mut egui::Ui) {
        ui.heading("Remove from list?");
        ui.add_space(12.0);
        if let Some(path) = &self.selected {
            ui.label(path.display().to_string());
        }
        ui.add_space(12.0);
        ui.label(
            "This removes only the saved shortcut. Your vault and its files stay on the drive.",
        );
        ui.add_space(18.0);
        if ui.button("Remove shortcut").clicked() {
            if let (Some(registry), Some(path)) = (&mut self.registry, &self.selected) {
                match registry.remove(path) {
                    Ok(()) => {
                        self.selected = None;
                        self.navigate(Screen::Home);
                    }
                    Err(e) => self.error = Some(format!("Could not update the vault list: {e}")),
                }
            }
        }
    }
    fn form(&mut self, ui: &mut egui::Ui) {
        if self.screen == Screen::Create {
            ui.label(RichText::new("CREATE / 1 OF 2").small().weak());
            ui.heading("Choose a location");
            ui.add_space(16.0);
            ui.label("Keep the vault beside this app to move them together.");
            ui.add_space(16.0);
            if ui.button("Choose folder…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.selected = Some(path);
                }
            }
            if let Some(path) = &self.selected {
                ui.label(path.display().to_string());
            }
            ui.add_space(20.0);
            if ui
                .add_enabled(
                    self.selected.is_some(),
                    egui::Button::new("Continue").min_size(egui::vec2(ui.available_width(), 40.0)),
                )
                .clicked()
            {
                self.navigate(Screen::CreatePassword);
            }
            return;
        }
        let create = self.screen == Screen::CreatePassword;
        ui.label(
            RichText::new(if create {
                "CREATE / 2 OF 2"
            } else if self.screen == Screen::Decrypt {
                "DECRYPT"
            } else {
                "UNLOCK"
            })
            .small()
            .weak(),
        );
        let decrypt = self.screen == Screen::Decrypt;
        ui.heading(if create {
            "Create vault"
        } else if decrypt {
            "Decrypt vault"
        } else {
            "Unlock vault"
        });
        ui.add_space(12.0);
        if let Some(path) = &self.selected {
            ui.label(path.display().to_string());
        }
        ui.add_space(12.0);
        if decrypt {
            ui.label("Export to a new, unencrypted folder. The encrypted vault stays intact.");
            ui.add_space(12.0);
        }
        ui.label("Password");
        let field = ui.add(
            egui::TextEdit::singleline(&mut self.password)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        if self.focus_password {
            field.request_focus();
            self.focus_password = false;
        }
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if create {
            ui.label("Confirm password");
            ui.add(
                egui::TextEdit::singleline(&mut self.confirm)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
        }
        if !decrypt {
            ui.checkbox(&mut self.automatic, "Connect automatically after unlock");
        }
        ui.add_space(16.0);
        if ui
            .add_enabled(
                self.selected.is_some(),
                egui::Button::new(if create {
                    "Create & unlock"
                } else if decrypt {
                    "Choose destination & decrypt"
                } else {
                    "Unlock"
                })
                .min_size(egui::vec2(ui.available_width(), 42.0)),
            )
            .clicked()
            || enter
        {
            self.start();
        }
    }
    fn connection(&mut self, ui: &mut egui::Ui) {
        ui.heading(if self.phase == Phase::Stopping {
            "Locking…"
        } else {
            "Vault unlocked"
        });
        ui.add_space(12.0);
        if let Some(path) = &self.selected {
            ui.label(path.display().to_string());
        }
        ui.add_space(16.0);
        ui.monospace(&self.url);
        ui.label("Username: vault");
        ui.checkbox(&mut self.reveal, "Show temporary connection password");
        if self.reveal {
            ui.monospace(self.credential.as_str());
        }
        ui.add_space(16.0);
        ui.add_enabled_ui(self.phase == Phase::Unlocked, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Connect").clicked() {
                    self.connect();
                }
                if ui.button("Copy address").clicked() {
                    ui.ctx().copy_text(self.url.clone());
                }
            });
        });
        ui.add_space(12.0);
        ui.label("Eject the volume in your file manager before locking. Unsaved client changes cannot be verified.");
        ui.add_space(12.0);
        if ui
            .add_enabled(
                self.phase == Phase::Unlocked,
                egui::Button::new("Lock vault").min_size(egui::vec2(180.0, 42.0)),
            )
            .clicked()
        {
            self.lock();
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(100));
        self.poll();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(248, 247, 244))
                    .inner_margin(22.0),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let label = ui.add(
                        egui::Label::new(RichText::new("VaultDrive").size(18.0))
                            .sense(egui::Sense::drag()),
                    );
                    if label.drag_started() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }
                    let drag = ui.allocate_response(
                        egui::vec2((ui.available_width() - 64.0).max(0.0), 24.0),
                        egui::Sense::drag(),
                    );
                    if drag.drag_started() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }
                    if ui.small_button("-").on_hover_text("Minimize").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                    if ui.small_button("x").on_hover_text("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(10.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let working = self.phase == Phase::Working || self.phase == Phase::Stopping;
                    if self.screen != Screen::Home
                        && ui
                            .add_enabled(!working, egui::Button::new("< Back"))
                            .clicked()
                    {
                        self.navigate(if self.screen == Screen::CreatePassword {
                            Screen::Create
                        } else {
                            Screen::Home
                        });
                    }
                    ui.add_space(12.0);
                    ui.add_enabled_ui(!working, |ui| match self.screen {
                        Screen::Home => self.home(ui),
                        Screen::Connection => self.connection(ui),
                        Screen::Forget => self.forget(ui),
                        _ => self.form(ui),
                    });
                    if working {
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(if self.phase == Phase::Stopping {
                                "Finishing active requests…"
                            } else {
                                "Working…"
                            });
                        });
                    }
                    if let Some(message) = &self.notice {
                        ui.add_space(16.0);
                        ui.label(message);
                    }
                    if let Some(error) = &self.error {
                        ui.add_space(16.0);
                        ui.colored_label(Color32::from_rgb(160, 40, 30), error);
                    }
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("Experimental. Keep a separate backup.")
                            .small()
                            .weak(),
                    );
                });
            });
    }
}
