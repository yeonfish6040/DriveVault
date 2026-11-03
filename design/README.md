# VaultDrive desktop design

Created using `/Users/yeonfish/IdeaProjects/design-system-studio/dss`.
Child `gen-8fd2c3e90e73`, version 1, parent `07` (Cursor, version 14).
The reference is a draft and is not certified as a faithful reconstruction. This app is a proposed native adaptation of its warm neutral palette, compact left-aligned copy and restrained surfaces, not a replica. Exported fonts/assets are reference material only and are not bundled into the native executable.

Native implementation: `vault-gui/src/app.rs`. Uses system-independent egui default typeface, warm canvas (#f8f7f4), compact controls and a compact 420×500 borderless window, a vault-list home, and separate task steps. Create advances from folder selection to password setup; forms replace the home instead of expanding below menus. The default UI language is English to avoid missing CJK glyphs in the bundled default font. Path text remains supported only to the extent the font provides glyphs.

States: no vault, selection, create/confirm, deriving key (disabled controls), unlocked, stopping (wait for in-flight HTTP requests), error. Passwords are masked and moved off the UI thread before key derivation. Temporary connection credentials require explicit reveal and are cleared after stop. No vault password is persisted. Server readiness is reported only after loopback bind succeeds. Lock status is reported after the server future has finished; OS mount status is not inferred.

The window does not automatically mount or unmount network volumes. Follow the on-screen eject instruction. Closing the process ends service but cannot guarantee external client buffers were flushed. Core snapshot-size, platform and compatibility limitations still apply.

The custom header provides drag, minimize and close controls. Content scrolls when needed; minimum window size is 380×420. Back clears password inputs.
