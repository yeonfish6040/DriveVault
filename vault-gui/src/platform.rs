//! Best-effort native connection request. This is not proof of a mounted volume.
use std::process::{Command, Stdio};

pub(crate) fn request_connection(http_url: &str) -> Result<(), String> {
    let (port, path) = parse_address(http_url)?;
    let mut command = connector(port, &path);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            format!(
                "Could not open the file manager: {e}. Connect manually with the address below."
            )
        })?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
fn parse_address(url: &str) -> Result<(u16, String), String> {
    let rest = url
        .strip_prefix("http://127.0.0.1:")
        .ok_or("invalid loopback address")?;
    let (port, path) = rest.split_once('/').ok_or("invalid loopback address")?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or("invalid loopback port")?;
    if !(path.is_empty()
        || path.len() == 49
            && path.ends_with('/')
            && path[..48].bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("invalid session path".into());
    }
    Ok((port, path.to_owned()))
}
#[cfg(target_os = "macos")]
fn connector(port: u16, path: &str) -> Command {
    let mut command = Command::new("/usr/bin/open");
    command.arg(format!("dav://127.0.0.1:{port}/{path}"));
    command
}
#[cfg(target_os = "windows")]
fn connector(port: u16, path: &str) -> Command {
    let mut command = Command::new("explorer.exe");
    command.arg(format!(
        r"\\127.0.0.1@{port}\DavWWWRoot\{}",
        path.replace('/', "\\")
    ));
    command
}
#[cfg(target_os = "linux")]
fn connector(port: u16, path: &str) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(format!("dav://127.0.0.1:{port}/{path}"));
    command
}
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
compile_error!("VaultDrive desktop currently targets macOS, Windows and Linux");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_non_loopback_and_malformed_addresses() {
        for url in [
            "https://example.com/",
            "http://127.0.0.1:0/",
            "http://127.0.0.1:80/;rm",
            "http://127.0.0.1:65536/",
        ] {
            assert!(request_connection(url).is_err());
        }
    }
    #[test]
    fn connection_request_contains_no_password() {
        let cmd = connector(49152, "");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args.len(), 1);
        assert!(args[0].to_string_lossy().contains("49152"));
        assert!(!args[0].to_string_lossy().contains("password"));
    }
}
