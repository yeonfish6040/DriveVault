use rand::RngCore;
use std::{path::PathBuf, sync::mpsc};
use zeroize::{Zeroize, Zeroizing};
pub(crate) enum Event {
    Ready {
        url: String,
        credential: Zeroizing<String>,
        stop: tokio::sync::oneshot::Sender<()>,
    },
    Finished(Result<(), String>),
    Exported(Result<PathBuf, String>),
}

pub(crate) fn spawn(
    path: PathBuf,
    password: Zeroizing<String>,
    create: bool,
) -> (mpsc::Receiver<Event>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = (|| -> anyhow::Result<()> {
            let vault = if create {
                vault_core::Vault::create(&path, password.as_bytes())?
            } else {
                vault_core::Vault::open(&path, password.as_bytes())?
            };
            drop(password);
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let listener =
                    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let url = format!("http://127.0.0.1:{}/", listener.local_addr()?.port());
                let mut random = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut random);
                let credential = Zeroizing::new(
                    random
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                );
                random.zeroize();
                let (stop, shutdown) = tokio::sync::oneshot::channel();
                tx.send(Event::Ready {
                    url,
                    credential: credential.clone(),
                    stop,
                })?;
                vault_dav::serve_controlled(
                    vault_fs::Store { vault, dir: path },
                    &credential,
                    listener,
                    shutdown,
                )
                .await
            })
        })();
        let _ = tx.send(Event::Finished(result.map_err(|e| e.to_string())));
    });
    (rx, thread)
}

pub(crate) fn export(
    path: PathBuf,
    password: Zeroizing<String>,
    parent: PathBuf,
) -> (mpsc::Receiver<Event>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = (|| -> anyhow::Result<PathBuf> {
            let vault = vault_core::Vault::open(&path, password.as_bytes())?;
            drop(password);
            vault_fs::export_plaintext(&vault, &parent)
        })();
        let _ = tx.send(Event::Exported(result.map_err(|e| e.to_string())));
    });
    (rx, thread)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closing_during_startup_releases_vault_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (rx, worker) = spawn(
            dir.path().to_path_buf(),
            Zeroizing::new("secret".into()),
            true,
        );
        drop(rx);
        worker.join().unwrap();
        assert!(vault_core::Vault::open(dir.path(), b"secret").is_ok());
    }
    #[test]
    fn export_worker_reports_invalid_password() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        drop(vault_core::Vault::create(dir.path(), b"secret").unwrap());
        let (rx, worker) = export(
            dir.path().to_path_buf(),
            Zeroizing::new("wrong".into()),
            out.path().to_path_buf(),
        );
        assert!(matches!(rx.recv().unwrap(), Event::Exported(Err(_))));
        worker.join().unwrap();
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}
