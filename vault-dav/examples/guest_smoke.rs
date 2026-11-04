//! Disposable guest-mount fixture; never opens a user vault.
use vault_core::{Entry, Vault};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut vault = Vault::create(dir.path(), b"disposable-test-only")?;
    vault.contents.0.insert(
        "/hello.txt".into(),
        Entry::File(b"VaultDrive guest smoke test\n".to_vec()),
    );
    vault.save(dir.path())?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let token = "a".repeat(48);
    println!(
        "http://127.0.0.1:{}/{token}/",
        listener.local_addr()?.port()
    );
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(());
    });
    vault_dav::serve_guest(
        vault_fs::Store {
            vault,
            dir: dir.path().to_path_buf(),
        },
        &token,
        listener,
        shutdown,
    )
    .await
}
