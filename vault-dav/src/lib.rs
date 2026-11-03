mod http;
use axum::{routing::any, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use http::{handle, App};
use std::sync::{Arc, Mutex};
use vault_fs::Store;
pub async fn serve(store: Store, user: &str, password: &str, port: u16) -> anyhow::Result<()> {
    let app = App {
        admission: Arc::new(tokio::sync::Semaphore::new(4)),
        store: Arc::new(Mutex::new(store)),
        authorization: format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))),
    };
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    println!(
        "WebDAV: http://127.0.0.1:{}/ (user: {})",
        listener.local_addr()?.port(),
        user
    );
    axum::serve(
        listener,
        Router::new().fallback(any(handle)).with_state(app),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

/// Controlled server for the desktop app. Caller owns listener and shutdown lifecycle.
pub async fn serve_controlled(
    store: Store,
    password: &str,
    listener: tokio::net::TcpListener,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "loopback listener required"
    );
    let app = App {
        admission: Arc::new(tokio::sync::Semaphore::new(4)),
        store: Arc::new(Mutex::new(store)),
        authorization: format!("Basic {}", STANDARD.encode(format!("vault:{password}"))),
    };
    use std::future::IntoFuture;
    let (draining, drained) = tokio::sync::oneshot::channel();
    let server = axum::serve(
        listener,
        Router::new().fallback(any(handle)).with_state(app),
    )
    .with_graceful_shutdown(async {
        let _ = shutdown.await;
        let _ = draining.send(());
    })
    .into_future();
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result?,
        _ = drained => {
            tokio::time::timeout(std::time::Duration::from_secs(5), &mut server)
                .await.map_err(|_| anyhow::anyhow!("client drain timed out; server closed, check client saves"))??;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::{Request, State},
        http::{header, StatusCode},
        response::Response,
    };
    use vault_core::Vault;

    #[tokio::test]
    async fn real_http_write_survives_shutdown_and_unlock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path(), b"secret").unwrap();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let store = Store {
            vault,
            dir: dir.path().to_path_buf(),
        };
        let server =
            tokio::spawn(
                async move { serve_controlled(store, "temporary", listener, shutdown).await },
            );
        async fn request(
            addr: std::net::SocketAddr,
            method: &str,
            body: &str,
            auth: bool,
        ) -> String {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let auth = if auth {
                format!(
                    "Authorization: Basic {}\r\n",
                    STANDARD.encode("vault:temporary")
                )
            } else {
                String::new()
            };
            let request=format!("{method} /file HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",body.len());
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            String::from_utf8(response).unwrap()
        }
        assert!(request(addr, "GET", "", false)
            .await
            .starts_with("HTTP/1.1 401"));
        assert!(request(addr, "PUT", "persist me", true)
            .await
            .starts_with("HTTP/1.1 201"));
        assert!(request(addr, "GET", "", true).await.ends_with("persist me"));
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        let reopened = Vault::open(dir.path(), b"secret").unwrap();
        assert_eq!(
            reopened.contents.0.get("/file"),
            Some(&vault_core::Entry::File(b"persist me".to_vec()))
        );
    }

    #[tokio::test]
    async fn controlled_shutdown_closes_listener() {
        let dir = std::env::temp_dir().join(format!("vault-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = Vault::create(&dir, b"test password").unwrap();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_controlled(Store { vault, dir }, "token", listener, shutdown).await
        });
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
        std::fs::remove_dir_all(
            std::env::temp_dir().join(format!("vault-stop-{}", std::process::id())),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn authenticated_file_lifecycle() {
        let dir = std::env::temp_dir().join(format!("vault-dav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = Vault::create(&dir, b"test password").unwrap();
        let app = App {
            admission: Arc::new(tokio::sync::Semaphore::new(4)),
            store: Arc::new(Mutex::new(Store {
                vault,
                dir: dir.clone(),
            })),
            authorization: format!("Basic {}", STANDARD.encode("vault:temporary")),
        };
        async fn call(
            app: &App,
            method: &str,
            path: &str,
            body: &str,
            authorized: bool,
        ) -> Response {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header("depth", "1");
            if authorized {
                req = req.header(header::AUTHORIZATION, &app.authorization);
            }
            handle(
                State(app.clone()),
                req.body(Body::from(body.to_owned())).unwrap(),
            )
            .await
        }
        assert_eq!(
            call(&app, "GET", "/", "", false).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "MKCOL", "/folder", "", true).await.status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(&app, "PUT", "/folder/file.txt", "hello", true)
                .await
                .status(),
            StatusCode::CREATED
        );
        let read = call(&app, "GET", "/folder/file.txt", "", true).await;
        assert_eq!(
            to_bytes(read.into_body(), 100).await.unwrap().as_ref(),
            b"hello"
        );
        assert_eq!(
            call(&app, "PROPFIND", "/folder", "", true).await.status(),
            StatusCode::MULTI_STATUS
        );
        assert_eq!(
            call(&app, "DELETE", "/folder", "", true).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&app, "GET", "/folder/file.txt", "", true)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        drop(app);
        assert!(Vault::open(&dir, b"test password")
            .unwrap()
            .contents
            .0
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
