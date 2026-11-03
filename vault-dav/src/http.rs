use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use vault_core::Entry;
use vault_fs::{parent_exists, validate, Store};
#[derive(Clone)]
pub(crate) struct App {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) authorization: String,
    pub(crate) admission: Arc<tokio::sync::Semaphore>,
}
fn response(status: StatusCode, body: impl Into<Body>) -> Response {
    Response::builder()
        .status(status)
        .body(body.into())
        .unwrap()
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub(crate) async fn handle(State(app): State<App>, req: Request) -> Response {
    if req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(app.authorization.as_str())
    {
        let mut r = response(StatusCode::UNAUTHORIZED, "Authentication required");
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"VaultDrive\""),
        );
        return r;
    }
    let Ok(_permit) = app.admission.clone().try_acquire_owned() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault is busy; retry shortly",
        );
    };
    if req.headers().contains_key(header::ORIGIN) {
        return response(
            StatusCode::FORBIDDEN,
            "browser-origin requests are not supported",
        );
    }
    let method = req.method().as_str().to_owned();
    let path = match decode_path(req.uri().path()) {
        Ok(p) => p,
        Err(_) => return response(StatusCode::BAD_REQUEST, "invalid path"),
    };
    let headers = req.headers().clone();
    if method == "PUT" && headers.contains_key(header::CONTENT_RANGE) {
        return response(
            StatusCode::BAD_REQUEST,
            "partial PUT is unsupported; send the complete file",
        );
    }
    let destination = if method == "MOVE" {
        let target = headers
            .get("destination")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<axum::http::Uri>().ok());
        match target {
            Some(uri)
                if uri.query().is_none()
                    && (uri.authority().is_none()
                        || (uri.scheme_str() == Some("http")
                            && uri.authority().map(|a| a.as_str())
                                == headers.get(header::HOST).and_then(|v| v.to_str().ok()))) =>
            {
                match decode_path(uri.path()) {
                    Ok(p) => Some(p),
                    Err(_) => return response(StatusCode::BAD_REQUEST, "invalid destination"),
                }
            }
            _ => {
                return response(
                    StatusCode::BAD_REQUEST,
                    "destination must be on this server",
                )
            }
        }
    } else {
        None
    };
    if headers
        .get("overwrite")
        .is_some_and(|v| v != "T" && v != "F")
    {
        return response(StatusCode::BAD_REQUEST, "invalid Overwrite header");
    }
    let depth = req
        .headers()
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("infinity")
        .to_owned();
    let body = if method == "PUT" {
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            to_bytes(req.into_body(), 32 * 1024 * 1024),
        )
        .await
        {
            Ok(Ok(b)) => b.to_vec(),
            Ok(Err(_)) => return response(StatusCode::PAYLOAD_TOO_LARGE, "too large"),
            Err(_) => return response(StatusCode::REQUEST_TIMEOUT, "upload timed out"),
        }
    } else {
        Vec::new()
    };
    match tokio::task::spawn_blocking(move || {
        dispatch(app, method, path, depth, body, headers, destination)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, "request worker failed"),
    }
}
fn dispatch(
    app: App,
    method: String,
    path: String,
    depth: String,
    body: Vec<u8>,
    headers: axum::http::HeaderMap,
    destination: Option<String>,
) -> Response {
    let mut s = match app.store.lock() {
        Ok(s) => s,
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "vault state unavailable"),
    };
    let current = s.vault.contents.0.get(&path);
    let tag = current.and_then(|e| {
        if let Entry::File(bytes) = e {
            Some(etag(bytes))
        } else {
            None
        }
    });
    if let Some(value) = headers.get(header::IF_MATCH) {
        let matches = value.to_str().ok().is_some_and(|v| {
            if v.trim() == "*" {
                current.is_some()
            } else {
                v.split(',').any(|t| tag.as_deref() == Some(t.trim()))
            }
        });
        if !matches {
            return response(
                StatusCode::PRECONDITION_FAILED,
                "file changed; reload before saving",
            );
        }
    }
    if let Some(value) = headers.get(header::IF_NONE_MATCH) {
        let matches = value.to_str().ok().is_some_and(|v| {
            if v.trim() == "*" {
                current.is_some()
            } else {
                v.split(',')
                    .any(|t| tag.as_deref() == Some(t.trim().trim_start_matches("W/")))
            }
        });
        if matches {
            return response(
                if method == "GET" || method == "HEAD" {
                    StatusCode::NOT_MODIFIED
                } else {
                    StatusCode::PRECONDITION_FAILED
                },
                "",
            );
        }
    }
    // Never silently ignore DAV lock preconditions that this server cannot evaluate.
    if headers.contains_key("if") {
        return response(
            StatusCode::PRECONDITION_FAILED,
            "DAV lock conditions unsupported",
        );
    }
    if method == "PUT" {
        let existed = s.vault.contents.0.contains_key(&path);
        if path == "/"
            || !parent_exists(&s.vault.contents, &path)
            || matches!(s.vault.contents.0.get(&path), Some(Entry::Directory))
        {
            return response(StatusCode::CONFLICT, "invalid target");
        }
        return match s.change(|v| {
            v.0.insert(path, Entry::File(body));
            Ok(())
        }) {
            Ok(()) => response(
                if existed {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::CREATED
                },
                "",
            ),
            Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, "save failed"),
        };
    }
    match method.as_str() {
        "OPTIONS" => {
            let mut r = response(StatusCode::OK, "");
            r.headers_mut().insert("dav", HeaderValue::from_static("1"));
            r.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, PROPFIND"),
            );
            r
        }
        "GET" | "HEAD" => match s.vault.contents.0.get(&path) {
            Some(Entry::File(data)) => {
                let mut r = response(
                    StatusCode::OK,
                    if method == "HEAD" {
                        Vec::new()
                    } else {
                        data.clone()
                    },
                );
                r.headers_mut()
                    .insert(header::ETAG, HeaderValue::from_str(&etag(data)).unwrap());
                r.headers_mut().insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&data.len().to_string()).unwrap(),
                );
                r
            }
            _ => response(StatusCode::NOT_FOUND, "not found"),
        },
        "MOVE" => {
            let destination = destination.expect("validated MOVE destination");
            if path == "/"
                || destination == "/"
                || path == destination
                || destination.starts_with(&format!("{path}/"))
                || path.starts_with(&format!("{destination}/"))
            {
                return response(StatusCode::FORBIDDEN, "invalid move relationship");
            }
            if !s.vault.contents.0.contains_key(&path) {
                return response(StatusCode::NOT_FOUND, "source missing");
            }
            if !parent_exists(&s.vault.contents, &destination) {
                return response(StatusCode::CONFLICT, "destination parent missing");
            }
            let existed = s.vault.contents.0.contains_key(&destination);
            if existed && headers.get("overwrite").is_some_and(|v| v == "F") {
                return response(StatusCode::PRECONDITION_FAILED, "destination exists");
            }
            let result = s.change(|v| {
                let prefix = format!("{path}/");
                let dest_prefix = format!("{destination}/");
                let keys: Vec<_> =
                    v.0.keys()
                        .filter(|k| *k == &path || k.starts_with(&prefix))
                        .cloned()
                        .collect();
                v.0.retain(|k, _| k != &destination && !k.starts_with(&dest_prefix));
                for key in keys {
                    let entry =
                        v.0.remove(&key)
                            .expect("key was collected under exclusive store lock");
                    v.0.insert(format!("{destination}{}", &key[path.len()..]), entry);
                }
                Ok(())
            });
            match result {
                Ok(()) => response(
                    if existed {
                        StatusCode::NO_CONTENT
                    } else {
                        StatusCode::CREATED
                    },
                    "",
                ),
                Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, "move save failed"),
            }
        }
        "MKCOL" => {
            if path == "/" || s.vault.contents.0.contains_key(&path) {
                return response(StatusCode::METHOD_NOT_ALLOWED, "exists");
            }
            if !parent_exists(&s.vault.contents, &path) {
                return response(StatusCode::CONFLICT, "missing parent");
            }
            match s.change(|v| {
                v.0.insert(path, Entry::Directory);
                Ok(())
            }) {
                Ok(()) => response(StatusCode::CREATED, ""),
                Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, "save failed"),
            }
        }
        "DELETE" => {
            if path == "/" || !s.vault.contents.0.contains_key(&path) {
                return response(StatusCode::NOT_FOUND, "not found");
            }
            let prefix = format!("{path}/");
            match s.change(|v| {
                v.0.retain(|k, _| k != &path && !k.starts_with(&prefix));
                Ok(())
            }) {
                Ok(()) => response(StatusCode::NO_CONTENT, ""),
                Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, "save failed"),
            }
        }
        "PROPFIND" => {
            if depth != "0" && depth != "1" {
                return response(StatusCode::FORBIDDEN, "depth must be 0 or 1");
            }
            if path != "/" && !s.vault.contents.0.contains_key(&path) {
                return response(StatusCode::NOT_FOUND, "not found");
            }
            let mut entries = vec![(
                path.clone(),
                s.vault.contents.0.get(&path).unwrap_or(&Entry::Directory),
            )];
            if depth == "1" {
                let prefix = if path == "/" {
                    "/".to_owned()
                } else {
                    format!("{path}/")
                };
                for (k, v) in &s.vault.contents.0 {
                    if let Some(rest) = k.strip_prefix(&prefix) {
                        if !rest.is_empty() && !rest.contains('/') {
                            entries.push((k.clone(), v));
                        }
                    }
                }
            }
            let mut out = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
            );
            for (p, e) in entries {
                let (kind, size) = match e {
                    Entry::Directory => ("<d:collection/>", 0),
                    Entry::File(b) => ("", b.len()),
                };
                let href =
                    percent_encoding::utf8_percent_encode(&p, percent_encoding::NON_ALPHANUMERIC)
                        .to_string()
                        .replace("%2F", "/");
                let href = if matches!(e, Entry::Directory) && !href.ends_with('/') {
                    format!("{href}/")
                } else {
                    href
                };
                out.push_str(&format!("<d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype>{kind}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",xml(&href)));
            }
            out.push_str("</d:multistatus>");
            let mut r = response(StatusCode::MULTI_STATUS, out);
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            );
            r
        }
        _ => response(StatusCode::METHOD_NOT_ALLOWED, "unsupported"),
    }
}

fn decode_path(raw: &str) -> Result<String, ()> {
    let decoded = percent_decode_str(raw).decode_utf8().map_err(|_| ())?;
    let p = decoded.trim_end_matches('/');
    let p = if p.is_empty() { "/" } else { p };
    validate(p).map_err(|_| ())?;
    Ok(p.to_owned())
}
fn etag(data: &[u8]) -> String {
    format!("\"{:x}\"", Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    struct Fixture {
        _dir: tempfile::TempDir,
        app: App,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vault = vault_core::Vault::create(dir.path(), b"secret").unwrap();
            let app = App {
                admission: Arc::new(tokio::sync::Semaphore::new(4)),
                store: Arc::new(Mutex::new(Store {
                    vault,
                    dir: dir.path().to_path_buf(),
                })),
                authorization: format!("Basic {}", STANDARD.encode("vault:test")),
            };
            Self { _dir: dir, app }
        }
        async fn call(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: &str,
        ) -> Response {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, &self.app.authorization)
                .header(header::HOST, "127.0.0.1:49152");
            for (key, value) in headers {
                req = req.header(*key, *value);
            }
            handle(
                State(self.app.clone()),
                req.body(Body::from(body.to_owned())).unwrap(),
            )
            .await
        }
    }
    #[tokio::test]
    async fn partial_put_is_rejected_without_truncating_file() {
        let f = Fixture::new();
        f.call("PUT", "/file", &[], "original").await;
        assert_eq!(
            f.call("PUT", "/file", &[("content-range", "bytes 0-2/8")], "bad")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let read = f.call("GET", "/file", &[], "").await;
        assert_eq!(
            to_bytes(read.into_body(), 100).await.unwrap().as_ref(),
            b"original"
        );
    }
    #[tokio::test]
    async fn overload_returns_retryable_error_instead_of_queueing_uploads() {
        let f = Fixture::new();
        let _all = f.app.admission.acquire_many(4).await.unwrap();
        assert_eq!(
            f.call("PUT", "/file", &[], "data").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn stale_update_and_create_only_put_preserve_current_data() {
        let f = Fixture::new();
        assert_eq!(
            f.call("PUT", "/file", &[], "v1").await.status(),
            StatusCode::CREATED
        );
        let read = f.call("GET", "/file", &[], "").await;
        let tag = read.headers()[header::ETAG].to_str().unwrap().to_owned();
        assert_eq!(
            f.call("PUT", "/file", &[("if-match", &tag)], "v2")
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            f.call("PUT", "/file", &[("if-match", &tag)], "stale")
                .await
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            f.call("PUT", "/file", &[("if-none-match", "*")], "clobber")
                .await
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
        let read = f.call("GET", "/file", &[], "").await;
        assert_eq!(
            to_bytes(read.into_body(), 100).await.unwrap().as_ref(),
            b"v2"
        );
    }
    #[tokio::test]
    async fn move_collection_is_atomic_and_prevents_cycles_or_implicit_overwrite() {
        let f = Fixture::new();
        f.call("MKCOL", "/folder", &[], "").await;
        f.call("PUT", "/folder/file", &[], "data").await;
        assert_eq!(
            f.call("MOVE", "/folder", &[("destination", "/folder/child")], "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.call(
                "MOVE",
                "/folder",
                &[("destination", "http://127.0.0.1:49152/new")],
                ""
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            f.call("GET", "/folder/file", &[], "").await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            f.call("GET", "/new/file", &[], "").await.status(),
            StatusCode::OK
        );
        f.call("PUT", "/other", &[], "keep").await;
        assert_eq!(
            f.call(
                "MOVE",
                "/new/file",
                &[("destination", "/other"), ("overwrite", "F")],
                ""
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            f.call(
                "MOVE",
                "/new/file",
                &[("destination", "http://example.com/file")],
                ""
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.call("MOVE", "/new/file", &[("destination", "/missing/file")], "")
                .await
                .status(),
            StatusCode::CONFLICT
        );
    }
    #[tokio::test]
    async fn move_save_failure_restores_entire_tree() {
        let f = Fixture::new();
        f.call("PUT", "/source", &[], "keep").await;
        f.app.store.lock().unwrap().dir = f._dir.path().join("missing");
        assert_eq!(
            f.call("MOVE", "/source", &[("destination", "/target")], "")
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            f.call("GET", "/source", &[], "").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            f.call("GET", "/target", &[], "").await.status(),
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn browser_origin_and_unsupported_lock_conditions_fail_closed() {
        let f = Fixture::new();
        assert_eq!(
            f.call("PUT", "/file", &[("origin", "http://evil.example")], "data")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.call(
                "PUT",
                "/file",
                &[("if", "(<opaquelocktoken:unknown>)")],
                "data"
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            f.call("GET", "/file", &[], "").await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
