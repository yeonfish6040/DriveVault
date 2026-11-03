use anyhow::{bail, Result};
use std::path::PathBuf;
use vault_core::{Entry, Vault};
pub struct Store {
    pub vault: Vault,
    pub dir: PathBuf,
}
impl Store {
    pub fn change(
        &mut self,
        f: impl FnOnce(&mut vault_core::Contents) -> Result<()>,
    ) -> Result<()> {
        let before = self.vault.contents.clone();
        let result = f(&mut self.vault.contents).and_then(|()| self.vault.save(&self.dir));
        if result.is_err() {
            self.vault.contents = before;
        }
        result
    }
}
pub fn parent_exists(v: &vault_core::Contents, path: &str) -> bool {
    let p = path.rsplit_once('/').map(|x| x.0).unwrap_or("");
    p.is_empty() || matches!(v.0.get(p), Some(Entry::Directory))
}
pub fn validate(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.contains('\\')
        || (path != "/" && path.split('/').skip(1).any(str::is_empty))
        || path.split('/').any(|x| x == "." || x == "..")
    {
        bail!("invalid path");
    }
    Ok(())
}

/// Export to a fresh private directory. Failure removes the partial export.
/// The encrypted source remains unchanged; plaintext files are intentional.
pub fn export_plaintext(vault: &Vault, parent: &std::path::Path) -> Result<PathBuf> {
    use std::io::Write;
    vault.contents.validate()?;
    validate_export_names(&vault.contents)?;
    let out = tempfile::Builder::new()
        .prefix("VaultDrive-decrypted-")
        .tempdir_in(parent)?;
    for (path, entry) in &vault.contents.0 {
        let target = out.path().join(path.trim_start_matches('/'));
        match entry {
            Entry::Directory => std::fs::create_dir_all(target)?,
            Entry::File(data) => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(target)?;
                file.write_all(data)?;
                file.sync_all()?;
            }
        }
    }
    Ok(out.keep())
}

/// Windows path syntax must never turn a vault name into an alternate stream
/// or a drive-relative path during cross-platform export.
fn validate_export_names(contents: &vault_core::Contents) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    for path in contents.0.keys() {
        anyhow::ensure!(
            names.insert(path.to_lowercase()),
            "case-colliding filenames cannot be exported portably"
        );
        for component in path.split('/').skip(1) {
            let base = component
                .split('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            let device = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || ["COM", "LPT"].iter().any(|prefix| {
                    base.strip_prefix(prefix)
                        .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
                });
            anyhow::ensure!(
                !device
                    && !component.ends_with(['.', ' '])
                    && !component.contains([':', '*', '?', '"', '<', '>', '|']),
                "filename cannot be safely exported across platforms"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_windows_streams_and_device_names_before_export() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(dir.path(), b"secret").unwrap();
        for name in [
            "/C:escape",
            "/file:stream",
            "/CON.txt",
            "/LPT1",
            "/trailing.",
        ] {
            vault.contents.0.clear();
            vault.contents.0.insert(name.into(), Entry::File(vec![]));
            assert!(export_plaintext(&vault, out.path()).is_err(), "{name}");
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn export_preserves_source_and_creates_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(dir.path(), b"secret").unwrap();
        vault.contents.0.insert("/folder".into(), Entry::Directory);
        vault
            .contents
            .0
            .insert("/folder/test.txt".into(), Entry::File(b"hello".to_vec()));
        vault.save(dir.path()).unwrap();
        let before = std::fs::read(dir.path().join("vault.dat")).unwrap();
        let exported = export_plaintext(&vault, out.path()).unwrap();
        assert_eq!(
            std::fs::read(exported.join("folder/test.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(std::fs::read(dir.path().join("vault.dat")).unwrap(), before);
    }
    #[test]
    fn failed_commit_restores_memory_and_preserves_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path(), b"password").unwrap();
        let before = std::fs::read(dir.path().join("vault.dat")).unwrap();
        let mut store = Store {
            vault,
            dir: dir.path().join("missing"),
        };
        assert!(store
            .change(|c| {
                c.0.insert("/file".into(), Entry::File(b"data".to_vec()));
                Ok(())
            })
            .is_err());
        assert!(store.vault.contents.0.is_empty());
        assert_eq!(std::fs::read(dir.path().join("vault.dat")).unwrap(), before);
    }
    #[test]
    fn rejects_ambiguous_paths() {
        for path in ["/a//b", "/../x", "/a/./b", "/a\\b", "/a/"] {
            assert!(validate(path).is_err(), "{path}");
        }
        assert!(validate("/한글.txt").is_ok());
    }
}
