//! Portable, password-free vault registry, stored beside the distributed app.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Default, Serialize, Deserialize)]
struct Record {
    vaults: Vec<PathBuf>,
}
pub(crate) struct Registry {
    pub base: PathBuf,
    record: Record,
}
impl Registry {
    pub fn load(base: PathBuf) -> anyhow::Result<Self> {
        let base = std::fs::canonicalize(base)?;
        let file = base.join("vaults.json");
        let record = if file.exists() {
            serde_json::from_slice(&std::fs::read(file)?)?
        } else {
            Record::default()
        };
        Ok(Self { base, record })
    }
    pub fn paths(&self) -> Vec<PathBuf> {
        self.record
            .vaults
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    self.base.join(p)
                }
            })
            .collect()
    }
    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        let path = std::fs::canonicalize(path)?;
        let stored = path.strip_prefix(&self.base).unwrap_or(&path).to_path_buf();
        self.update(|paths| {
            if !paths.contains(&stored) {
                paths.push(stored);
            }
        })
    }
    pub fn remove(&mut self, path: &Path) -> anyhow::Result<()> {
        let stored = path.strip_prefix(&self.base).unwrap_or(path).to_path_buf();
        self.update(|paths| paths.retain(|p| p != &stored))
    }
    fn update(&mut self, apply: impl FnOnce(&mut Vec<PathBuf>)) -> anyhow::Result<()> {
        use std::io::Write;
        // Reload under a short-lived lock so multiple portable apps cannot lose list edits.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.base.join("vaults.lock"))?;
        lock.try_lock()
            .map_err(|e| anyhow::anyhow!("vault list is busy: {e}"))?;
        let mut current = Self::load(self.base.clone())?.record;
        apply(&mut current.vaults);
        let data = serde_json::to_vec_pretty(&current)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.base)?;
        file.write_all(&data)?;
        file.as_file().sync_all()?;
        file.persist(self.base.join("vaults.json"))?;
        self.record = current;
        Ok(())
    }
}
pub(crate) fn portable_base() -> anyhow::Result<PathBuf> {
    if let Some(base) = std::env::var_os("VAULTDRIVE_PORTABLE_HOME") {
        let path = PathBuf::from(base);
        anyhow::ensure!(path.is_absolute(), "portable home must be an absolute path");
        return Ok(std::fs::canonicalize(path)?);
    }
    let exe = std::env::current_exe()?;
    // Direct app launches also find the registry at the package root.
    if let Some(base) = exe
        .ancestors()
        .skip(1)
        .take(6)
        .find(|p| p.join("manifest.json").is_file() && p.join("VaultDrive.sh").is_file())
    {
        return Ok(base.to_path_buf());
    }
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("executable has no parent"))?;
    #[cfg(target_os = "macos")]
    if parent.file_name().is_some_and(|n| n == "MacOS") {
        if let Some(base) = parent.ancestors().nth(3) {
            return Ok(base.to_path_buf());
        }
    }
    Ok(parent.to_path_buf())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_app_list_cannot_erase_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["One", "Two"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }
        let mut first = Registry::load(dir.path().to_path_buf()).unwrap();
        let mut second = Registry::load(dir.path().to_path_buf()).unwrap();
        first.add(&dir.path().join("One")).unwrap();
        second.add(&dir.path().join("Two")).unwrap();
        assert_eq!(second.paths().len(), 2);
        first
            .remove(&std::fs::canonicalize(dir.path()).unwrap().join("One"))
            .unwrap();
        assert_eq!(first.paths().len(), 1);
        assert!(dir.path().join("One").exists());
    }
    #[test]
    fn registry_moves_with_drive() {
        let original = tempfile::tempdir().unwrap();
        let moved = tempfile::tempdir().unwrap();
        std::fs::create_dir(original.path().join("MyVault")).unwrap();
        let mut r = Registry::load(original.path().to_path_buf()).unwrap();
        r.add(&original.path().join("MyVault")).unwrap();
        std::fs::copy(
            original.path().join("vaults.json"),
            moved.path().join("vaults.json"),
        )
        .unwrap();
        let r = Registry::load(moved.path().to_path_buf()).unwrap();
        assert_eq!(
            r.paths(),
            vec![std::fs::canonicalize(moved.path()).unwrap().join("MyVault")]
        );
    }
    #[test]
    fn corrupted_registry_is_not_silently_reset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vaults.json"), b"broken").unwrap();
        assert!(Registry::load(dir.path().to_path_buf()).is_err());
    }
}
