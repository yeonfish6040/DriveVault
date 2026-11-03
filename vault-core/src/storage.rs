//! Host storage: lifetime exclusive lock and same-directory atomic replacement.
use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(crate) fn lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("vault.lock"))?;
    file.try_lock()
        .context("vault is in use, or the filesystem cannot provide exclusive locking")?;
    // Keep this file and its path in place for the entire unlocked session.
    Ok(file)
}
pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).context("cannot read vault snapshot")?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "vault snapshot exceeds format limit");
    Ok(bytes)
}
pub(crate) fn replace(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(dir.join(name))
        .context("atomic snapshot replacement failed")?;
    // Commit has occurred. A directory flush failure must not cause callers to
    // roll memory back to a version different from the committed snapshot.
    #[cfg(unix)]
    if let Ok(directory) = File::open(dir) {
        let _ = directory.sync_all();
    }
    Ok(())
}
