mod storage;
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VDMVP001";
const CHUNK: usize = 64 * 1024;
const MAX_PLAINTEXT: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Entry {
    Directory,
    File(Vec<u8>),
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contents(pub std::collections::BTreeMap<String, Entry>);

impl Contents {
    pub fn validate(&self) -> Result<()> {
        for path in self.0.keys() {
            anyhow::ensure!(
                path.starts_with('/')
                    && path != "/"
                    && !path.contains('\\')
                    && !path.chars().any(char::is_control),
                "invalid stored path"
            );
            anyhow::ensure!(
                !path
                    .split('/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == "." || p == ".."),
                "invalid stored path component"
            );
            if let Some((parent, _)) = path.rsplit_once('/') {
                anyhow::ensure!(
                    parent.is_empty() || matches!(self.0.get(parent), Some(Entry::Directory)),
                    "missing directory parent"
                );
            }
        }
        Ok(())
    }
}

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    pub contents: Contents,
    _lock: File,
    dir: std::path::PathBuf,
}
fn derive(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, Some(32)).expect("fixed valid parameters"),
    )
    .hash_password_into(password, salt, key.as_mut())
    .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}
impl Vault {
    pub fn create(dir: &Path, password: &[u8]) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = storage::lock(dir)?;
        if dir.join("vault.dat").exists() {
            bail!("vault already exists");
        }
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);
        let v = Self {
            key: derive(password, &salt)?,
            salt,
            contents: Contents::default(),
            _lock: lock,
            dir: fs::canonicalize(dir)?,
        };
        v.save(dir)?;
        Ok(v)
    }
    pub fn open(dir: &Path, password: &[u8]) -> Result<Self> {
        let lock = storage::lock(dir)?;
        let bytes = storage::read_bounded(&dir.join("vault.dat"), MAX_PLAINTEXT + 100_000)?;
        if bytes.len() < 28 || &bytes[..8] != MAGIC {
            bail!("invalid vault header");
        }
        let salt: [u8; 16] = bytes[8..24].try_into()?;
        let key = derive(password, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let count = u32::from_le_bytes(bytes[24..28].try_into()?) as usize;
        if count == 0 || count > MAX_PLAINTEXT / CHUNK + 1 {
            bail!("invalid chunk count");
        }
        let mut pos = 28;
        let mut plain = Zeroizing::new(Vec::new());
        for i in 0..count {
            if bytes.len().saturating_sub(pos) < 28 {
                bail!("truncated chunk");
            }
            let nonce = &bytes[pos..pos + 24];
            pos += 24;
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into()?) as usize;
            pos += 4;
            if !(16..=CHUNK + 16).contains(&len) || bytes.len().saturating_sub(pos) < len {
                bail!("invalid chunk length");
            }
            let aad = [
                MAGIC.as_slice(),
                &salt,
                &(count as u32).to_le_bytes(),
                &(i as u32).to_le_bytes(),
            ]
            .concat();
            let part = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(nonce),
                        Payload {
                            msg: &bytes[pos..pos + len],
                            aad: &aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("wrong password or vault damaged"))?,
            );
            plain.extend_from_slice(&part);
            pos += len;
        }
        if pos != bytes.len() || plain.len() > MAX_PLAINTEXT {
            bail!("invalid vault length");
        }
        let contents: Contents =
            serde_json::from_slice(&plain).context("invalid vault contents")?;
        contents.validate()?;
        Ok(Self {
            key,
            salt,
            contents,
            _lock: lock,
            dir: fs::canonicalize(dir)?,
        })
    }
    pub fn save(&self, dir: &Path) -> Result<()> {
        anyhow::ensure!(
            fs::canonicalize(dir)? == self.dir,
            "save target differs from locked vault"
        );
        self.contents.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(&self.contents)?);
        if plain.len() > MAX_PLAINTEXT {
            bail!("vault exceeds 64 MiB MVP limit");
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref()).unwrap();
        let count = plain.len().div_ceil(CHUNK).max(1) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&count.to_le_bytes());
        for (i, chunk) in plain.chunks(CHUNK).enumerate() {
            let mut nonce = [0u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let aad = [
                MAGIC.as_slice(),
                &self.salt,
                &count.to_le_bytes(),
                &(i as u32).to_le_bytes(),
            ]
            .concat();
            let encrypted = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: chunk,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("encryption failed"))?;
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
            out.extend_from_slice(&encrypted);
        }
        // Preserve the last committed ciphertext before replacing it.
        if dir.join("vault.dat").exists() {
            let previous = storage::read_bounded(&dir.join("vault.dat"), MAX_PLAINTEXT + 100_000)?;
            storage::replace(dir, "vault.bak", &previous)?;
        }
        storage::replace(dir, "vault.dat", &out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_wrong_password_and_tamper() {
        let d = std::env::temp_dir().join(format!("vd-{}", rand::random::<u64>()));
        let mut v = Vault::create(&d, b"secret").unwrap();
        v.contents
            .0
            .insert("/secret-name".into(), Entry::File(vec![42; 100_000]));
        v.save(&d).unwrap();
        let raw = fs::read(d.join("vault.dat")).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"secret-name"));
        let expected = v.contents.clone();
        drop(v);
        assert_eq!(Vault::open(&d, b"secret").unwrap().contents, expected);
        assert!(Vault::open(&d, b"bad").is_err());
        let mut bad = raw;
        let n = bad.len();
        bad[n - 1] ^= 1;
        fs::write(d.join("vault.dat"), bad).unwrap();
        assert!(Vault::open(&d, b"secret").is_err());
        fs::remove_dir_all(d).unwrap();
    }
}

#[cfg(test)]
mod reliability_tests {
    use super::*;
    #[test]
    fn exclusive_session_lock_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::create(dir.path(), b"secret").unwrap();
        assert!(Vault::open(dir.path(), b"secret").is_err());
        assert!(Vault::create(dir.path(), b"other").is_err());
        drop(v);
        assert!(Vault::open(dir.path(), b"secret").is_ok());
    }
    #[test]
    fn backup_is_previous_committed_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(dir.path(), b"secret").unwrap();
        let original = fs::read(dir.path().join("vault.dat")).unwrap();
        v.contents
            .0
            .insert("/file".into(), Entry::File(vec![1, 2, 3]));
        v.save(dir.path()).unwrap();
        assert_eq!(fs::read(dir.path().join("vault.bak")).unwrap(), original);
        drop(v);
        fs::copy(dir.path().join("vault.bak"), dir.path().join("vault.dat")).unwrap();
        assert!(Vault::open(dir.path(), b"secret")
            .unwrap()
            .contents
            .0
            .is_empty());
    }
    #[test]
    fn invalid_tree_cannot_replace_valid_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(dir.path(), b"secret").unwrap();
        let original = fs::read(dir.path().join("vault.dat")).unwrap();
        v.contents
            .0
            .insert("/missing/file".into(), Entry::File(vec![]));
        assert!(v.save(dir.path()).is_err());
        assert_eq!(fs::read(dir.path().join("vault.dat")).unwrap(), original);
    }
}
