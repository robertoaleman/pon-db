// SPDX-License-Identifier: AGPL-3.0-only
// PON-DB Engine: a database engine encapsulated in a single, portable, encrypted binary format
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/pon-db
use chrono::Local;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct MasterkeyManager;

/// Crea el archivo de clave sin sobrescribir ninguno existente y, en Unix, con permisos 0600.
fn open_new_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

impl MasterkeyManager {
    /// Genera una clave maestra aleatoria de 32 bytes y la guarda en el directorio actual.
    pub fn generate_and_save() -> io::Result<(Zeroizing<[u8; 32]>, PathBuf)> {
        Self::generate_and_save_in(Path::new("."))
    }

    pub fn generate_and_save_in(dir: &Path) -> io::Result<(Zeroizing<[u8; 32]>, PathBuf)> {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill(&mut *key);

        for _ in 0..8 {
            let random_id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();
            let date_str = Local::now().format("%Y-%m-%d").to_string();
            let path = dir.join(format!("masterkey_{}_{}.bin", random_id, date_str));

            match open_new_private(&path) {
                Ok(mut file) => {
                    let written = file.write_all(&*key).and_then(|_| file.sync_all());
                    if let Err(e) = written {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(e);
                    }
                    return Ok((key, path));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not choose a unique master key file name",
        ))
    }

    /// Carga una clave maestra. El archivo debe medir exactamente 32 bytes.
    pub fn load_key(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        if meta.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid key file {}: expected 32 bytes, found {}",
                    path.display(),
                    meta.len()
                ),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "warning: key file {} is accessible by other users; run: chmod 600 {}",
                    path.display(),
                    path.display()
                );
            }
        }

        let mut key = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut *key)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn generated_key_can_be_loaded_back() {
        let dir = TempDir::new("keys");
        let (key, path) = MasterkeyManager::generate_and_save_in(dir.path()).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        let loaded = MasterkeyManager::load_key(&path).unwrap();
        assert_eq!(*loaded, *key);
    }

    #[test]
    fn two_keys_are_different_files_and_values() {
        let dir = TempDir::new("keys2");
        let (k1, p1) = MasterkeyManager::generate_and_save_in(dir.path()).unwrap();
        let (k2, p2) = MasterkeyManager::generate_and_save_in(dir.path()).unwrap();
        assert_ne!(p1, p2);
        assert_ne!(*k1, *k2);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("keys3");
        let (_, path) = MasterkeyManager::generate_and_save_in(dir.path()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn wrong_size_key_is_rejected() {
        let dir = TempDir::new("keys4");
        let p = dir.join("short.bin");
        fs::write(&p, [1u8; 31]).unwrap();
        assert!(MasterkeyManager::load_key(&p).is_err());
        fs::write(&p, [1u8; 33]).unwrap();
        assert!(MasterkeyManager::load_key(&p).is_err());
    }
}
