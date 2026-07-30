use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

pub fn load_or_create_master_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建密钥目录：{error}"))?;
    }

    let mut generated = Zeroizing::new(vec![0_u8; KEY_BYTES]);
    OsRng.fill_bytes(&mut generated);

    #[cfg(unix)]
    let create_result = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(not(unix))]
    let create_result = OpenOptions::new().write(true).create_new(true).open(path);

    match create_result {
        Ok(mut file) => {
            file.write_all(&generated)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("无法写入主密钥：{error}"))?;
            Ok(generated)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => read_master_key(path),
        Err(error) => Err(format!("无法创建主密钥：{error}")),
    }
}

fn read_master_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("无法读取主密钥：{error}"))?;
    if bytes.len() != KEY_BYTES {
        return Err(format!(
            "主密钥长度无效：需要 {KEY_BYTES} 字节，实际为 {} 字节；为避免凭据丢失，应用不会覆盖该文件",
            bytes.len()
        ));
    }
    Ok(bytes)
}

pub fn encrypt(
    master_key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| "主密钥长度无效".to_string())?;
    let mut nonce = vec![0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "API Key 加密失败".to_string())?;
    Ok((nonce, ciphertext))
}

pub fn decrypt(
    master_key: &[u8],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<String>, String> {
    if nonce.len() != NONCE_BYTES {
        return Err("API Key 密文 nonce 无效".into());
    }
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| "主密钥长度无效".to_string())?;
    let plaintext = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "无法解密 API Key；主密钥可能已损坏或被替换".to_string())?;
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| "API Key 密文不是有效 UTF-8".to_string())
}
