//crypto.rs
//XOR encryption/decryption for payload obfuscation
//Author: wanmywann

// Hardcoded 32-byte XOR key
const XOR_KEY: [u8; 32] = [
    0x5A, 0x3C, 0x8E, 0x1F, 0x7B, 0xD2, 0x44, 0x99,
    0xAE, 0x61, 0x33, 0x0D, 0xCA, 0xFE, 0x27, 0x81,
    0x4F, 0xB8, 0xE2, 0x15, 0x6D, 0x9A, 0x30, 0x42,
    0xF7, 0x0B, 0xCC, 0x58, 0x1A, 0x83, 0xDE, 0x74,
];

pub fn xor_crypt(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect()
}

pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 2 && &data[..2] != b"MZ"
}

pub fn decrypt_if_needed(data: Vec<u8>) -> Vec<u8> {
    if is_encrypted(&data) {
        xor_crypt(&data)
    } else {
        data
    }
}

pub fn encrypt_file(path: &str) -> Result<(), String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    if data.len() < 2 {
        return Err("File too small".to_string());
    }

    let encrypted = xor_crypt(&data);
    let out_path = format!("{}.enc", path);

    std::fs::write(&out_path, &encrypted)
        .map_err(|e| format!("Failed to write encrypted file: {}", e))?;

    Ok(())
}
