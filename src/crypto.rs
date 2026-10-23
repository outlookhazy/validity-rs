use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::{NonZeroScalar, SecretKey};
use sha2::Sha256;
use std::fs;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const PASSWORD_HARDCODED: &[u8; 32] = &[
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];

pub const GWK_SIGN_HARDCODED: &[u8; 32] = &[
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];

pub fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(length);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC init");
    mac.update(seed);
    let mut a = mac.finalize().into_bytes().to_vec();

    let mut remaining = length;
    while remaining > 0 {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC init");
        mac.update(&a);
        mac.update(seed);
        let block = mac.finalize().into_bytes();
        let take = remaining.min(block.len());
        res.extend_from_slice(&block[..take]);
        remaining -= take;

        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC init");
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();
    }
    res
}

#[allow(dead_code)]
pub struct HwKeys {
    pub psk_encryption_key: Vec<u8>,
    pub psk_validation_key: Vec<u8>,
    pub product_name: String,
    pub product_serial: String,
}

impl HwKeys {
    pub fn load() -> Self {
        let product_name = fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap_or_else(|_| "VirtualBox".to_string())
            .trim()
            .to_string();

        let product_serial = std::env::var("VALIDITY_SERIAL")
            .ok()
            .or_else(|| fs::read_to_string("/sys/class/dmi/id/product_serial").ok())
            .unwrap_or_else(|| "0".to_string())
            .trim()
            .to_string();

        let mut hw_key = Vec::new();
        hw_key.extend_from_slice(product_name.as_bytes());
        hw_key.push(0);
        hw_key.extend_from_slice(product_serial.as_bytes());
        hw_key.push(0);

        let mut psk_enc_seed = b"GWK".to_vec();
        psk_enc_seed.extend_from_slice(&hw_key);
        let psk_encryption_key = prf(PASSWORD_HARDCODED, &psk_enc_seed, 0x20);

        let mut psk_val_seed = b"GWK_SIGN".to_vec();
        psk_val_seed.extend_from_slice(GWK_SIGN_HARDCODED);
        let psk_validation_key = prf(&psk_encryption_key, &psk_val_seed, 0x20);

        Self {
            psk_encryption_key,
            psk_validation_key,
            product_name,
            product_serial,
        }
    }
}

#[allow(dead_code)]
pub struct DecryptedPrivKey {
    pub secret_key: SecretKey,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub fn decrypt_host_priv_key(hw: &HwKeys, body: &[u8]) -> Result<DecryptedPrivKey, Box<dyn std::error::Error>> {
    if body.is_empty() {
        return Err("Empty private key body".into());
    }
    let prefix = body[0];
    if prefix != 2 {
        return Err(format!("Unknown private key prefix 0x{:02x} (expected 0x02)", prefix).into());
    }
    let rest = &body[1..];
    if rest.len() < 0x20 + 0x10 {
        return Err("Private key body too short".into());
    }

    let (c, hs) = rest.split_at(rest.len() - 0x20);

    // Verify HMAC-SHA256 signature in constant time
    let mut mac = HmacSha256::new_from_slice(&hw.psk_validation_key)?;
    mac.update(c);
    mac.verify_slice(hs)
        .map_err(|_| "Signature check failed! Sensor flash was likely paired with another machine or Windows.")?;

    let (iv, ciphertext) = c.split_at(0x10);

    let mut buf = ciphertext.to_vec();
    let decryptor = Aes256CbcDec::new_from_slices(&hw.psk_encryption_key, iv)?;
    let plaintext = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| format!("PKCS7 padding decrypt error: {:?}", e))?;

    if plaintext.len() < 0x60 {
        return Err("Decrypted private key payload too short".into());
    }

    let x = plaintext[0x00..0x20].to_vec();
    let y = plaintext[0x20..0x40].to_vec();
    let d = &plaintext[0x40..0x60];

    // d is little-endian 32-byte integer; convert to big-endian for p256
    let mut d_be = [0u8; 32];
    for (i, &b) in d.iter().enumerate() {
        d_be[31 - i] = b;
    }

    let non_zero_scalar: Option<NonZeroScalar> = NonZeroScalar::from_repr(d_be.into()).into();
    let non_zero_scalar = non_zero_scalar.ok_or("Invalid non-zero scalar for P-256 private key")?;
    let secret_key = SecretKey::from(non_zero_scalar);

    Ok(DecryptedPrivKey {
        secret_key,
        x,
        y,
    })
}
