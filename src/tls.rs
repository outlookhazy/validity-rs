use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::crypto::{prf, DecryptedPrivKey};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct DeviceEcdhKey {
    pub public_key: PublicKey,
}

impl DeviceEcdhKey {
    pub fn parse(body: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if body.len() < 0x90 {
            return Err("Device ECDH block too short".into());
        }
        let key = &body[..0x90];
        let x_le = &key[0x8..0x28];
        let y_le = &key[0x4c..0x6c];

        let mut x_be = [0u8; 32];
        let mut y_be = [0u8; 32];
        for i in 0..32 {
            x_be[31 - i] = x_le[i];
            y_be[31 - i] = y_le[i];
        }

        let encoded = EncodedPoint::from_affine_coordinates(
            &x_be.into(),
            &y_be.into(),
            false,
        );
        let public_key: Option<PublicKey> = PublicKey::from_encoded_point(&encoded).into();
        let public_key = public_key.ok_or("Failed to construct P-256 public key from device ECDH coordinates")?;

        Ok(Self { public_key })
    }
}

pub struct TlsSession {
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: Vec<u8>,
    pub sign_key: [u8; 32],
    pub validation_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub decryption_key: [u8; 32],
    pub handshake_hash: Sha256,
    pub secure_tx: bool,
    pub secure_rx: bool,
}

impl TlsSession {
    pub fn new() -> Self {
        let mut client_random = [0u8; 32];
        getrandom::getrandom(&mut client_random).expect("getrandom client_random");

        Self {
            client_random,
            server_random: [0u8; 32],
            master_secret: Vec::new(),
            sign_key: [0u8; 32],
            validation_key: [0u8; 32],
            encryption_key: [0u8; 32],
            decryption_key: [0u8; 32],
            handshake_hash: Sha256::new(),
            secure_tx: false,
            secure_rx: false,
        }
    }

    fn update_neg(&mut self, data: &[u8]) {
        self.handshake_hash.update(data);
    }

    fn with_3bytes_size(chunk: &[u8]) -> Vec<u8> {
        let len = chunk.len();
        let mut v = Vec::with_capacity(3 + len);
        v.push((len >> 16) as u8);
        v.push((len >> 8) as u8);
        v.push(len as u8);
        v.extend_from_slice(chunk);
        v
    }

    fn with_2bytes_size(chunk: &[u8]) -> Vec<u8> {
        let len = chunk.len();
        let mut v = Vec::with_capacity(2 + len);
        v.push((len >> 8) as u8);
        v.push(len as u8);
        v.extend_from_slice(chunk);
        v
    }

    fn with_neg_hdr(&mut self, t: u8, b: &[u8]) -> Vec<u8> {
        let mut res = Vec::new();
        res.push(t);
        res.extend_from_slice(&Self::with_3bytes_size(b));
        self.update_neg(&res);
        res
    }

    pub fn make_client_hello(&mut self) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        h.extend_from_slice(&self.client_random);

        // Session ID: 7 bytes of zeroes
        let sess_id = [0u8; 7];
        h.push(sess_id.len() as u8);
        h.extend_from_slice(&sess_id);

        // Cipher suites: 0xc005, 0x003d, 0x008d
        let mut suits = Vec::new();
        suits.extend_from_slice(&0xc005u16.to_be_bytes());
        suits.extend_from_slice(&0x003du16.to_be_bytes());
        suits.extend_from_slice(&0x008du16.to_be_bytes());
        h.extend_from_slice(&Self::with_2bytes_size(&suits));

        // Compression: none (0)
        h.push(0);

        // Extensions
        let mut exts = Vec::new();
        // truncated_hmac (0x0004) -> 0x0017
        exts.extend_from_slice(&0x0004u16.to_be_bytes());
        exts.extend_from_slice(&Self::with_2bytes_size(&0x0017u16.to_be_bytes()));

        // ec_point_formats (0x000b) -> uncompressed (0)
        exts.extend_from_slice(&0x000bu16.to_be_bytes());
        exts.extend_from_slice(&Self::with_2bytes_size(&[1, 0]));

        // Note: len(exts) - 2 quirk from python-validity
        let ext_len_quirk = (exts.len() - 2) as u16;
        h.extend_from_slice(&ext_len_quirk.to_be_bytes());
        h.extend_from_slice(&exts);

        let neg = self.with_neg_hdr(0x01, &h);

        // Prefix with 44 00 00 00 and TLS record header (16 03 03 [len])
        let mut record = Vec::new();
        record.extend_from_slice(&[0x44, 0x00, 0x00, 0x00]);
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&Self::with_2bytes_size(&neg));
        record
    }

    pub fn parse_tls_response(&mut self, rsp: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut app_data = Vec::new();
        let mut data = rsp;

        while !data.is_empty() {
            if data.len() < 5 {
                break;
            }
            let t = data[0];
            let mj = data[1];
            let mn = data[2];
            let sz = BigEndian::read_u16(&data[3..5]) as usize;
            data = &data[5..];

            if mj != 3 || mn != 3 {
                return Err(format!("Unexpected TLS version {}.{}", mj, mn).into());
            }

            if sz > data.len() {
                return Err(format!("Truncated TLS packet: expected {} bytes, got {}", sz, data.len()).into());
            }

            let pkt = &data[..sz];
            data = &data[sz..];

            match t {
                0x15 => {
                    // Alert record!
                    let level = if !pkt.is_empty() { pkt[0] } else { 0 };
                    let desc = if pkt.len() > 1 { pkt[1] } else { 0 };
                    let level_str = if level == 1 { "Warning" } else if level == 2 { "Fatal" } else { "Unknown" };
                    return Err(format!("TLS Alert from sensor: {} (code 0x{:02x} / {})", level_str, desc, desc).into());
                }
                0x14 => {
                    // ChangeCipherSpec
                    if pkt != [0x01] {
                        return Err(format!("Unexpected ChangeCipherSpec payload: {}", hex::encode(pkt)).into());
                    }
                    self.secure_rx = true;
                    println!("    Received ChangeCipherSpec: sensor enabled encrypted transmission!");
                }
                0x16 => {
                    // Handshake record
                    let decrypted_hs;
                    let hs_bytes = if self.secure_rx {
                        decrypted_hs = self.decrypt_record(0x16, pkt)?;
                        &decrypted_hs[..]
                    } else {
                        pkt
                    };

                    let mut hs = hs_bytes;
                    while !hs.is_empty() {
                        if hs.len() < 4 {
                            break;
                        }
                        let ht = hs[0];
                        let hlen = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
                        let hhdr = &hs[..4];
                        hs = &hs[4..];
                        if hlen > hs.len() {
                            return Err("Truncated handshake element".into());
                        }
                        let p = &hs[..hlen];
                        hs = &hs[hlen..];

                        match ht {
                            2 => {
                                // ServerHello
                                if p.len() < 34 {
                                    return Err("ServerHello too short".into());
                                }
                                self.server_random.copy_from_slice(&p[2..34]);
                                println!("    Parsed ServerHello: server_random = {}", hex::encode(&self.server_random[..8]));
                            }
                            0x0d => {
                                println!("    Parsed CertificateRequest");
                            }
                            0x0e => {
                                println!("    Parsed ServerHelloDone");
                            }
                            0x14 => {
                                // Server Finished
                                let hs_hash = self.handshake_hash.clone().finalize();
                                let mut fin_seed = b"server finished".to_vec();
                                fin_seed.extend_from_slice(&hs_hash);
                                let expected_verify_data = prf(&self.master_secret, &fin_seed, 0x0c);
                                if expected_verify_data.as_slice() != p {
                                    return Err("Server Finished verify_data mismatch!".into());
                                }
                                println!("    Server Finished verified successfully!");
                            }
                            _ => println!("    Handshake type: 0x{:02x}", ht),
                        }

                        let mut h_combined = Vec::new();
                        h_combined.extend_from_slice(hhdr);
                        h_combined.extend_from_slice(p);
                        self.update_neg(&h_combined);
                    }
                }
                0x17 => {
                    // ApplicationData
                    if !self.secure_rx {
                        return Err("App payload received before secure connection established".into());
                    }
                    let decrypted = self.decrypt_record(0x17, pkt)?;
                    app_data.extend_from_slice(&decrypted);
                }
                _ => return Err(format!("Unknown TLS message type 0x{:02x}", t).into()),
            }
        }

        Ok(app_data)
    }

    pub fn make_keys_and_finish(
        &mut self,
        device_ecdh: &DeviceEcdhKey,
        host_priv: &DecryptedPrivKey,
        tls_cert: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Generate ephemeral client key pair for ECDH
        let mut rng = OsRng;
        let ephemeral_sk = SecretKey::random(&mut rng);
        let ephemeral_pk = ephemeral_sk.public_key();

        // Perform ECDH with device's public key from Block 6
        let shared_secret = p256::ecdh::diffie_hellman(
            ephemeral_sk.to_nonzero_scalar(),
            device_ecdh.public_key.as_affine(),
        );

        let pre_master = shared_secret.raw_secret_bytes();

        let mut seed = Vec::new();
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);

        let mut ms_seed = b"master secret".to_vec();
        ms_seed.extend_from_slice(&seed);
        self.master_secret = prf(pre_master.as_slice(), &ms_seed, 0x30);

        let mut ke_seed = b"key expansion".to_vec();
        ke_seed.extend_from_slice(&seed);
        let key_block = prf(&self.master_secret, &ke_seed, 0x120);

        self.sign_key.copy_from_slice(&key_block[0x00..0x20]);
        self.validation_key.copy_from_slice(&key_block[0x20..0x40]);
        self.encryption_key.copy_from_slice(&key_block[0x40..0x60]);
        self.decryption_key.copy_from_slice(&key_block[0x60..0x80]);

        println!("    Derived TLS Master Secret and Session Keys successfully!");

        // Build Certificates payload
        let mut cert_payload = Vec::new();
        cert_payload.extend_from_slice(&[0xac, 0x16]);
        cert_payload.extend_from_slice(tls_cert);
        let mut cert_wrapped = Vec::new();
        cert_wrapped.extend_from_slice(&[0, (tls_cert.len() >> 8) as u8, tls_cert.len() as u8]);
        cert_wrapped.extend_from_slice(&cert_payload);
        let mut cert_double_wrapped = Vec::new();
        cert_double_wrapped.extend_from_slice(&[0, (tls_cert.len() >> 8) as u8, tls_cert.len() as u8]);
        cert_double_wrapped.extend_from_slice(&cert_wrapped);
        let cert_msg = self.with_neg_hdr(0x0b, &cert_double_wrapped);

        // Build ClientKeyExchange (ephemeral public key coordinates x, y)
        let encoded_point = ephemeral_pk.to_encoded_point(false);
        let kex_msg = self.with_neg_hdr(0x10, encoded_point.as_bytes());

        // Build CertificateVerify: ECDSA signature over handshake_hash using host_priv
        let hash_so_far = self.handshake_hash.clone().finalize();
        let signing_key = SigningKey::from(&host_priv.secret_key);
        let signature: Signature = signing_key.sign_prehash(&hash_so_far)?;
        let der_sig = signature.to_der();
        let verify_msg = self.with_neg_hdr(0x0f, der_sig.as_bytes());

        // Combine Handshake messages (Cert + KEX + CertVerify)
        let mut hs_combined = Vec::new();
        hs_combined.extend_from_slice(&cert_msg);
        hs_combined.extend_from_slice(&kex_msg);
        hs_combined.extend_from_slice(&verify_msg);

        // Wrap into record
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x44, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x16, 0x03, 0x03]);
        packet.extend_from_slice(&Self::with_2bytes_size(&hs_combined));

        // Append ChangeCipherSpec: 14 03 03 00 01 01
        packet.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

        // Client Finished: 0x14 + with_3bytes_size(verify_data)
        self.secure_tx = true;
        let hs_final_hash = self.handshake_hash.clone().finalize();
        let mut fin_seed = b"client finished".to_vec();
        fin_seed.extend_from_slice(&hs_final_hash);
        let verify_data = prf(&self.master_secret, &fin_seed, 0x0c);

        let mut fin_msg = Vec::new();
        fin_msg.push(0x14);
        fin_msg.extend_from_slice(&Self::with_3bytes_size(&verify_data));

        // Encrypt and sign Finished
        let encrypted_fin = self.encrypt_record(0x16, &fin_msg)?;
        packet.extend_from_slice(&[0x16, 0x03, 0x03]);
        packet.extend_from_slice(&Self::with_2bytes_size(&encrypted_fin));

        Ok(packet)
    }

    pub fn encrypt_record(&self, t: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Sign with sign_key
        let mut hdr = [0u8; 5];
        hdr[0] = t;
        hdr[1] = 3;
        hdr[2] = 3;
        BigEndian::write_u16(&mut hdr[3..5], payload.len() as u16);

        let mut mac = HmacSha256::new_from_slice(&self.sign_key)?;
        mac.update(&hdr);
        mac.update(payload);
        let sig = mac.finalize().into_bytes();

        let mut to_encrypt = Vec::new();
        to_encrypt.extend_from_slice(payload);
        to_encrypt.extend_from_slice(&sig);

        // In TLS 1.2 CBC, padding bytes are (pad_len - 1) repeated pad_len times
        let pad_len = 16 - (to_encrypt.len() % 16);
        for _ in 0..pad_len {
            to_encrypt.push((pad_len - 1) as u8);
        }

        let mut iv = [0u8; 16];
        getrandom::getrandom(&mut iv).expect("getrandom iv");

        let encryptor = Aes256CbcEnc::new_from_slices(&self.encryption_key, &iv)?;
        let total_len = to_encrypt.len();
        let ciphertext = encryptor.encrypt_padded_mut::<NoPadding>(&mut to_encrypt, total_len)
            .map_err(|e| format!("AES CBC encrypt error: {:?}", e))?;

        let mut out = Vec::new();
        out.extend_from_slice(&iv);
        out.extend_from_slice(ciphertext);
        Ok(out)
    }

    pub fn decrypt_record(&self, t: u8, c: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if c.len() < 16 + 32 {
            return Err("Ciphertext too short".into());
        }
        let (iv, ciphertext) = c.split_at(16);
        let mut buf = ciphertext.to_vec();
        let decryptor = Aes256CbcDec::new_from_slices(&self.decryption_key, iv)?;
        let decrypted = decryptor.decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|e| format!("AES CBC decrypt error: {:?}", e))?;

        if decrypted.is_empty() {
            return Err("Decrypted payload empty".into());
        }
        let pad_len = (*decrypted.last().unwrap() as usize) + 1;
        if pad_len > decrypted.len() {
            return Err("Invalid padding length".into());
        }
        let unpadded = &decrypted[..decrypted.len() - pad_len];

        if unpadded.len() < 32 {
            return Err("Payload too short for HMAC".into());
        }
        let (payload, sig) = unpadded.split_at(unpadded.len() - 32);

        let mut hdr = [0u8; 5];
        hdr[0] = t;
        hdr[1] = 3;
        hdr[2] = 3;
        BigEndian::write_u16(&mut hdr[3..5], payload.len() as u16);

        let mut mac = HmacSha256::new_from_slice(&self.validation_key)?;
        mac.update(&hdr);
        mac.update(payload);
        mac.verify_slice(sig)
            .map_err(|_| "TLS record signature validation check failed")?;

        Ok(payload.to_vec())
    }

    pub fn make_app_data(&self, cmd: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let enc = self.encrypt_record(0x17, cmd)?;
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x17, 0x03, 0x03]);
        packet.extend_from_slice(&Self::with_2bytes_size(&enc));
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_format() {
        let mut tls = TlsSession::new();
        tls.client_random = [1u8; 32];
        let ch = tls.make_client_hello();
        assert_eq!(
            hex::encode(&ch),
            "440000001603030045010000410303010101010101010101010101010101010101010101010101010101010101010107000000000000000006c005003d008d00000a000400020017000b00020100"
        );
    }

    #[test]
    fn test_prehash_signer() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&sk);
        let digest = [0x5au8; 32];
        let sig: Signature = signing_key.sign_prehash(&digest).unwrap();
        assert_eq!(sig.to_der().as_bytes().len() > 0, true);
    }
}
