#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use byteorder::{ByteOrder, LittleEndian};
use nusb::transfer::{Buffer, Bulk, In, Interrupt, Out};
use crate::blobs::{INIT_HARDCODED, DB_WRITE_ENABLE};
use crate::crypto::{HwKeys, decrypt_host_priv_key};
use crate::db::{uid_to_identity_bytes, make_finger_data, parse_user_storage, parse_user, finger_id_to_name, UserInfo};
use crate::tls::{TlsSession, DeviceEcdhKey};

pub const CAPTURE_PROG_BLOB_0: &[u8] = &[
    0x23, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x20, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x32, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x80, 0x20, 0x20, 0x05, 0x00, 0x24, 0x20, 0x00, 0x00,
    0x50, 0x20, 0x77, 0x36, 0x28, 0x20, 0x01, 0x00, 0x30, 0x20, 0x01, 0x00, 0x08, 0x21, 0x70, 0x00,
    0x0c, 0x21, 0x00, 0x00, 0x48, 0x21, 0x02, 0x00, 0x4c, 0x21, 0x00, 0x00, 0x58, 0x20, 0x00, 0x00,
    0x5c, 0x20, 0x00, 0x00, 0x60, 0x20, 0x00, 0x00, 0x68, 0x20, 0x05, 0x00, 0x6c, 0x20, 0x01, 0x29,
    0x70, 0x20, 0x01, 0x21, 0x74, 0x20, 0x01, 0x88, 0x78, 0x20, 0x01, 0x80, 0x84, 0x20, 0x20, 0x00,
    0x94, 0x20, 0x01, 0x80, 0x9c, 0x20, 0x09, 0x02, 0xa0, 0x20, 0x0b, 0x19, 0xb4, 0x20, 0x00, 0x00,
    0xb8, 0x20, 0x3b, 0x04, 0xbc, 0x20, 0x14, 0x00, 0xc0, 0x20, 0x02, 0x00, 0xc4, 0x20, 0x01, 0x00,
    0xc8, 0x20, 0x02, 0x00, 0x33, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x80, 0xcc, 0x20, 0x00, 0x00,
    0xf5, 0x03, 0xd0, 0x20, 0x00, 0x00, 0xa1, 0x01, 0x32, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x80,
    0xdc, 0x20, 0xe8, 0x03, 0xe0, 0x20, 0x64, 0x01, 0xe4, 0x20, 0xd0, 0x02, 0xe8, 0x20, 0x00, 0x01,
    0xf0, 0x20, 0x05, 0x00, 0xf8, 0x20, 0x05, 0x00, 0xfc, 0x20, 0x00, 0x00, 0xb8, 0x20, 0x3b, 0x00,
    0x00, 0x08, 0x04, 0x00, 0x14, 0x08, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00,
    0x14, 0x08, 0x30, 0x00, 0x08, 0x08, 0x00, 0x00, 0x14, 0x08, 0x31, 0x00, 0x1c, 0x08, 0x1a, 0x00,
];

pub const CAPTURE_PROG_BLOB_1: &[u8] = &[
    0x32, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x80, 0x50, 0x11, 0x01, 0x00, 0x4c, 0x11, 0x26, 0x00,
    0x34, 0x00, 0x08, 0x03, 0x10, 0x06, 0x1d, 0x10, 0x06, 0x1d, 0x10, 0x06, 0x1d, 0x10, 0x06, 0x1d,
    0x10, 0x06, 0x1c, 0x01, 0x06, 0x58, 0x10, 0x08, 0x01, 0x01, 0x00, 0x00, 0x07, 0xc8, 0x07, 0x8c,
    0x06, 0x10, 0x00, 0x00, 0x20, 0x4f, 0x80, 0x00, 0x7f, 0x00, 0x00, 0x03, 0x07, 0x01, 0x07, 0x01,
    0x0c, 0x07, 0x03, 0x2c, 0x08, 0xfc, 0x80, 0x09, 0x5a, 0x80, 0x0a, 0xfc, 0x08, 0xfb, 0x80, 0x0b,
    0x5a, 0x09, 0x5b, 0x80, 0x0a, 0xfb, 0x08, 0xfa, 0x80, 0x0b, 0x5b, 0x09, 0x5c, 0x80, 0x0a, 0xfa,
    0x08, 0xf9, 0x80, 0x0b, 0x5c, 0x09, 0x5d, 0x80, 0x0a, 0xf9, 0x08, 0xf8, 0x80, 0x0b, 0x5d, 0x09,
    0x5e, 0x80, 0x0a, 0xf8, 0x08, 0xf7, 0x80, 0x0b, 0x5e, 0x09, 0x5f, 0x80, 0x0a, 0xf7, 0x08, 0xf6,
    0x80, 0x0b, 0x5f, 0x09, 0x60, 0x80, 0x0a, 0xf6, 0x08, 0xf5, 0x80, 0x0b, 0x60, 0x09, 0x61, 0x80,
    0x0a, 0xf5, 0x08, 0xf4, 0x80, 0x0b, 0x61, 0x09, 0x62, 0x80, 0x0a, 0xf4, 0x08, 0xf3, 0x80, 0x0b,
    0x62, 0x09, 0x63, 0x80, 0x0a, 0xf3, 0x08, 0xf2, 0x80, 0x0b, 0x63, 0x09, 0x64, 0x80, 0x0a, 0xf2,
    0x08, 0xf1, 0x80, 0x0b, 0x64, 0x09, 0x65, 0x80, 0x0a, 0xf1, 0x08, 0xf0, 0x80, 0x0b, 0x65, 0x09,
    0x66, 0x80, 0x0a, 0xf0, 0x08, 0xef, 0x80, 0x0b, 0x66, 0x09, 0x67, 0x80, 0x0a, 0xef, 0x08, 0xee,
    0x80, 0x0b, 0x67, 0x09, 0x68, 0x80, 0x0a, 0xee, 0x08, 0xed, 0x80, 0x0b, 0x68, 0x09, 0x6c, 0x80,
    0x0a, 0xed, 0x08, 0xec, 0x80, 0x0b, 0x6c, 0x09, 0x6d, 0x80, 0x0a, 0xec, 0x08, 0xeb, 0x80, 0x0b,
    0x6d, 0x09, 0x6e, 0x80, 0x0a, 0xeb, 0x08, 0xea, 0x80, 0x0b, 0x6e, 0x09, 0x6f, 0x80, 0x0a, 0xea,
    0x08, 0xe9, 0x80, 0x0b, 0x6f, 0x09, 0x70, 0x80, 0x0a, 0xe9, 0x08, 0xe8, 0x80, 0x0b, 0x70, 0x09,
    0x71, 0x80, 0x0a, 0xe8, 0x08, 0xe7, 0x80, 0x0b, 0x71, 0x09, 0x72, 0x80, 0x0a, 0xe7, 0x08, 0xe6,
    0x80, 0x0b, 0x72, 0x09, 0x73, 0x80, 0x0a, 0xe6, 0x08, 0xe5, 0x80, 0x0b, 0x73, 0x09, 0x74, 0x80,
    0x0a, 0xe5, 0x08, 0xe4, 0x80, 0x0b, 0x74, 0x09, 0x75, 0x80, 0x0a, 0xe4, 0x08, 0xe3, 0x80, 0x0b,
    0x75, 0x09, 0x76, 0x80, 0x0a, 0xe3, 0x08, 0xe2, 0x80, 0x0b, 0x76, 0x09, 0x77, 0x80, 0x0a, 0xe2,
    0x08, 0xe1, 0x80, 0x0b, 0x77, 0x09, 0x78, 0x80, 0x0a, 0xe1, 0x08, 0xe0, 0x80, 0x0b, 0x78, 0x09,
    0x79, 0x80, 0x0a, 0xe0, 0x08, 0xdf, 0x80, 0x0b, 0x79, 0x09, 0x7a, 0x80, 0x0a, 0xdf, 0x08, 0xde,
    0x80, 0x0b, 0x7a, 0x09, 0x7b, 0x80, 0x0a, 0xde, 0x08, 0xdd, 0x80, 0x0b, 0x7b, 0x09, 0x7c, 0x80,
    0x0a, 0xdd, 0x08, 0xdc, 0x80, 0x0b, 0x7c, 0x09, 0x7d, 0x80, 0x0a, 0xdc, 0x08, 0xdb, 0x80, 0x0b,
    0x7d, 0x09, 0x7e, 0x80, 0x0a, 0xdb, 0x08, 0xda, 0x80, 0x0b, 0x7e, 0x09, 0x7f, 0x80, 0x0a, 0xda,
    0x08, 0xd9, 0x80, 0x0b, 0x7f, 0x09, 0x80, 0x80, 0x0a, 0xd9, 0x08, 0xd8, 0x80, 0x0b, 0x80, 0x09,
    0x81, 0x80, 0x0a, 0xd8, 0x08, 0xd7, 0x80, 0x0b, 0x81, 0x09, 0x82, 0x80, 0x0a, 0xd7, 0x08, 0xd6,
    0x80, 0x0b, 0x82, 0x09, 0x83, 0x80, 0x0a, 0xd6, 0x08, 0xd5, 0x80, 0x0b, 0x83, 0x09, 0x84, 0x80,
    0x0a, 0xd5, 0x08, 0xd4, 0x80, 0x0b, 0x84, 0x09, 0x85, 0x80, 0x0a, 0xd4, 0x08, 0xd3, 0x80, 0x0b,
    0x85, 0x09, 0x86, 0x80, 0x0a, 0xd3, 0x08, 0xd2, 0x80, 0x0b, 0x86, 0x09, 0x87, 0x80, 0x0a, 0xd2,
    0x08, 0xd1, 0x80, 0x0b, 0x87, 0x09, 0x88, 0x80, 0x0a, 0xd1, 0x08, 0xd0, 0x80, 0x0b, 0x88, 0x09,
    0x89, 0x80, 0x0a, 0xd0, 0x08, 0xcf, 0x80, 0x0b, 0x89, 0x09, 0x8a, 0x80, 0x0a, 0xcf, 0x08, 0xce,
    0x80, 0x0b, 0x8a, 0x09, 0x8b, 0x80, 0x0a, 0xce, 0x08, 0xcd, 0x80, 0x0b, 0x8b, 0x09, 0x8c, 0x80,
    0x0a, 0xcd, 0x08, 0xcc, 0x80, 0x0b, 0x8c, 0x09, 0x8d, 0x80, 0x0a, 0xcc, 0x08, 0xcb, 0x80, 0x0b,
    0x8d, 0x09, 0x8e, 0x80, 0x0a, 0xcb, 0x08, 0xca, 0x80, 0x0b, 0x8e, 0x09, 0x8f, 0x80, 0x0a, 0xca,
    0x08, 0xc9, 0x80, 0x0b, 0x8f, 0x09, 0x90, 0x80, 0x0a, 0xc9, 0x08, 0xc8, 0x80, 0x0b, 0x90, 0x09,
    0x91, 0x80, 0x0a, 0xc8, 0x08, 0xc7, 0x80, 0x0b, 0x91, 0x09, 0x92, 0x80, 0x0a, 0xc7, 0x08, 0xc6,
    0x80, 0x0b, 0x92, 0x09, 0x93, 0x80, 0x0a, 0xc6, 0x08, 0xc5, 0x80, 0x0b, 0x93, 0x09, 0x94, 0x80,
    0x0a, 0xc5, 0x08, 0xc4, 0x80, 0x0b, 0x94, 0x09, 0x95, 0x80, 0x0a, 0xc4, 0x08, 0xc3, 0x80, 0x0b,
    0x95, 0x09, 0x96, 0x80, 0x0a, 0xc3, 0x08, 0xc2, 0x80, 0x0b, 0x96, 0x09, 0x97, 0x80, 0x0a, 0xc2,
    0x08, 0xc1, 0x80, 0x0b, 0x97, 0x09, 0x98, 0x80, 0x0a, 0xc1, 0x08, 0xc0, 0x80, 0x0b, 0x98, 0x09,
    0x99, 0x80, 0x0a, 0xc0, 0x08, 0xbf, 0x80, 0x0b, 0x99, 0x09, 0x9a, 0x80, 0x0a, 0xbf, 0x08, 0xbe,
    0x80, 0x0b, 0x9a, 0x09, 0x9b, 0x80, 0x0a, 0xbe, 0x08, 0xbd, 0x80, 0x0b, 0x9b, 0x09, 0x9c, 0x80,
    0x0a, 0xbd, 0x08, 0xbc, 0x80, 0x0b, 0x9c, 0x09, 0x9d, 0x80, 0x0a, 0xbc, 0x08, 0xbb, 0x80, 0x0b,
    0x9d, 0x09, 0x9e, 0x80, 0x0a, 0xbb, 0x08, 0xba, 0x80, 0x0b, 0x9e, 0x09, 0x9f, 0x80, 0x0a, 0xba,
    0x08, 0xb9, 0x80, 0x0b, 0x9f, 0x09, 0xa0, 0x80, 0x0a, 0xb9, 0x08, 0xb8, 0x80, 0x0b, 0xa0, 0x08,
    0x01, 0x80, 0x0a, 0xb8, 0x08, 0xb7, 0x80, 0x0a, 0x01, 0x08, 0x02, 0x80, 0x0a, 0xb7, 0x08, 0xb6,
    0x80, 0x0a, 0x02, 0x08, 0x03, 0x80, 0x0a, 0xb6, 0x08, 0xb5, 0x80, 0x0a, 0x03, 0x08, 0x04, 0x80,
    0x20, 0x03, 0x07, 0x04, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x04, 0x00,
    0x90, 0x00, 0x00, 0x00, 0x29, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x04, 0x00,
    0x10, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Calibrate,
    Identify,
    Enroll,
}

pub fn build_cmd_02(calib_data: &[u8], calib_vals: &[u8], mode: CaptureMode) -> Vec<u8> {
    let mut prog = Vec::new();
    prog.extend_from_slice(CAPTURE_PROG_BLOB_0);
    prog.extend_from_slice(CAPTURE_PROG_BLOB_1);

    let mut chunks: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut data = &prog[..];
    while data.len() >= 4 {
        let typ = LittleEndian::read_u16(&data[0..2]);
        let len = LittleEndian::read_u16(&data[2..4]) as usize;
        data = &data[4..];
        if len > data.len() { break; }
        chunks.push((typ, data[..len].to_vec()));
        data = &data[len..];
    }

    // Patch chunk 0x34
    for (typ, val) in &mut chunks {
        if *typ == 0x34 {
            let mut i = 0;
            while i + 3 < val.len() {
                if val[i] & 0xf8 == 0x10 {
                    if val[i + 2] > 1 {
                        val[i + 1] += 1;
                    }
                    i += 3;
                    continue;
                }
                if val[i] == 0 {
                    i += 1;
                    continue;
                }
                if val[i] == 7 {
                    i += 2;
                    continue;
                }
                break;
            }
            if calib_vals.len() > 0x48 {
                val[34] = calib_vals[0x48];
            }
        }
    }

    // 0x17 (Reply Config)
    chunks.push((0x17, Vec::new()));

    if mode == CaptureMode::Identify {
        // 0x4e for IDENTIFY
        let c4e = hex::decode(
            "fbb20f0000000f00300000006001020040010a00018000000a0200000b1900008813b80b01091000"
        ).unwrap();
        chunks.push((0x4e, c4e));

        // 0x2e for IDENTIFY
        let c2e = hex::decode(
            "0200180002000000900090004d01000090017c013c323232640a0201"
        ).unwrap();
        chunks.push((0x2e, c2e));
    } else if mode == CaptureMode::Enroll {
        // 0x26 for ENROLL
        let c26 = hex::decode(
            "fbb20f0000000f00300000006001020040010a00018000000a0200000b19000050c360ea01091000"
        ).unwrap();
        chunks.push((0x26, c26));

        // 0x2e for ENROLL
        let c2e = hex::decode(
            "0200180023000000900090004d01000090017c013c323232640a0201"
        ).unwrap();
        chunks.push((0x2e, c2e));
    }

    // 0x30 (Line Update)
    let mut line_update = Vec::new();
    line_update.extend_from_slice(&3u32.to_le_bytes()); // 3 lines
    line_update.extend_from_slice(&0xffu32.to_le_bytes());
    line_update.extend_from_slice(&0x0300001du32.to_le_bytes());
    line_update.extend_from_slice(&0xffu32.to_le_bytes());
    line_update.extend_from_slice(&0x03000025u32.to_le_bytes());
    line_update.extend_from_slice(&0xffu32.to_le_bytes());
    line_update.extend_from_slice(&0x03000022u32.to_le_bytes());

    for b in 0x10u8..=0x9fu8 {
        line_update.push(b);
    }
    line_update.extend_from_slice(calib_data);
    line_update.extend_from_slice(calib_vals);

    chunks.push((0x30, line_update));

    let mut cmd = Vec::new();
    cmd.push(0x02);
    cmd.extend_from_slice(&0x98u16.to_le_bytes());
    cmd.extend_from_slice(&0u16.to_le_bytes());

    for (typ, val) in chunks {
        cmd.extend_from_slice(&typ.to_le_bytes());
        cmd.extend_from_slice(&(val.len() as u16).to_le_bytes());
        cmd.extend_from_slice(&val);
    }

    cmd
}

/// Outcome of a failed capture, so callers can decide whether to re-arm, retry or give up.
#[derive(Debug)]
pub enum CaptureError {
    /// The operation was cancelled by the client.
    Cancelled,
    /// No finger was placed within the capture window.
    Timeout,
    /// The sensor reported a bad scan (finger moved, partial touch, ...).
    ScanProblem(u32),
    /// USB / TLS / protocol failure.
    Device(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Cancelled => write!(f, "capture cancelled"),
            CaptureError::Timeout => write!(f, "capture timed out waiting for finger"),
            CaptureError::ScanProblem(code) => write!(f, "sensor scanning problem: 0x{:08x}", code),
            CaptureError::Device(e) => write!(f, "{}", e),
        }
    }
}

impl From<String> for CaptureError {
    fn from(e: String) -> Self {
        CaptureError::Device(e)
    }
}

struct UsbTransport {
    _interface: nusb::Interface,
    out_ep: nusb::Endpoint<Bulk, Out>,
    in_ep: nusb::Endpoint<Bulk, In>,
    int_ep: nusb::Endpoint<Interrupt, In>,
}

pub struct SensorDriver {
    transport: Option<UsbTransport>,
    tls: Option<TlsSession>,
    slept: Arc<AtomicBool>,
    user_cache: HashMap<u32, Option<UserInfo>>,
    pub calib_data: Vec<u8>,
    pub calib_vals: Vec<u8>,
    pub stg_id: u16,
    /// Incremented on every (re)connect. Sensor-side session state such as an
    /// in-progress enrollment does not survive a reconnect, so callers can detect that.
    pub generation: u64,
}

impl SensorDriver {
    pub async fn open() -> Result<Self, String> {
        let (transport, tls, calib_data, calib_vals, stg_id) =
            Self::connect(Some(Duration::from_secs(5))).await?;
        Ok(Self {
            transport: Some(transport),
            tls: Some(tls),
            slept: Arc::new(AtomicBool::new(false)),
            user_cache: HashMap::new(),
            calib_data,
            calib_vals,
            stg_id,
            generation: 1,
        })
    }

    /// Lock-free flag set by the PrepareForSleep(true) handler so the next `ensure_connected`
    /// invalidates any pre-sleep TLS session even if the driver mutex was held entering sleep.
    pub fn slept_flag(&self) -> Arc<AtomicBool> {
        self.slept.clone()
    }

    #[cfg(test)]
    pub(crate) fn dummy_disconnected() -> Self {
        Self {
            transport: None,
            tls: None,
            slept: Arc::new(AtomicBool::new(false)),
            user_cache: HashMap::new(),
            calib_data: Vec::new(),
            calib_vals: Vec::new(),
            stg_id: 3,
            generation: 1,
        }
    }

    /// Release the open usbfs handle so the kernel can runtime-suspend the USB device and root
    /// hub when idle. The 138a:0097 discards its TLS session while suspended (verified on
    /// hardware: encrypted requests get raw non-TLS replies afterwards), so the session is
    /// dropped too and the next use performs a full handshake. The user cache is kept.
    pub fn suspend_usb(&mut self) {
        self.tls = None;
        if self.transport.take().is_some() {
            eprintln!("Sensor idle; releasing USB interface for runtime suspend");
        }
    }

    /// Drop both the USB handle and cached TLS session before S3 sleep (which cuts VBUS power
    /// and resets sensor SRAM).
    pub fn on_system_sleep(&mut self) {
        self.transport = None;
        self.tls = None;
    }

    pub async fn reconnect(&mut self) -> Result<(), String> {
        eprintln!("Reconnecting sensor hardware...");
        // Explicitly drop old endpoints and interface so kernel frees interface 0 immediately
        drop(self.transport.take());
        self.tls = None;

        let (transport, tls, calib_data, calib_vals, stg_id) =
            Self::connect(Some(Duration::from_secs(6))).await?;
        if stg_id != self.stg_id {
            self.user_cache.clear();
        }
        self.slept.store(false, Ordering::SeqCst);
        self.transport = Some(transport);
        self.tls = Some(tls);
        self.calib_data = calib_data;
        self.calib_vals = calib_vals;
        self.stg_id = stg_id;
        self.generation = self.generation.wrapping_add(1);
        eprintln!("Sensor hardware reconnected successfully! Windsor storage ID: {}", self.stg_id);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_some()
    }

    pub fn peek_cached_user(&self, uid: u32) -> Option<&Option<UserInfo>> {
        self.user_cache.get(&uid)
    }

    pub async fn ensure_connected(&mut self) -> Result<(), String> {
        if self.slept.swap(false, Ordering::SeqCst) {
            self.transport = None;
            self.tls = None;
        }

        // Quick probe if USB is already open: query sensor hardware type (0x75)
        if self.transport.is_some() {
            if self.send_app_cmd_once(&[0x75]).await.is_ok() {
                return Ok(());
            }
            eprintln!("Sensor connection check failed, attempting reconnect...");
            return self.reconnect().await;
        }

        self.reconnect().await
    }

    async fn open_usb_transport_once(drain_timeout: Duration) -> Result<UsbTransport, String> {
        let devices = nusb::list_devices().await
            .map_err(|e| format!("USB list failed: {}", e))?;

        let mut dev_info = None;
        for d in devices {
            if d.vendor_id() == 0x138a && d.product_id() == 0x0097 {
                dev_info = Some(d);
                break;
            }
        }

        let di = dev_info
            .ok_or_else(|| "Validity 138a:0097 sensor not found on USB bus".to_string())?;

        let dev = di.open().await
            .map_err(|e| format!("Failed to open USB device: {}", e))?;

        let iface = dev.claim_interface(0).await
            .map_err(|e| format!("Failed to claim interface 0: {}", e))?;

        let out_ep = iface.endpoint::<Bulk, Out>(0x01)
            .map_err(|e| format!("Failed to claim EP 0x01: {}", e))?;

        let mut in_ep = iface.endpoint::<Bulk, In>(0x81)
            .map_err(|e| format!("Failed to claim EP 0x81: {}", e))?;

        let int_ep = iface.endpoint::<Interrupt, In>(0x83)
            .map_err(|e| format!("Failed to claim EP 0x83: {}", e))?;

        // Drain any leftover pending data
        in_ep.submit(in_ep.allocate(64 * 1024));
        let _ = tokio::time::timeout(drain_timeout, in_ep.next_complete()).await;

        Ok(UsbTransport {
            _interface: iface,
            out_ep,
            in_ep,
            int_ep,
        })
    }

    async fn connect(timeout: Option<Duration>) -> Result<(UsbTransport, TlsSession, Vec<u8>, Vec<u8>, u16), String> {
        let timeout = timeout.unwrap_or(Duration::from_secs(5));
        let start = std::time::Instant::now();
        let mut last_err = "Validity 138a:0097 sensor not found on USB bus".to_string();

        while start.elapsed() < timeout {
            let mut transport = match Self::open_usb_transport_once(Duration::from_millis(50)).await {
                Ok(t) => t,
                Err(e) => {
                    last_err = e;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };
            let out_ep = &mut transport.out_ep;
            let in_ep = &mut transport.in_ep;

            let init_res: Result<(TlsSession, Vec<u8>, Vec<u8>, u16), String> = async {
                // 1. Ping / initialization
                let _ = Self::raw_usb_cmd(out_ep, in_ep, &[0x01], Duration::from_secs(3)).await?;
                let _ = Self::raw_usb_cmd(out_ep, in_ep, &[0x19], Duration::from_secs(3)).await?;
                let _ = Self::raw_usb_cmd(out_ep, in_ep, &[0x43, 0x02], Duration::from_secs(3)).await?;
                let _ = Self::raw_usb_cmd(out_ep, in_ep, INIT_HARDCODED, Duration::from_secs(5)).await?;

                // 2. Read Partition 1
                let mut read_p1_cmd = Vec::new();
                read_p1_cmd.push(0x40); // Read flash
                read_p1_cmd.push(0x01); // Partition 1
                read_p1_cmd.push(0x01); // 1
                read_p1_cmd.extend_from_slice(&0u16.to_le_bytes()); // 0
                read_p1_cmd.extend_from_slice(&0u32.to_le_bytes()); // addr = 0
                read_p1_cmd.extend_from_slice(&0x1000u32.to_le_bytes()); // size = 4096

                let p1_rsp = Self::raw_usb_cmd(out_ep, in_ep, &read_p1_cmd, Duration::from_secs(5)).await?;
                if p1_rsp.len() < 10 {
                    return Err("Partition 1 read truncated".into());
                }

                let hw = HwKeys::load();
                let mut host_priv = None;
                let mut device_ecdh = None;
                let mut tls_cert = Vec::new();

                let mut data = &p1_rsp[8..];
                while data.len() >= 36 {
                    let id = LittleEndian::read_u16(&data[0..2]);
                    let len = LittleEndian::read_u16(&data[2..4]) as usize;
                    data = &data[36..];
                    if id == 0xffff || len > data.len() {
                        break;
                    }
                    let body = &data[..len];
                    data = &data[len..];

                    match id {
                        3 => tls_cert = body.to_vec(),
                        4 => if let Ok(k) = decrypt_host_priv_key(&hw, body) { host_priv = Some(k); },
                        6 => if let Ok(k) = DeviceEcdhKey::parse(body) { device_ecdh = Some(k); },
                        _ => {}
                    }
                }

                let host_key = host_priv.ok_or_else(|| "Failed to decrypt host private key".to_string())?;
                let dev_key = device_ecdh.ok_or_else(|| "Failed to parse device ECDH key".to_string())?;

                // 3. TLS 1.2 Handshake
                let mut tls = TlsSession::new();
                let client_hello = tls.make_client_hello();
                let rsp_sh = Self::raw_usb_cmd(out_ep, in_ep, &client_hello, Duration::from_secs(10)).await?;
                tls.parse_tls_response(&rsp_sh).map_err(|e| e.to_string())?;

                let finish_pkt = tls.make_keys_and_finish(&dev_key, &host_key, &tls_cert)
                    .map_err(|e| e.to_string())?;
                let rsp_fin = Self::raw_usb_cmd(out_ep, in_ep, &finish_pkt, Duration::from_secs(10)).await?;
                tls.parse_tls_response(&rsp_fin).map_err(|e| e.to_string())?;

                // 4. Query Windsor Storage record ID
                let mut stg_cmd = vec![0x4b];
                stg_cmd.extend_from_slice(&0u16.to_le_bytes()); // dbid = 0
                let stg_name = b"StgWindsor\0";
                stg_cmd.extend_from_slice(&(stg_name.len() as u16).to_le_bytes());
                stg_cmd.extend_from_slice(stg_name);

                let app_stg = tls.make_app_data(&stg_cmd).map_err(|e| e.to_string())?;
                let rsp_stg = Self::raw_usb_cmd(out_ep, in_ep, &app_stg, Duration::from_secs(5)).await?;
                let dec_stg = tls.parse_tls_response(&rsp_stg).map_err(|e| e.to_string())?;
                let stg = parse_user_storage(&dec_stg)?
                    .ok_or_else(|| "StgWindsor storage not initialized on sensor".to_string())?;
                let stg_id = stg.dbid;

                // 5. Query Sensor Hardware Type (0x75)
                let _ = Self::raw_usb_cmd(out_ep, in_ep, &tls.make_app_data(&[0x75]).map_err(|e| e.to_string())?, Duration::from_secs(5)).await?;

                // 6. Query Factory Bits (0x6f, tag 0x0e00)
                let mut calib_data = Vec::new();
                let mut calib_vals = Vec::new();
                let mut fb_cmd = vec![0x6f];
                fb_cmd.extend_from_slice(&0x0e00u16.to_le_bytes());
                fb_cmd.extend_from_slice(&0u16.to_le_bytes());
                fb_cmd.extend_from_slice(&0u32.to_le_bytes());
                let app_fb = tls.make_app_data(&fb_cmd).map_err(|e| e.to_string())?;
                let rsp_fb = Self::raw_usb_cmd(out_ep, in_ep, &app_fb, Duration::from_secs(5)).await?;
                let dec_fb = tls.parse_tls_response(&rsp_fb).map_err(|e| e.to_string())?;

                let entries = if dec_fb.len() >= 10 { LittleEndian::read_u32(&dec_fb[6..10]) as usize } else { 0 };
                let mut fb_ptr = &dec_fb[10..];
                for _ in 0..entries {
                    if fb_ptr.len() < 12 { break; }
                    let len = LittleEndian::read_u16(&fb_ptr[4..6]) as usize;
                    let subtag = LittleEndian::read_u16(&fb_ptr[8..10]);
                    fb_ptr = &fb_ptr[12..];
                    if len > fb_ptr.len() { break; }
                    let val = &fb_ptr[..len];
                    fb_ptr = &fb_ptr[len..];
                    if subtag == 3 && calib_vals.is_empty() && val.len() >= 4 {
                        calib_vals = val[4..].to_vec();
                    } else if subtag == 7 && calib_data.is_empty() && val.len() >= 4 {
                        calib_data = val[4..].to_vec();
                    }
                }

                if calib_data.is_empty() || calib_vals.is_empty() {
                    return Err("Failed to extract sensor calibration factory bits".into());
                }

                Ok((tls, calib_data, calib_vals, stg_id))
            }.await;

            match init_res {
                Ok((tls, calib_data, calib_vals, stg_id)) => {
                    return Ok((transport, tls, calib_data, calib_vals, stg_id));
                }
                Err(e) => {
                    last_err = e;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }

        Err(format!("Sensor connection timed out: {}", last_err))
    }

    async fn raw_usb_cmd(
        out_ep: &mut nusb::Endpoint<Bulk, Out>,
        in_ep: &mut nusb::Endpoint<Bulk, In>,
        cmd: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        out_ep.submit(Buffer::from(cmd.to_vec()));
        let comp = tokio::time::timeout(timeout, out_ep.next_complete()).await
            .map_err(|_| format!("Timeout writing {} bytes to EP 0x01", cmd.len()))?;
        comp.into_result().map_err(|e| format!("USB Out failed: {}", e))?;

        // Reuse an already-pending IN transfer (e.g. the drain read issued at connect time)
        // instead of stacking another one behind it.
        if in_ep.pending() == 0 {
            in_ep.submit(in_ep.allocate(64 * 1024));
        }
        let comp = tokio::time::timeout(timeout, in_ep.next_complete()).await
            .map_err(|_| "Timeout reading response from EP 0x81".to_string())?;
        let buf = comp.into_result().map_err(|e| format!("USB In failed: {}", e))?;
        Ok(buf.to_vec())
    }

    /// One encrypted request/response round trip on an established connection.
    async fn exchange(
        transport: &mut UsbTransport,
        tls: &mut TlsSession,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let app_req = tls.make_app_data(payload).map_err(|e| e.to_string())?;
        let rsp = Self::raw_usb_cmd(&mut transport.out_ep, &mut transport.in_ep, &app_req, timeout).await?;
        tls.parse_tls_response(&rsp).map_err(|e| e.to_string())
    }

    /// Send a command exactly once. Use this for anything that mutates sensor state.
    ///
    /// On any failure the connection is dropped: a timed-out transfer may still be pending,
    /// or the sensor may deliver the late reply to the *next* request. Reconnecting is the
    /// only way to guarantee requests and responses stay paired.
    pub async fn send_app_cmd_once(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let (Some(transport), Some(tls)) = (self.transport.as_mut(), self.tls.as_mut()) else {
            return Err("Sensor device not connected".to_string());
        };
        let res = Self::exchange(transport, tls, payload, Duration::from_secs(5)).await;
        if res.is_err() {
            self.transport = None;
            self.tls = None;
        }
        res
    }

    /// Send an idempotent command, reconnecting and retrying once on failure.
    pub async fn send_app_cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if self.transport.is_none() {
            self.ensure_connected().await?;
        }
        match self.send_app_cmd_once(payload).await {
            Ok(dec) => Ok(dec),
            Err(msg) => {
                eprintln!("Sensor command failed ({}), reconnecting and retrying...", msg);
                self.reconnect().await?;
                self.send_app_cmd_once(payload).await
            }
        }
    }

    /// Wait for an interrupt. `Ok(None)` means the timeout elapsed.
    ///
    /// Exactly one interrupt transfer is kept outstanding; on timeout it stays queued and is
    /// picked up by the next call, so transfers never pile up and no interrupt is lost.
    pub async fn poll_int(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| "Sensor device not connected".to_string())?;
        if transport.int_ep.pending() == 0 {
            transport.int_ep.submit(transport.int_ep.allocate(1024));
        }
        let res = match tokio::time::timeout(timeout, transport.int_ep.next_complete()).await {
            Err(_) => return Ok(None),
            Ok(comp) => comp.into_result()
                .map(|buf| buf.to_vec())
                .map_err(|e| format!("USB Interrupt failed: {}", e)),
        };
        match res {
            Ok(buf) => Ok(Some(buf)),
            Err(e) => {
                self.transport = None;
                self.tls = None;
                Err(e)
            }
        }
    }

    pub async fn wait_int(&mut self, timeout: Duration) -> Result<Vec<u8>, String> {
        self.poll_int(timeout).await?
            .ok_or_else(|| "Timeout waiting for interrupt from EP 0x83".to_string())
    }

    pub async fn write_enable(&mut self) -> Result<(), String> {
        let rsp = self.send_app_cmd_once(DB_WRITE_ENABLE).await?;
        if rsp.len() >= 2 && LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err(format!("write_enable failed: 0x{:04x}", LittleEndian::read_u16(&rsp[0..2])));
        }
        Ok(())
    }

    pub async fn call_cleanups(&mut self) -> Result<(), String> {
        let rsp = self.send_app_cmd_once(&[0x1a]).await?;
        if rsp.len() >= 2 {
            let err = LittleEndian::read_u16(&rsp[0..2]);
            if err != 0 && err != 0x0491 {
                return Err(format!("call_cleanups error: 0x{:04x}", err));
            }
        }
        Ok(())
    }

    pub async fn led_glow(&mut self, on: bool) -> Result<(), String> {
        let cmd = if on {
            hex::decode(
                "3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ).map_err(|e| e.to_string())?
        } else {
            hex::decode(
                "39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ).map_err(|e| e.to_string())?
        };
        // LED state is cosmetic: never reconnect just to change it.
        let _ = self.send_app_cmd_once(&cmd).await?;
        Ok(())
    }

    /// Abort whatever the sensor is doing and turn the LED off. Never reconnects.
    pub async fn cancel_current(&mut self) -> Result<(), String> {
        if let (Some(transport), Some(tls)) = (self.transport.as_mut(), self.tls.as_mut()) {
            if Self::exchange(transport, tls, &[0x04], Duration::from_secs(1)).await.is_err() {
                self.transport = None;
                self.tls = None;
            }
        }
        if self.transport.is_some() {
            let _ = self.led_glow(false).await;
        }
        Ok(())
    }

    /// Run finger capture pipeline
    pub async fn capture(
        &mut self,
        mode: CaptureMode,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<(), CaptureError> {
        let cmd_02 = build_cmd_02(&self.calib_data, &self.calib_vals, mode);
        let rsp_02 = self.send_app_cmd(&cmd_02).await?;
        if rsp_02.len() >= 2 && LittleEndian::read_u16(&rsp_02[0..2]) != 0 {
            return Err(CaptureError::Device(format!(
                "cmd_02 returned status 0x{:04x}",
                LittleEndian::read_u16(&rsp_02[0..2])
            )));
        }

        // Wait for sensor start interrupt (type 0)
        let _ = self.wait_int(Duration::from_secs(3)).await?;

        // Turn on glow indicator
        self.led_glow(true).await?;

        let start_time = std::time::Instant::now();

        // Wait for touch (interrupt type 2), then capture complete (type 3 with b[2] & 4)
        for stage in 0..2 {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = self.cancel_current().await;
                    return Err(CaptureError::Cancelled);
                }
                if start_time.elapsed() >= timeout {
                    let _ = self.cancel_current().await;
                    return Err(CaptureError::Timeout);
                }
                // Device errors propagate immediately instead of spinning until the timeout
                if let Some(b) = self.poll_int(Duration::from_millis(300)).await? {
                    let done = if stage == 0 {
                        !b.is_empty() && b[0] == 2
                    } else {
                        b.len() >= 3 && b[0] == 3 && (b[2] & 4) != 0
                    };
                    if done {
                        break;
                    }
                }
            }
        }

        // Query PRG status2 (0x51). The capture lives in sensor RAM, so no reconnect/retry here.
        let stat_rsp = self.send_app_cmd_once(&[0x51, 0x00, 0x20, 0x00, 0x00]).await?;
        let _ = self.send_app_cmd_once(&[0x04]).await; // Stop capture

        if stat_rsp.len() >= 18 {
            let err = LittleEndian::read_u32(&stat_rsp[14..18]);
            if err != 0 {
                return Err(CaptureError::ScanProblem(err));
            }
        }

        Ok(())
    }

    /// Match captured finger against on-chip database
    pub async fn match_finger(&mut self) -> Result<(u32, u16), String> {
        // The captured image lives in sensor RAM; a reconnect would lose it, so no retries.
        let cmd = [0x5e, 2, 0xff, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        let _ = self.send_app_cmd_once(&cmd).await?;

        let b = self.wait_int(Duration::from_secs(4)).await?;
        if b.is_empty() || b[0] != 3 {
            let _ = self.send_app_cmd_once(&[0x62, 0, 0, 0, 0]).await;
            return Err("Finger not recognized".into());
        }

        // Query match results (0x60)
        let rsp = self.send_app_cmd_once(&[0x60, 0, 0, 0, 0]).await?;
        let _ = self.send_app_cmd_once(&[0x62, 0, 0, 0, 0]).await;

        if rsp.len() < 4 || LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err("Failed to query match results".into());
        }

        let l = LittleEndian::read_u16(&rsp[2..4]) as usize;
        let mut dict_data = &rsp[4..];
        if dict_data.len() > l {
            dict_data = &dict_data[..l];
        }

        let mut matched_uid: Option<u32> = None;
        let mut matched_subtype: Option<u16> = None;

        while dict_data.len() >= 4 {
            let tag = LittleEndian::read_u16(&dict_data[0..2]);
            let len = LittleEndian::read_u16(&dict_data[2..4]) as usize;
            dict_data = &dict_data[4..];
            if len > dict_data.len() { break; }
            let val = &dict_data[..len];
            dict_data = &dict_data[len..];

            if tag == 1 && val.len() >= 4 {
                matched_uid = Some(LittleEndian::read_u32(&val[0..4]));
            } else if tag == 3 && val.len() >= 2 {
                matched_subtype = Some(LittleEndian::read_u16(&val[0..2]));
            }
        }

        match (matched_uid, matched_subtype) {
            (Some(uid), Some(sub)) => Ok((uid, sub)),
            _ => Err("Invalid match result dictionary".into()),
        }
    }

    pub async fn create_enrollment(&mut self) -> Result<(), String> {
        let _ = self.send_app_cmd(&[0x69, 1, 0, 0, 0]).await?;
        Ok(())
    }

    // Enrollment state lives on the sensor and is lost on reconnect, so the remaining
    // enrollment commands are never retried.
    pub async fn enrollment_update_end(&mut self) -> Result<(), String> {
        let _ = self.send_app_cmd_once(&[0x69, 0, 0, 0, 0]).await?;
        Ok(())
    }

    pub async fn enrollment_update_start(&mut self, key: u32) -> Result<u32, String> {
        let mut req = vec![0x68];
        req.extend_from_slice(&key.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());

        let rsp = self.send_app_cmd_once(&req).await?;
        if rsp.len() < 6 || LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err("enrollment_update_start failed".into());
        }
        let new_key = LittleEndian::read_u32(&rsp[2..6]);
        let _ = self.wait_int(Duration::from_secs(3)).await?;
        Ok(new_key)
    }

    pub async fn enrollment_update(&mut self, prev: &[u8]) -> Result<Vec<u8>, String> {
        self.write_enable().await?;
        let mut req = vec![0x6b];
        req.extend_from_slice(prev);
        let res = self.send_app_cmd_once(&req).await;
        let _ = self.call_cleanups().await;
        let rsp = res?;
        if rsp.len() < 2 || LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err("enrollment_update failed".into());
        }
        Ok(rsp[2..].to_vec())
    }

    pub async fn append_new_image(
        &mut self,
        prev: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>), String> {
        let _ = self.enrollment_update(prev).await?;
        let _ = self.wait_int(Duration::from_secs(4)).await?;
        let res = self.enrollment_update(prev).await?;

        if res.len() < 2 {
            return Err("append_new_image response too short".into());
        }

        let l = LittleEndian::read_u16(&res[0..2]) as usize;
        let mut payload = &res[2..];
        if payload.len() != l {
            return Err(format!("append_new_image size mismatch: {} != {}", l, payload.len()));
        }

        let magic_len = 0x38usize;
        let mut template = Vec::new();
        let mut header = Vec::new();
        let mut tid = None;

        while payload.len() >= 4 {
            let tag = LittleEndian::read_u16(&payload[0..2]);
            let chunk_len = LittleEndian::read_u16(&payload[2..4]) as usize;
            if magic_len + chunk_len > payload.len() {
                break;
            }

            if tag == 0 {
                template = payload[..magic_len + chunk_len].to_vec();
            } else if tag == 1 {
                header = payload[magic_len..magic_len + chunk_len].to_vec();
            } else if tag == 3 {
                tid = Some(payload[magic_len..magic_len + chunk_len].to_vec());
            }

            payload = &payload[magic_len + chunk_len..];
        }

        Ok((header, template, tid))
    }

    pub async fn new_record(
        &mut self,
        parent: u16,
        typ: u16,
        storage: u16,
        data: &[u8],
    ) -> Result<u16, String> {
        self.user_cache.clear();
        self.write_enable().await?;
        let mut req = vec![0x47];
        req.extend_from_slice(&parent.to_le_bytes());
        req.extend_from_slice(&typ.to_le_bytes());
        req.extend_from_slice(&storage.to_le_bytes());
        req.extend_from_slice(&(data.len() as u16).to_le_bytes());
        req.extend_from_slice(data);

        let res = self.send_app_cmd_once(&req).await;
        let _ = self.call_cleanups().await;
        let rsp = res?;

        if rsp.len() < 4 || LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err(format!("new_record failed: status 0x{:04x}", LittleEndian::read_u16(&rsp[0..2])));
        }

        Ok(LittleEndian::read_u16(&rsp[2..4]))
    }

    pub async fn lookup_user_uncached(&mut self, uid: u32) -> Result<Option<UserInfo>, String> {
        let identity = uid_to_identity_bytes(uid);
        let mut req = vec![0x4a, 0x00, 0x00];
        req.extend_from_slice(&self.stg_id.to_le_bytes());
        req.extend_from_slice(&(identity.len() as u16).to_le_bytes());
        req.extend_from_slice(&identity);

        let rsp = self.send_app_cmd(&req).await?;
        let parsed = if rsp.len() >= 2 && LittleEndian::read_u16(&rsp[0..2]) == 0x04b3 {
            None
        } else {
            Some(parse_user(&rsp)?)
        };
        self.user_cache.insert(uid, parsed.clone());
        Ok(parsed)
    }

    pub async fn lookup_user(&mut self, uid: u32) -> Result<Option<UserInfo>, String> {
        if let Some(cached) = self.user_cache.get(&uid) {
            return Ok(cached.clone());
        }
        self.lookup_user_uncached(uid).await
    }

    pub async fn new_user(&mut self, uid: u32) -> Result<u16, String> {
        let identity = uid_to_identity_bytes(uid);
        self.new_record(self.stg_id, 5, self.stg_id, &identity).await
    }

    pub async fn save_finger(
        &mut self,
        user_dbid: u16,
        subtype: u16,
        template: &[u8],
        tid: &[u8],
    ) -> Result<u16, String> {
        let tinfo = make_finger_data(subtype, template, tid);
        let recid = self.new_record(user_dbid, 0x000b, self.stg_id, &tinfo).await?;
        let _ = self.wait_int(Duration::from_secs(3)).await?;
        self.user_cache.clear();
        Ok(recid)
    }

    pub async fn del_record(&mut self, recid: u16) -> Result<(), String> {
        self.user_cache.clear();
        self.write_enable().await?;
        let mut req = vec![0x48];
        req.extend_from_slice(&recid.to_le_bytes());
        let res = self.send_app_cmd_once(&req).await;
        let _ = self.call_cleanups().await;
        let rsp = res?;
        if rsp.len() >= 2 && LittleEndian::read_u16(&rsp[0..2]) != 0 {
            return Err(format!("del_record failed: 0x{:04x}", LittleEndian::read_u16(&rsp[0..2])));
        }
        Ok(())
    }

    pub async fn del_finger(&mut self, uid: u32, subtype: u16) -> Result<bool, String> {
        let user_info = match self.lookup_user_uncached(uid).await? {
            Some(u) => u,
            None => return Ok(false),
        };
        for f in &user_info.fingers {
            if f.subtype == subtype {
                self.del_record(f.dbid).await?;
                // If this was the user's only enrolled finger, remove the user record too
                if user_info.fingers.len() == 1 {
                    let _ = self.del_record(user_info.dbid).await;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn del_user(&mut self, user_dbid: u16) -> Result<(), String> {
        self.del_record(user_dbid).await
    }

    pub async fn list_enrolled_fingers(&mut self, uid: u32) -> Result<Vec<String>, String> {
        let usr = match self.lookup_user(uid).await? {
            Some(u) => u,
            None => return Ok(Vec::new()),
        };

        let list = usr.fingers.into_iter()
            .map(|f| finger_id_to_name(f.subtype).to_string())
            .collect();
        Ok(list)
    }
}
