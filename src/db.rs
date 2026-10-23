#![allow(dead_code)]
use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug, Clone)]
pub struct FingerRecord {
    pub dbid: u16,
    pub subtype: u16,
    pub storage: u16,
    pub value_size: u16,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub dbid: u16,
    pub uid: Option<u32>,
    pub fingers: Vec<FingerRecord>,
}

#[derive(Debug, Clone)]
pub struct UserStorage {
    pub dbid: u16,
    pub name: String,
    pub users: Vec<UserStorageEntry>,
}

#[derive(Debug, Clone)]
pub struct UserStorageEntry {
    pub dbid: u16,
    pub value_size: u16,
}

/// Convert Linux UID into Windows SID identity bytes for on-chip Windsor storage
pub fn uid_to_identity_bytes(uid: u32) -> Vec<u8> {
    let mut sid = Vec::with_capacity(28);
    sid.push(1); // revision 1
    sid.push(5); // 5 sub-authorities
    sid.extend_from_slice(&0u16.to_be_bytes()); // auth high 16 = 0
    sid.extend_from_slice(&5u32.to_be_bytes()); // auth low 32 = 5 (SECURITY_NT_AUTHORITY)
    sid.extend_from_slice(&21u32.to_le_bytes()); // SECURITY_NT_NON_UNIQUE
    sid.extend_from_slice(&111111111u32.to_le_bytes());
    sid.extend_from_slice(&1111111111u32.to_le_bytes());
    sid.extend_from_slice(&1111111111u32.to_le_bytes());
    sid.extend_from_slice(&uid.to_le_bytes());

    let mut out = Vec::with_capacity(0x4c);
    out.extend_from_slice(&3u32.to_le_bytes()); // type 3 = SID
    out.extend_from_slice(&(sid.len() as u32).to_le_bytes()); // len = 28
    out.extend_from_slice(&sid);
    while out.len() < 0x4c {
        out.push(0);
    }
    out
}

/// Parse Windows SID identity bytes back to Linux UID
pub fn identity_bytes_to_uid(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 8 {
        return None;
    }
    let typ = LittleEndian::read_u32(&bytes[0..4]);
    if typ != 3 {
        return None;
    }
    let len = LittleEndian::read_u32(&bytes[4..8]) as usize;
    if bytes.len() < 8 + len || len < 8 {
        return None;
    }
    let sid = &bytes[8..8 + len];
    let subcnt = sid[1] as usize;
    if sid.len() < 8 + subcnt * 4 || subcnt == 0 {
        return None;
    }
    let last_offset = 8 + (subcnt - 1) * 4;
    Some(LittleEndian::read_u32(&sid[last_offset..last_offset + 4]))
}

/// Pack finger template and tid into Windsor tinfo payload
pub fn make_finger_data(subtype: u16, template: &[u8], tid: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&(template.len() as u16).to_le_bytes());
    payload.extend_from_slice(template);

    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&(tid.len() as u16).to_le_bytes());
    payload.extend_from_slice(tid);

    let mut tinfo = Vec::new();
    tinfo.extend_from_slice(&subtype.to_le_bytes());
    tinfo.extend_from_slice(&3u16.to_le_bytes());
    tinfo.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    tinfo.extend_from_slice(&0x20u16.to_le_bytes());
    tinfo.extend_from_slice(&payload);
    tinfo.resize(tinfo.len() + 0x20, 0); // 32 trailing zeros
    tinfo
}

pub fn parse_user_storage(rsp: &[u8]) -> Result<Option<UserStorage>, String> {
    if rsp.len() < 2 {
        return Err("Response too short".into());
    }
    let status = LittleEndian::read_u16(&rsp[0..2]);
    if status == 0x04b3 {
        return Ok(None);
    }
    if status != 0 {
        return Err(format!("Storage query failed with status 0x{:04x}", status));
    }
    let rsp = &rsp[2..];
    if rsp.len() < 8 {
        return Err("Storage header too short".into());
    }
    let recid = LittleEndian::read_u16(&rsp[0..2]);
    let usercnt = LittleEndian::read_u16(&rsp[2..4]) as usize;
    let namesz = LittleEndian::read_u16(&rsp[4..6]) as usize;

    let mut data = &rsp[8..];
    if data.len() < 4 * usercnt + namesz {
        return Err("Storage payload truncated".into());
    }

    let mut users = Vec::with_capacity(usercnt);
    for _ in 0..usercnt {
        let urid = LittleEndian::read_u16(&data[0..2]);
        let valsz = LittleEndian::read_u16(&data[2..4]);
        users.push(UserStorageEntry { dbid: urid, value_size: valsz });
        data = &data[4..];
    }

    let name_bytes = &data[..namesz];
    let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();

    Ok(Some(UserStorage { dbid: recid, name, users }))
}

pub fn parse_user(rsp: &[u8]) -> Result<UserInfo, String> {
    if rsp.len() < 2 {
        return Err("User response too short".into());
    }
    let status = LittleEndian::read_u16(&rsp[0..2]);
    if status != 0 {
        return Err(format!("User query failed with status 0x{:04x}", status));
    }
    let rsp = &rsp[2..];
    if rsp.len() < 8 {
        return Err("User header truncated".into());
    }
    let recid = LittleEndian::read_u16(&rsp[0..2]);
    let fingercnt = LittleEndian::read_u16(&rsp[2..4]) as usize;
    let identitysz = LittleEndian::read_u16(&rsp[6..8]) as usize;

    let mut data = &rsp[8..];
    if data.len() < 8 * fingercnt + identitysz {
        return Err("User data truncated".into());
    }

    let mut fingers = Vec::with_capacity(fingercnt);
    for _ in 0..fingercnt {
        let frid = LittleEndian::read_u16(&data[0..2]);
        let subtype = LittleEndian::read_u16(&data[2..4]);
        let storage = LittleEndian::read_u16(&data[4..6]);
        let valsz = LittleEndian::read_u16(&data[6..8]);
        fingers.push(FingerRecord {
            dbid: frid,
            subtype,
            storage,
            value_size: valsz,
        });
        data = &data[8..];
    }

    let identity_bytes = &data[..identitysz];
    let uid = identity_bytes_to_uid(identity_bytes);

    Ok(UserInfo { dbid: recid, uid, fingers })
}

pub fn finger_id_to_name(id: u16) -> &'static str {
    match id {
        1 => "right-thumb",
        2 => "right-index-finger",
        3 => "right-middle-finger",
        4 => "right-ring-finger",
        5 => "right-little-finger",
        6 => "left-thumb",
        7 => "left-index-finger",
        8 => "left-middle-finger",
        9 => "left-ring-finger",
        10 => "left-little-finger",
        _ => "unknown",
    }
}

pub fn finger_name_to_id(name: &str) -> Option<u16> {
    match name {
        "right-thumb" => Some(1),
        "right-index-finger" => Some(2),
        "right-middle-finger" => Some(3),
        "right-ring-finger" => Some(4),
        "right-little-finger" => Some(5),
        "left-thumb" => Some(6),
        "left-index-finger" => Some(7),
        "left-middle-finger" => Some(8),
        "left-ring-finger" => Some(9),
        "left-little-finger" => Some(10),
        "any" => Some(0),
        _ => None,
    }
}
