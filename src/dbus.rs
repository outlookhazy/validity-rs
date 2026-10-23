use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use zbus::fdo::DBusProxy;
use zbus::object_server::SignalEmitter;
use zbus::OwnedObjectPath;
use zbus::{interface, DBusError};

use crate::db::finger_name_to_id;
use crate::sensor::{CaptureMode, SensorDriver};

#[derive(Debug, DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
pub enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    AlreadyInUse(String),
    ClaimDevice(String),
    PermissionDenied(String),
    NoSuchDevice(String),
    NoEnrolledPrints(String),
    Internal(String),
}

pub fn username_to_uid(username: &str) -> Option<u32> {
    if username.is_empty() {
        return None;
    }
    let c_user = std::ffi::CString::new(username).ok()?;
    let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pwd.is_null() {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[0] == username {
                return parts[2].parse().ok();
            }
        }
        None
    } else {
        Some(unsafe { (*pwd).pw_uid as u32 })
    }
}

pub fn uid_to_username(uid: u32) -> Option<String> {
    let pwd = unsafe { libc::getpwuid(uid as libc::uid_t) };
    if pwd.is_null() {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
                return Some(parts[0].to_string());
            }
        }
        None
    } else {
        let name = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_name) };
        name.to_str().ok().map(|s| s.to_string())
    }
}

async fn get_caller_info(
    conn: &zbus::Connection,
    hdr: &zbus::message::Header<'_>,
) -> Result<(String, u32), FprintError> {
    let sender = hdr.sender().ok_or_else(|| FprintError::PermissionDenied("No message sender".into()))?;
    let dbus = DBusProxy::new(conn).await
        .map_err(|e| FprintError::Internal(format!("Failed to connect to D-Bus daemon: {}", e)))?;
    let bus_name = zbus::names::BusName::try_from(sender.as_str())
        .map_err(|e| FprintError::Internal(format!("Invalid bus name: {}", e)))?;
    let uid = dbus.get_connection_unix_user(bus_name).await
        .map_err(|e| FprintError::PermissionDenied(format!("Failed to get caller UID: {}", e)))?;
    Ok((sender.as_str().to_string(), uid))
}

pub struct FprintManager {
    pub device_path: OwnedObjectPath,
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl FprintManager {
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![self.device_path.clone()]
    }

    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        Ok(self.device_path.clone())
    }
}

#[derive(Clone, Debug)]
pub struct Claim {
    pub sender: String,
    pub username: String,
    pub uid: u32,
}

pub struct FprintDevice {
    pub driver: Arc<Mutex<SensorDriver>>,
    pub claimed_by: Arc<std::sync::Mutex<Option<Claim>>>,
    pub current_cancel: Arc<std::sync::Mutex<Option<Arc<AtomicBool>>>>,
}

impl FprintDevice {
    pub fn new(driver: Arc<Mutex<SensorDriver>>) -> Self {
        Self {
            driver,
            claimed_by: Arc::new(std::sync::Mutex::new(None)),
            current_cancel: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl FprintDevice {
    // --- Properties ---
    #[zbus(property, name = "name")]
    async fn name(&self) -> String {
        "Validity VFS0097 Fingerprint Reader".to_string()
    }

    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        7
    }

    #[zbus(property, name = "scan-type")]
    async fn scan_type(&self) -> String {
        "press".to_string()
    }

    #[zbus(property, name = "finger-presence")]
    async fn finger_presence(&self) -> bool {
        false
    }

    // --- Signals ---
    #[zbus(signal)]
    async fn enroll_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_finger_selected(
        emitter: &SignalEmitter<'_>,
        finger: &str,
    ) -> zbus::Result<()>;

    // --- Methods ---
    async fn claim(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: &str,
    ) -> Result<(), FprintError> {
        let (caller_sender, caller_uid) = get_caller_info(conn, &hdr).await?;
        let (target_user, target_uid) = if username.is_empty() {
            let u = uid_to_username(caller_uid)
                .ok_or_else(|| FprintError::Internal(format!("Cannot resolve username for caller UID {}", caller_uid)))?;
            (u, caller_uid)
        } else {
            let uid = username_to_uid(username)
                .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", username)))?;
            (username.to_string(), uid)
        };

        if caller_uid != 0 && caller_uid != target_uid {
            return Err(FprintError::PermissionDenied(format!(
                "Caller UID {} is not authorized to claim device for user {}",
                caller_uid, target_user
            )));
        }

        let mut claim_guard = self.claimed_by.lock().unwrap();
        if let Some(ref current) = *claim_guard {
            if current.sender != caller_sender || current.uid != target_uid {
                return Err(FprintError::AlreadyInUse("Device is already claimed".into()));
            }
        }

        *claim_guard = Some(Claim {
            sender: caller_sender,
            username: target_user,
            uid: target_uid,
        });
        Ok(())
    }

    async fn release(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> Result<(), FprintError> {
        let (caller_sender, caller_uid) = get_caller_info(conn, &hdr).await?;
        let mut claim_guard = self.claimed_by.lock().unwrap();
        if let Some(ref current) = *claim_guard {
            if caller_uid != 0 && current.sender != caller_sender {
                return Err(FprintError::PermissionDenied("Cannot release device claimed by another caller".into()));
            }
        }
        *claim_guard = None;

        if let Some(cancel) = self.current_cancel.lock().unwrap().take() {
            cancel.store(true, Ordering::Relaxed);
        }

        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
            let _ = d.led_glow(false).await;
        });
        Ok(())
    }

    async fn list_enrolled_fingers(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: &str,
    ) -> Result<Vec<String>, FprintError> {
        let (_caller_sender, caller_uid) = get_caller_info(conn, &hdr).await?;
        let (target_user, target_uid) = if username.is_empty() {
            let u = uid_to_username(caller_uid)
                .ok_or_else(|| FprintError::Internal(format!("Cannot resolve username for caller UID {}", caller_uid)))?;
            (u, caller_uid)
        } else {
            let uid = username_to_uid(username)
                .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", username)))?;
            (username.to_string(), uid)
        };

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        let fingers = driver.list_enrolled_fingers(target_uid).await
            .map_err(|e| FprintError::Internal(e.to_string()))?;

        if fingers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!("No enrolled prints for user {}", target_user)));
        }
        Ok(fingers)
    }

    async fn delete_enrolled_fingers(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: &str,
    ) -> Result<(), FprintError> {
        let (_caller_sender, caller_uid) = get_caller_info(conn, &hdr).await?;
        let (target_user, target_uid) = if username.is_empty() {
            let u = uid_to_username(caller_uid)
                .ok_or_else(|| FprintError::Internal(format!("Cannot resolve username for caller UID {}", caller_uid)))?;
            (u, caller_uid)
        } else {
            let uid = username_to_uid(username)
                .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", username)))?;
            (username.to_string(), uid)
        };

        if caller_uid != 0 && caller_uid != target_uid {
            return Err(FprintError::PermissionDenied(format!(
                "Caller UID {} is not authorized to delete prints for user {}",
                caller_uid, target_user
            )));
        }

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        if let Some(user_info) = driver.lookup_user(target_uid).await.map_err(|e| FprintError::Internal(e.to_string()))? {
            driver.del_user(user_info.dbid).await.map_err(|e| FprintError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete_enrolled_fingers2(&self) -> Result<(), FprintError> {
        let claim = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        if let Some(user_info) = driver.lookup_user(claim.uid).await.map_err(|e| FprintError::Internal(e.to_string()))? {
            driver.del_user(user_info.dbid).await.map_err(|e| FprintError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete_enrolled_finger(&self, finger_name: &str) -> Result<(), FprintError> {
        let claim = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };
        let subtype = finger_name_to_id(finger_name)
            .ok_or_else(|| FprintError::Internal(format!("Unknown finger name: {}", finger_name)))?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        let deleted = driver.del_finger(claim.uid, subtype).await
            .map_err(|e| FprintError::Internal(e.to_string()))?;
        if !deleted {
            return Err(FprintError::Internal(format!("Finger {} was not enrolled", finger_name)));
        }
        Ok(())
    }

    async fn verify_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let claim = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };

        // Synchronously verify user has enrolled prints
        {
            let mut d = self.driver.lock().await;
            d.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
            let user_info = d.lookup_user(claim.uid).await.map_err(|e| FprintError::Internal(e.to_string()))?;
            match user_info {
                Some(u) if !u.fingers.is_empty() => (),
                _ => {
                    return Err(FprintError::NoEnrolledPrints(format!("No enrolled prints for user {}", claim.username)));
                }
            }
        }

        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut c_guard = self.current_cancel.lock().unwrap();
            if let Some(old) = c_guard.replace(cancel.clone()) {
                old.store(true, Ordering::Relaxed);
            }
        }

        let driver = self.driver.clone();
        let emitter_clone = emitter.to_owned();
        let selected_finger = if finger_name.is_empty() { "any" } else { finger_name }.to_string();
        let uid = claim.uid;

        tokio::spawn(async move {
            // Give D-Bus method reply a moment to reach PAM so data->verify_started = true
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = Self::verify_finger_selected(&emitter_clone, &selected_finger).await;

            let mut d = driver.lock().await;

            let user_info = match d.lookup_user(uid).await {
                Ok(Some(u)) if !u.fingers.is_empty() => u,
                _ => {
                    let _ = Self::verify_status(&emitter_clone, "verify-no-match", true).await;
                    return;
                }
            };

            // Loop to allow retries on swipe / touch errors or wrong finger brushes
            let mut attempts = 0;
            const MAX_ATTEMPTS: u32 = 3;

            while !cancel.load(Ordering::Relaxed) && attempts < MAX_ATTEMPTS {
                match d.capture(CaptureMode::Identify, &cancel, Duration::from_secs(15)).await {
                    Ok(()) => {
                        // Capture succeeded, match against on-chip database
                        match d.match_finger().await {
                            Ok((matched_uid, _subtype)) => {
                                // Tag 1 returned by the chip is the Windsor user record dbid
                                if matched_uid == (user_info.dbid as u32) {
                                    let _ = d.led_glow(false).await;
                                    let _ = Self::verify_status(&emitter_clone, "verify-match", true).await;
                                    break;
                                } else {
                                    attempts += 1;
                                    let done = attempts >= MAX_ATTEMPTS;
                                    if done {
                                        let _ = d.led_glow(false).await;
                                    }
                                    let _ = Self::verify_status(&emitter_clone, "verify-no-match", done).await;
                                    if !done {
                                        tokio::time::sleep(Duration::from_millis(500)).await;
                                    }
                                }
                            }
                            Err(_) => {
                                attempts += 1;
                                let done = attempts >= MAX_ATTEMPTS;
                                if done {
                                    let _ = d.led_glow(false).await;
                                }
                                let _ = Self::verify_status(&emitter_clone, "verify-no-match", done).await;
                                if !done {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if cancel.load(Ordering::Relaxed) {
                            let _ = d.cancel_current().await;
                            break;
                        }
                        if e.to_string().contains("scanning problem") {
                            let _ = Self::verify_status(&emitter_clone, "verify-retry-scan", false).await;
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        } else {
                            let _ = d.cancel_current().await;
                            let _ = Self::verify_status(&emitter_clone, "verify-unknown-error", true).await;
                            break;
                        }
                    }
                }
            }
            let _ = d.led_glow(false).await;
        });

        Ok(())
    }

    async fn verify_stop(&self) -> Result<(), FprintError> {
        if let Some(cancel) = self.current_cancel.lock().unwrap().take() {
            cancel.store(true, Ordering::Relaxed);
        }
        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
        });
        Ok(())
    }

    async fn enroll_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let claim = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };

        let subtype = finger_name_to_id(finger_name)
            .unwrap_or(2); // default right-index-finger

        {
            let mut d = self.driver.lock().await;
            d.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        }

        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut c_guard = self.current_cancel.lock().unwrap();
            if let Some(old) = c_guard.replace(cancel.clone()) {
                old.store(true, Ordering::Relaxed);
            }
        }

        let driver = self.driver.clone();
        let emitter_clone = emitter.to_owned();
        let uid = claim.uid;

        tokio::spawn(async move {
            let mut d = driver.lock().await;

            if let Err(_) = d.create_enrollment().await {
                let _ = Self::enroll_status(&emitter_clone, "enroll-unknown-error", true).await;
                return;
            }

            let mut key = 0u32;
            let mut template = Vec::new();
            let mut final_tid = None;

            while !cancel.load(Ordering::Relaxed) {
                match d.capture(CaptureMode::Enroll, &cancel, Duration::from_secs(15)).await {
                    Ok(()) => {
                        let new_key = match d.enrollment_update_start(key).await {
                            Ok(k) => k,
                            Err(_) => {
                                let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                                continue;
                            }
                        };
                        key = new_key;

                        let (_header, new_template, tid) = match d.append_new_image(&template).await {
                            Ok(res) => res,
                            Err(_) => {
                                let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                                continue;
                            }
                        };
                        template = new_template;

                        if let Some(t) = tid {
                            final_tid = Some(t);
                            let _ = Self::enroll_status(&emitter_clone, "enroll-stage-passed", false).await;
                            break;
                        } else {
                            let _ = Self::enroll_status(&emitter_clone, "enroll-stage-passed", false).await;
                        }
                    }
                    Err(e) => {
                        if cancel.load(Ordering::Relaxed) {
                            let _ = d.cancel_current().await;
                            break;
                        }
                        if e.to_string().contains("scanning problem") {
                            let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        } else {
                            let _ = d.cancel_current().await;
                            let _ = Self::enroll_status(&emitter_clone, "enroll-unknown-error", true).await;
                            break;
                        }
                    }
                }
            }

            let _ = d.enrollment_update_end().await;

            if let Some(tid) = final_tid {
                // Find or create user on chip
                let user_id = match d.lookup_user(uid).await {
                    Ok(Some(u)) => u.dbid,
                    _ => match d.new_user(uid).await {
                        Ok(id) => id,
                        Err(_) => {
                            let _ = d.led_glow(false).await;
                            let _ = Self::enroll_status(&emitter_clone, "enroll-data-full", true).await;
                            return;
                        }
                    },
                };

                match d.save_finger(user_id, subtype, &template, &tid).await {
                    Ok(_) => {
                        let _ = d.led_glow(false).await;
                        let _ = Self::enroll_status(&emitter_clone, "enroll-completed", true).await;
                    }
                    Err(_) => {
                        let _ = d.led_glow(false).await;
                        let _ = Self::enroll_status(&emitter_clone, "enroll-data-full", true).await;
                    }
                }
            } else {
                let _ = d.cancel_current().await;
            }
        });

        Ok(())
    }

    async fn enroll_stop(&self) -> Result<(), FprintError> {
        if let Some(cancel) = self.current_cancel.lock().unwrap().take() {
            cancel.store(true, Ordering::Relaxed);
        }
        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
        });
        Ok(())
    }
}
