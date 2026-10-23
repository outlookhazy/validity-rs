use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use zbus::fdo::DBusProxy;
use zbus::object_server::SignalEmitter;
use zbus::OwnedObjectPath;
use zbus::{interface, DBusError};

use crate::db::finger_name_to_id;
use crate::sensor::{CaptureError, CaptureMode, SensorDriver};

/// How long a single capture arms the sensor before re-arming. Clients (pam_fprintd, lock
/// screens) own the overall timeout, exactly like fprintd, so this is not a user-visible limit.
const CAPTURE_WINDOW: Duration = Duration::from_secs(10);
/// Consecutive device failures tolerated (with reconnects) before reporting an error.
const MAX_DEVICE_FAILURES: u32 = 3;

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
    InvalidFingername(String),
    Internal(String),
}

fn passwd_buf_len() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if n > 0 { n as usize } else { 16 * 1024 }
}

/// Thread-safe passwd lookup (getpwnam/getpwuid return a shared static buffer and must not be
/// called concurrently from tokio worker threads). Goes through NSS, so SSSD/LDAP users work.
fn lookup_passwd<T>(
    mut call: impl FnMut(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> libc::c_int,
    extract: impl Fn(&libc::passwd) -> Option<T>,
) -> Option<T> {
    let mut buf: Vec<libc::c_char> = vec![0; passwd_buf_len()];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = call(&mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            let new_len = buf.len() * 2;
            buf.resize(new_len, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return extract(&pwd);
    }
}

pub fn username_to_uid(username: &str) -> Option<u32> {
    if username.is_empty() {
        return None;
    }
    let c_user = std::ffi::CString::new(username).ok()?;
    lookup_passwd(
        |pwd, buf, len, result| unsafe { libc::getpwnam_r(c_user.as_ptr(), pwd, buf, len, result) },
        |pwd| Some(pwd.pw_uid as u32),
    )
}

pub fn uid_to_username(uid: u32) -> Option<String> {
    lookup_passwd(
        |pwd, buf, len, result| unsafe { libc::getpwuid_r(uid as libc::uid_t, pwd, buf, len, result) },
        |pwd| {
            if pwd.pw_name.is_null() {
                return None;
            }
            let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
            name.to_str().ok().map(|s| s.to_string())
        },
    )
}

fn caller_sender(hdr: &zbus::message::Header<'_>) -> Result<String, FprintError> {
    hdr.sender()
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| FprintError::PermissionDenied("No message sender".into()))
}

async fn get_caller_info(
    conn: &zbus::Connection,
    hdr: &zbus::message::Header<'_>,
) -> Result<(String, u32), FprintError> {
    let sender = caller_sender(hdr)?;
    let dbus = DBusProxy::new(conn).await
        .map_err(|e| FprintError::Internal(format!("Failed to connect to D-Bus daemon: {}", e)))?;
    let bus_name = zbus::names::BusName::try_from(sender.as_str())
        .map_err(|e| FprintError::Internal(format!("Invalid bus name: {}", e)))?;
    let uid = dbus.get_connection_unix_user(bus_name).await
        .map_err(|e| FprintError::PermissionDenied(format!("Failed to get caller UID: {}", e)))?;
    Ok((sender, uid))
}

/// Resolve the target user ("" means the caller) and enforce that non-root callers can only
/// act on their own account.
fn resolve_target_user(caller_uid: u32, username: &str, action: &str) -> Result<(String, u32), FprintError> {
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
            "Caller UID {} is not authorized to {} for user {}",
            caller_uid, action, target_user
        )));
    }
    Ok((target_user, target_uid))
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

#[derive(Clone)]
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

    /// Return the active claim, but only if it belongs to `sender`. Every claim-scoped method
    /// goes through this, so one client can never drive another client's claim (e.g. enroll a
    /// finger into root's record while `sudo` holds the device).
    fn claim_for(&self, sender: &str) -> Result<Claim, FprintError> {
        let claimed = self.claimed_by.lock().unwrap();
        match claimed.as_ref() {
            None => {
                eprintln!("Rejected call from {}: device not claimed", sender);
                Err(FprintError::ClaimDevice("Client must claim device first".into()))
            }
            Some(c) if c.sender != sender => {
                eprintln!("Rejected call from {}: device claimed by {}", sender, c.sender);
                Err(FprintError::AlreadyInUse("Device is claimed by another client".into()))
            }
            Some(c) => Ok(c.clone()),
        }
    }

    /// Signal the running verify/enroll task (if any) to stop. Non-blocking.
    pub fn signal_cancel(&self) {
        if let Some(cancel) = self.current_cancel.lock().unwrap().take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Install a fresh cancel flag for a new operation, cancelling any previous one first.
    fn begin_operation(&self) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        if let Some(old) = self.current_cancel.lock().unwrap().replace(cancel.clone()) {
            old.store(true, Ordering::Relaxed);
        }
        cancel
    }

    /// Cancel the current operation and reset the sensor in the background.
    fn stop_operation(&self) {
        self.signal_cancel();
        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
        });
    }

    /// Called when a bus name loses its owner. If the claim holder vanished without calling
    /// Release (crash, Ctrl-C at a sudo prompt, ...), free the device so it is not stuck.
    pub fn client_vanished(&self, name: &str) {
        let released = {
            let mut claimed = self.claimed_by.lock().unwrap();
            if claimed.as_ref().is_some_and(|c| c.sender == name) {
                *claimed = None;
                true
            } else {
                false
            }
        };
        if released {
            eprintln!("Claim holder {} disconnected without releasing the device; releasing it", name);
            self.stop_operation();
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
        let (target_user, target_uid) = resolve_target_user(caller_uid, username, "claim device")
            .inspect_err(|_| eprintln!("Claim by {} (uid {}) for '{}' denied", caller_sender, caller_uid, username))?;

        let mut claim_guard = self.claimed_by.lock().unwrap();
        if let Some(ref current) = *claim_guard {
            if current.sender != caller_sender || current.uid != target_uid {
                eprintln!("Claim by {} for {} refused: already claimed by {}", caller_sender, target_user, current.sender);
                return Err(FprintError::AlreadyInUse("Device is already claimed".into()));
            }
        }

        eprintln!("Claim by {} (uid {}) for {}", caller_sender, caller_uid, target_user);
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
    ) -> Result<(), FprintError> {
        let sender = caller_sender(&hdr)?;
        self.claim_for(&sender)?;
        eprintln!("Release by {}", sender);
        *self.claimed_by.lock().unwrap() = None;
        self.stop_operation();
        Ok(())
    }

    async fn list_enrolled_fingers(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        username: &str,
    ) -> Result<Vec<String>, FprintError> {
        let (_caller_sender, caller_uid) = get_caller_info(conn, &hdr).await?;
        let (target_user, target_uid) = resolve_target_user(caller_uid, username, "list prints")?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(FprintError::Internal)?;
        let fingers = driver.list_enrolled_fingers(target_uid).await
            .map_err(FprintError::Internal)?;

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
        let (_target_user, target_uid) = resolve_target_user(caller_uid, username, "delete prints")?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(FprintError::Internal)?;
        if let Some(user_info) = driver.lookup_user(target_uid).await.map_err(FprintError::Internal)? {
            driver.del_user(user_info.dbid).await.map_err(FprintError::Internal)?;
        }
        Ok(())
    }

    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let claim = self.claim_for(&caller_sender(&hdr)?)?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(FprintError::Internal)?;
        if let Some(user_info) = driver.lookup_user(claim.uid).await.map_err(FprintError::Internal)? {
            driver.del_user(user_info.dbid).await.map_err(FprintError::Internal)?;
        }
        Ok(())
    }

    async fn delete_enrolled_finger(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let claim = self.claim_for(&caller_sender(&hdr)?)?;
        let subtype = match finger_name_to_id(finger_name) {
            Some(id) if id != 0 => id,
            _ => return Err(FprintError::InvalidFingername(format!("Invalid finger name: {}", finger_name))),
        };

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(FprintError::Internal)?;
        let deleted = driver.del_finger(claim.uid, subtype).await
            .map_err(FprintError::Internal)?;
        if !deleted {
            return Err(FprintError::NoEnrolledPrints(format!("Finger {} is not enrolled", finger_name)));
        }
        Ok(())
    }

    async fn verify_start(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let claim = self.claim_for(&caller_sender(&hdr)?)?;
        eprintln!("VerifyStart by {} for {} (finger '{}')", claim.sender, claim.username, finger_name);

        // Cancel any in-flight operation *before* taking the driver lock; otherwise we would
        // wait for the old capture to run out on its own.
        let cancel = self.begin_operation();

        // Synchronously verify user has enrolled prints
        {
            let mut d = self.driver.lock().await;
            let checked = async {
                d.ensure_connected().await?;
                d.lookup_user(claim.uid).await
            }.await;
            match checked {
                Ok(Some(u)) if !u.fingers.is_empty() => (),
                Ok(_) => {
                    return Err(FprintError::NoEnrolledPrints(format!("No enrolled prints for user {}", claim.username)));
                }
                Err(e) => return Err(FprintError::Internal(e)),
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
            if cancel.load(Ordering::Relaxed) {
                return;
            }

            let user_info = match d.lookup_user(uid).await {
                Ok(Some(u)) if !u.fingers.is_empty() => u,
                _ => {
                    let _ = Self::verify_status(&emitter_clone, "verify-no-match", true).await;
                    return;
                }
            };

            // Like fprintd, keep waiting for a finger until the client stops us (VerifyStop,
            // Release, or disconnecting). Timeouts are the client's decision.
            let mut device_failures = 0u32;
            while !cancel.load(Ordering::Relaxed) {
                match d.capture(CaptureMode::Identify, &cancel, CAPTURE_WINDOW).await {
                    Ok(()) => {
                        // Tag 1 returned by the chip is the Windsor user record dbid
                        let result = match d.match_finger().await {
                            Ok((matched_uid, _subtype)) if matched_uid == user_info.dbid as u32 => "verify-match",
                            _ => "verify-no-match",
                        };
                        let _ = d.led_glow(false).await;
                        eprintln!("Verify result: {}", result);
                        if !cancel.load(Ordering::Relaxed) {
                            // Per the fprintd API, a no-match is final; the client decides whether to retry.
                            let _ = Self::verify_status(&emitter_clone, result, true).await;
                        }
                        break;
                    }
                    Err(CaptureError::Cancelled) => break,
                    Err(CaptureError::Timeout) => continue,
                    Err(CaptureError::ScanProblem(_)) => {
                        device_failures = 0;
                        let _ = Self::verify_status(&emitter_clone, "verify-retry-scan", false).await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(CaptureError::Device(e)) => {
                        device_failures += 1;
                        eprintln!("Verify: sensor error ({}), attempt {}/{}", e, device_failures, MAX_DEVICE_FAILURES);
                        if device_failures >= MAX_DEVICE_FAILURES {
                            let _ = Self::verify_status(&emitter_clone, "verify-unknown-error", true).await;
                            break;
                        }
                        // Covers resume-from-suspend while a lock screen is waiting for a finger
                        let _ = d.ensure_connected().await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let _ = d.led_glow(false).await;
        });

        Ok(())
    }

    async fn verify_stop(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let claim = self.claim_for(&caller_sender(&hdr)?)?;
        eprintln!("VerifyStop by {}", claim.sender);
        self.stop_operation();
        Ok(())
    }

    async fn enroll_start(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let claim = self.claim_for(&caller_sender(&hdr)?)?;

        let subtype = match finger_name_to_id(finger_name) {
            Some(id) if id != 0 => id,
            _ => return Err(FprintError::InvalidFingername(format!("Invalid finger name: {}", finger_name))),
        };

        let cancel = self.begin_operation();

        {
            let mut d = self.driver.lock().await;
            d.ensure_connected().await.map_err(FprintError::Internal)?;
        }

        let driver = self.driver.clone();
        let emitter_clone = emitter.to_owned();
        let uid = claim.uid;

        tokio::spawn(async move {
            let mut d = driver.lock().await;
            if cancel.load(Ordering::Relaxed) {
                return;
            }

            if d.create_enrollment().await.is_err() {
                let _ = d.led_glow(false).await;
                let _ = Self::enroll_status(&emitter_clone, "enroll-unknown-error", true).await;
                return;
            }
            // Enrollment state lives on the sensor; if the connection is re-established
            // mid-enrollment, the partial template is gone and we must fail.
            let generation = d.generation;

            let mut key = 0u32;
            let mut template = Vec::new();
            let mut final_tid = None;
            let mut failed = false;

            while !cancel.load(Ordering::Relaxed) {
                match d.capture(CaptureMode::Enroll, &cancel, CAPTURE_WINDOW).await {
                    Ok(()) => {
                        if d.generation != generation {
                            failed = true;
                            break;
                        }
                        let new_key = match d.enrollment_update_start(key).await {
                            Ok(k) => k,
                            Err(_) if !d.is_connected() => {
                                failed = true;
                                break;
                            }
                            Err(_) => {
                                let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                                continue;
                            }
                        };
                        key = new_key;

                        let (_header, new_template, tid) = match d.append_new_image(&template).await {
                            Ok(res) => res,
                            Err(_) if !d.is_connected() => {
                                failed = true;
                                break;
                            }
                            Err(_) => {
                                let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                                continue;
                            }
                        };
                        template = new_template;

                        let _ = Self::enroll_status(&emitter_clone, "enroll-stage-passed", false).await;
                        if let Some(t) = tid {
                            final_tid = Some(t);
                            break;
                        }
                    }
                    Err(CaptureError::Cancelled) => break,
                    Err(CaptureError::Timeout) => continue,
                    Err(CaptureError::ScanProblem(_)) => {
                        let _ = Self::enroll_status(&emitter_clone, "enroll-retry-scan", false).await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(CaptureError::Device(e)) => {
                        eprintln!("Enroll: sensor error ({})", e);
                        failed = true;
                        break;
                    }
                }
            }

            let _ = d.enrollment_update_end().await;

            let tid = match final_tid {
                Some(tid) if !failed => tid,
                _ => {
                    let _ = d.cancel_current().await;
                    if failed && !cancel.load(Ordering::Relaxed) {
                        let _ = Self::enroll_status(&emitter_clone, "enroll-unknown-error", true).await;
                    }
                    return;
                }
            };

            // Find or create user on chip
            let (user_id, replaced) = match d.lookup_user(uid).await {
                Ok(Some(u)) => {
                    let old: Vec<u16> = u.fingers.iter()
                        .filter(|f| f.subtype == subtype)
                        .map(|f| f.dbid)
                        .collect();
                    (u.dbid, old)
                }
                _ => match d.new_user(uid).await {
                    Ok(id) => (id, Vec::new()),
                    Err(_) => {
                        let _ = d.led_glow(false).await;
                        let _ = Self::enroll_status(&emitter_clone, "enroll-data-full", true).await;
                        return;
                    }
                },
            };

            match d.save_finger(user_id, subtype, &template, &tid).await {
                Ok(_) => {
                    // Re-enrolling a finger replaces it. Remove the old record only after the new
                    // one is safely stored, so a failure never leaves the finger unenrolled.
                    for old in replaced {
                        if let Err(e) = d.del_record(old).await {
                            eprintln!("Failed to remove previous record {} for re-enrolled finger: {}", old, e);
                        }
                    }
                    let _ = d.led_glow(false).await;
                    let _ = Self::enroll_status(&emitter_clone, "enroll-completed", true).await;
                }
                Err(_) => {
                    let _ = d.led_glow(false).await;
                    let _ = Self::enroll_status(&emitter_clone, "enroll-data-full", true).await;
                }
            }
        });

        Ok(())
    }

    async fn enroll_stop(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        self.claim_for(&caller_sender(&hdr)?)?;
        self.stop_operation();
        Ok(())
    }
}
