use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
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
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == username {
            return parts[2].parse().ok();
        }
    }
    None
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

pub struct FprintDevice {
    pub driver: Arc<Mutex<SensorDriver>>,
    pub claimed_by: Arc<std::sync::Mutex<Option<String>>>,
    pub cancel_flag: Arc<AtomicBool>,
}

impl FprintDevice {
    pub fn new(driver: Arc<Mutex<SensorDriver>>) -> Self {
        Self {
            driver,
            claimed_by: Arc::new(std::sync::Mutex::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl FprintDevice {
    // --- Properties ---
    #[zbus(property, name = "name")]
    async fn name(&self) -> String {
        "Validity VFS0097 Fingerprint Reader (Rust)".to_string()
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
    async fn claim(&self, username: &str) -> Result<(), FprintError> {
        let mut claimed = self.claimed_by.lock().unwrap();
        let target_user = if username.is_empty() {
            "cgalant".to_string()
        } else {
            username.to_string()
        };
        if let Some(ref current) = *claimed {
            if current != &target_user {
                return Err(FprintError::AlreadyInUse("Device is already claimed".into()));
            }
        }
        *claimed = Some(target_user);
        self.cancel_flag.store(false, Ordering::Relaxed);
        Ok(())
    }

    async fn release(&self) -> Result<(), FprintError> {
        let mut claimed = self.claimed_by.lock().unwrap();
        *claimed = None;
        self.cancel_flag.store(true, Ordering::Relaxed);
        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
            let _ = d.led_glow(false).await;
        });
        Ok(())
    }

    async fn list_enrolled_fingers(&self, username: &str) -> Result<Vec<String>, FprintError> {
        let target_user = if username.is_empty() { "cgalant" } else { username };
        let uid = username_to_uid(target_user)
            .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", target_user)))?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        let fingers = driver.list_enrolled_fingers(uid).await
            .map_err(|e| FprintError::Internal(e.to_string()))?;

        if fingers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!("No enrolled prints for user {}", target_user)));
        }
        Ok(fingers)
    }

    async fn delete_enrolled_fingers(&self, username: &str) -> Result<(), FprintError> {
        let target_user = if username.is_empty() { "cgalant" } else { username };
        let uid = username_to_uid(target_user)
            .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", target_user)))?;

        let mut driver = self.driver.lock().await;
        driver.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        if let Some(user_info) = driver.lookup_user(uid).await.map_err(|e| FprintError::Internal(e.to_string()))? {
            driver.del_user(user_info.dbid).await.map_err(|e| FprintError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete_enrolled_fingers2(&self) -> Result<(), FprintError> {
        let username = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };
        self.delete_enrolled_fingers(&username).await
    }

    async fn delete_enrolled_finger(&self, _finger_name: &str) -> Result<(), FprintError> {
        let username = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };
        self.delete_enrolled_fingers(&username).await
    }

    async fn verify_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let username = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };

        let uid = username_to_uid(&username)
            .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", username)))?;

        // Synchronously verify user has enrolled prints
        {
            let mut d = self.driver.lock().await;
            d.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
            let user_info = d.lookup_user(uid).await.map_err(|e| FprintError::Internal(e.to_string()))?;
            match user_info {
                Some(u) if !u.fingers.is_empty() => (),
                _ => {
                    return Err(FprintError::NoEnrolledPrints(format!("No enrolled prints for user {}", username)));
                }
            }
        }

        self.cancel_flag.store(false, Ordering::Relaxed);
        let driver = self.driver.clone();
        let cancel = self.cancel_flag.clone();
        let emitter_clone = emitter.to_owned();
        let selected_finger = if finger_name.is_empty() { "any" } else { finger_name }.to_string();

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
                                if matched_uid == uid || matched_uid == (user_info.dbid as u32) {
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
        self.cancel_flag.store(true, Ordering::Relaxed);
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
        let username = {
            let claimed = self.claimed_by.lock().unwrap();
            claimed.clone().ok_or_else(|| FprintError::ClaimDevice("Client must claim device first".into()))?
        };

        let uid = username_to_uid(&username)
            .ok_or_else(|| FprintError::Internal(format!("Unknown user: {}", username)))?;

        let subtype = finger_name_to_id(finger_name)
            .unwrap_or(2); // default right-index-finger

        {
            let mut d = self.driver.lock().await;
            d.ensure_connected().await.map_err(|e| FprintError::Internal(e.to_string()))?;
        }

        self.cancel_flag.store(false, Ordering::Relaxed);
        let driver = self.driver.clone();
        let cancel = self.cancel_flag.clone();
        let emitter_clone = emitter.to_owned();

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
        self.cancel_flag.store(true, Ordering::Relaxed);
        let driver = self.driver.clone();
        tokio::spawn(async move {
            let mut d = driver.lock().await;
            let _ = d.cancel_current().await;
        });
        Ok(())
    }
}
