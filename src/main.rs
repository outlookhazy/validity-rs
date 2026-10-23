mod blobs;
mod crypto;
mod db;
mod dbus;
mod sensor;
mod tls;

use std::sync::Arc;
use dbus::{FprintDevice, FprintManager};
use sensor::SensorDriver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Validity 138a:0097 Fingerprint Daemon (Rust) ===");
    println!("Initializing sensor hardware...");

    let driver = SensorDriver::open().await
        .map_err(|e| format!("Failed to initialize sensor: {}", e))?;
    println!("Sensor initialized! Windsor storage ID: {}", driver.stg_id);

    let driver_arc = Arc::new(tokio::sync::Mutex::new(driver));
    let device_path: zbus::OwnedObjectPath = "/net/reactivated/Fprint/Device/0".try_into()?;

    let manager = FprintManager {
        device_path: device_path.clone(),
    };
    let device = FprintDevice::new(driver_arc);

    println!("Connecting to system bus and requesting 'net.reactivated.Fprint'...");
    let _conn = zbus::connection::Builder::system()
        .name("net.reactivated.Fprint")
        .serve_at("/net/reactivated/Fprint/Manager", manager)
        .serve_at("/net/reactivated/Fprint/Device/0", device)
        .build()
        .await?;

    println!("Daemon running! D-Bus service net.reactivated.Fprint is live.");
    println!("Ready for: PAM, fprintd-enroll, fprintd-verify, fprintd-delete, KDE Plasma 6.");

    tokio::signal::ctrl_c().await?;
    println!("\nReceived shutdown signal. Exiting daemon.");
    Ok(())
}
