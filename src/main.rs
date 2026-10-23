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

use futures_util::StreamExt;

#[zbus::proxy(
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    interface = "org.freedesktop.login1.Manager"
)]
trait Login1Manager {
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

    let driver_arc = Arc::new(tokio::sync::Mutex::new(driver));
    let device_path: zbus::OwnedObjectPath = "/net/reactivated/Fprint/Device/0".try_into()?;

    let manager = FprintManager {
        device_path: device_path.clone(),
    };
    let device = FprintDevice::new(driver_arc.clone());

    println!("Connecting to system bus and requesting 'net.reactivated.Fprint'...");
    let conn = zbus::connection::Builder::system()
        .name("net.reactivated.Fprint")
        .serve_at("/net/reactivated/Fprint/Manager", manager)
        .serve_at("/net/reactivated/Fprint/Device/0", device)
        .build()
        .await?;

    if let Ok(login_proxy) = Login1ManagerProxy::new(&conn).await {
        if let Ok(mut sleep_stream) = login_proxy.receive_prepare_for_sleep().await {
            let sleep_driver = driver_arc.clone();
            tokio::spawn(async move {
                while let Some(signal) = sleep_stream.next().await {
                    if let Ok(args) = signal.args() {
                        if !args.start {
                            println!("System resumed from sleep. Reconnecting sensor...");
                            let mut d = sleep_driver.lock().await;
                            if let Err(e) = d.reconnect().await {
                                eprintln!("Failed to reconnect sensor after resume: {}", e);
                            } else {
                                println!("Sensor reconnected successfully after resume!");
                            }
                        }
                    }
                }
            });
        }
    }


    println!("Daemon running! D-Bus service net.reactivated.Fprint is live.");
    println!("Ready for: PAM, fprintd-enroll, fprintd-verify, fprintd-delete, KDE Plasma 6.");

    tokio::signal::ctrl_c().await?;
    println!("\nReceived shutdown signal. Exiting daemon.");
    Ok(())
}
