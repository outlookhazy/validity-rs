mod blobs;
mod crypto;
mod db;
mod dbus;
mod sensor;
mod tls;

use std::sync::Arc;
use std::time::Duration;
use dbus::{FprintDevice, FprintManager};
use futures_util::StreamExt;
use sensor::SensorDriver;
use tokio::signal::unix::{signal, SignalKind};

#[zbus::proxy(
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    interface = "org.freedesktop.login1.Manager"
)]
trait Login1Manager {
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Validity 138a:0097 Fingerprint Daemon ===");
    println!("Initializing sensor hardware...");

    let driver = SensorDriver::open().await
        .map_err(|e| format!("Failed to initialize sensor: {}", e))?;
    println!("Sensor initialized! Windsor storage ID: {}", driver.stg_id);

    let driver_arc = Arc::new(tokio::sync::Mutex::new(driver));
    let device_path: zbus::OwnedObjectPath = "/net/reactivated/Fprint/Device/0".try_into()?;

    let manager = FprintManager {
        device_path: device_path.clone(),
    };
    let device = FprintDevice::new(driver_arc.clone());
    let device_handle = device.clone();

    println!("Connecting to system bus and requesting 'net.reactivated.Fprint'...");
    let conn = zbus::connection::Builder::system()
        .name("net.reactivated.Fprint")
        .serve_at("/net/reactivated/Fprint/Manager", manager)
        .serve_at("/net/reactivated/Fprint/Device/0", device)
        .build()
        .await?;

    // Release the device if the claiming client disappears without calling Release
    let dbus_proxy = zbus::fdo::DBusProxy::new(&conn).await?;
    let mut owner_changes = dbus_proxy.receive_name_owner_changed().await?;
    let watch_device = device_handle.clone();
    tokio::spawn(async move {
        while let Some(signal) = owner_changes.next().await {
            if let Ok(args) = signal.args() {
                if args.new_owner.is_none() {
                    watch_device.client_vanished(args.name.as_str());
                }
            }
        }
        eprintln!("NameOwnerChanged stream ended; stale claims will no longer be auto-released");
    });

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
    println!("Ready for authentication requests.");

    // systemd stops services with SIGTERM; handle it as well as Ctrl-C
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    println!("Received shutdown signal. Stopping sensor and exiting.");

    // Stop any running capture so it releases the driver, then reset the sensor and LED
    device_handle.signal_cancel();
    if let Ok(mut d) = tokio::time::timeout(Duration::from_secs(2), driver_arc.lock()).await {
        let _ = d.cancel_current().await;
    }
    Ok(())
}
