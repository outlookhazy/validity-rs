mod blobs;
mod crypto;
mod db;
mod dbus;
mod sensor;
mod tls;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use dbus::{is_lid_closed, FprintDevice, FprintManager, Login1ManagerProxy};
use futures_util::StreamExt;
use sensor::SensorDriver;
use tokio::signal::unix::{signal, SignalKind};

/// Abort the active verify/enroll if the lid is still closed and no sleep has started after a
/// short grace period. Closing the lid to suspend fires LidClosed ~100 ms before
/// PrepareForSleep(true); the delay keeps a lock-screen verify alive across that sleep, while a
/// lid closed in clamshell/docked mode (system stays awake) falls back to password.
fn cancel_if_lid_stays_closed(conn: zbus::Connection, device: FprintDevice) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if !device.sleeping.load(Ordering::SeqCst)
            && device.has_active_operation()
            && is_lid_closed(&conn).await
        {
            eprintln!("Lid closed while awake; aborting active fingerprint operation");
            device.cancel_for_lid_close();
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Validity 138a:0097 Fingerprint Daemon ===");
    println!("Initializing sensor hardware...");

    let driver = SensorDriver::open().await
        .map_err(|e| format!("Failed to initialize sensor: {}", e))?;
    println!("Sensor initialized! Windsor storage ID: {}", driver.stg_id);

    let slept_flag = driver.slept_flag();
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

    // Release the open USB handle once idle so 138a:0097 and usb1 enter runtime suspend
    device_handle.spawn_idle_task();
    device_handle.touch_activity();

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
        let sleeping = device_handle.sleeping.clone();

        if let Ok(mut sleep_stream) = login_proxy.receive_prepare_for_sleep().await {
            let sleep_driver = driver_arc.clone();
            let sleep_device = device_handle.clone();
            let sleep_conn = conn.clone();
            let sleep_flag = sleeping.clone();
            let driver_slept = slept_flag.clone();
            tokio::spawn(async move {
                while let Some(signal) = sleep_stream.next().await {
                    if let Ok(args) = signal.args() {
                        if args.start {
                            sleep_flag.store(true, Ordering::SeqCst);
                            driver_slept.store(true, Ordering::SeqCst);
                            if !sleep_device.has_active_operation() {
                                if let Ok(mut d) = sleep_driver.try_lock() {
                                    d.on_system_sleep();
                                }
                            }
                        } else {
                            sleep_flag.store(false, Ordering::SeqCst);
                            if is_lid_closed(&sleep_conn).await {
                                println!("System resumed from sleep with lid closed; keeping sensor suspended.");
                                if let Ok(mut d) = sleep_driver.try_lock() {
                                    d.on_system_sleep();
                                }
                                // A lock-screen verify kept alive across sleep can never complete
                                // while the lid stays closed (docked wake): fall back to password.
                                cancel_if_lid_stays_closed(sleep_conn.clone(), sleep_device.clone());
                            } else if let Ok(mut d) = sleep_driver.try_lock() {
                                println!("System resumed from sleep. Reconnecting sensor...");
                                d.on_system_sleep();
                                if let Err(e) = d.ensure_connected().await {
                                    eprintln!("Failed to reconnect sensor after resume: {}", e);
                                } else {
                                    println!("Sensor reconnected successfully after resume!");
                                }
                                drop(d);
                                sleep_device.touch_activity();
                            }
                        }
                    }
                }
            });
        }

        let lid_proxy = login_proxy.clone();
        let lid_conn = conn.clone();
        let lid_device = device_handle.clone();
        tokio::spawn(async move {
            let mut lid_stream = lid_proxy.receive_lid_closed_changed().await;
            while let Some(change) = lid_stream.next().await {
                if change.get().await == Ok(true) && lid_device.has_active_operation() {
                    cancel_if_lid_stays_closed(lid_conn.clone(), lid_device.clone());
                }
            }
        });
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
