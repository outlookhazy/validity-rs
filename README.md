# validity-rs

A **pure-Rust, zero-Python**, native asynchronous fingerprint authentication daemon for Validity Sensors (**`138a:0097`** and **`138a:0090`**) found on Lenovo ThinkPad laptops (such as the ThinkPad X1 Carbon 5th Gen).

`validity-rs` replaces the non-working upstream `fprintd` driver stack with a native, high-performance daemon that directly implements the standard **`net.reactivated.Fprint`** D-Bus interface.

---

## ✨ Features

- **Pure Rust Implementation:** No Python interpreter overhead, no C ctypes wrappers, and no out-of-tree libfprint patches.
- **Asynchronous Hardware I/O:** Powered by [`nusb`](https://crates.io/crates/nusb) and [`tokio`](https://tokio.rs) for non-blocking USB transfers.
- **Hardware-Level Cryptography:** Implements the sensor's proprietary TLS 1.2 ECDHE-ECDSA handshake, key derivation, and authenticated AES-256-CBC + HMAC-SHA256 session transport.
- **On-Chip Biometrics:** Utilizes the sensor's internal Windsor biometric database for enrollment and template matching.
- **Seamless Desktop & PAM Integration:**
  - Works with standard Linux PAM (`pam_fprintd.so`).
  - Terminal `sudo` fingerprint authentication.
  - **KDE Plasma 6** lock screen, SDDM login, and System Settings user manager.
  - Standard command-line tools: `fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete`.
- **Intuitive Touch Feedback:** Interactive LED ring breathing and status indications during touch capture.

---

## 💻 Supported Hardware

- **Device ID:** `138a:0097` (Validity Sensors, Inc.)
- **Device ID:** `138a:0090` (experimental)
- **Tested Platforms:** Lenovo ThinkPad X1 Carbon 5th Gen (`20HR...`), Fedora 44 (Linux 7.2+, KDE Plasma 6).

---

## 🚀 Installation (Fedora / RHEL)

### Option 1: Install Pre-Built RPM (Recommended)

Download and install the latest release directly from GitHub:

```bash
sudo dnf install -y https://github.com/outlookhazy/validity-rs/releases/download/v0.1.0/validity-rs-0.1.0-1.fc44.x86_64.rpm
```

### Option 2: Build and Install from Source

Requirements: `rust`, `cargo`, `rpm-build`.

```bash
# Build the RPM package
./packaging/build-rpm.sh

# Install the generated RPM
sudo dnf install -y target/rpmbuild/RPMS/*/*.rpm
```

### Enabling Fingerprint in PAM

If you haven't already enabled fingerprint authentication on your Fedora system, enable it with `authselect`:

```bash
sudo authselect enable-feature with-fingerprint
sudo authselect apply-changes
```

### Uninstallation

To uninstall and revert to standard `fprintd` at any time:
```bash
sudo dnf remove -y validity-rs
```

---

## 🛠️ Usage

Because `validity-rs` implements the standard `net.reactivated.Fprint` D-Bus interface, you interact with your fingerprint reader using standard Linux desktop tools:

### Enrolling Fingers
```bash
# Enroll your right index finger (press 7 times when prompted)
fprintd-enroll

# Enroll a specific finger
fprintd-enroll -f left-index-finger
```
*(Or use **KDE System Settings → Users → Fingerprint**).*

### Verifying
```bash
fprintd-verify
```

### Listing Enrolled Fingers
```bash
fprintd-list $USER
```

### Deleting Fingers
```bash
# Delete enrolled prints for current user
fprintd-delete $USER

# Delete enrolled prints for root
sudo fprintd-delete root
```

---

## 📄 License & Attribution

Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

### Acknowledgments
Protocol reverse-engineering and cryptographic flow design based on the foundational research of:
- [python-validity](https://github.com/uunicorn/python-validity) by **uunicorn**
- [open-fprintd](https://github.com/uunicorn/open-fprintd) by **uunicorn**
