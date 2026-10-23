# validity-rs

A native Linux fingerprint daemon for Validity Sensors (`138a:0097` and `138a:0090`) commonly found on Lenovo ThinkPads (such as the X1 Carbon Gen 5).

`validity-rs` communicates directly with the sensor over USB and implements the standard `net.reactivated.Fprint` D-Bus interface, allowing standard desktop environments and PAM to interact with the device out of the box.

## Features

- **Direct USB communication:** Implements the sensor's TLS 1.2 ECDHE-ECDSA handshake and encrypted transport natively using `nusb`.
- **On-chip matching:** Uses the hardware's internal biometric database for enrollment and template verification.
- **Desktop and PAM integration:**
  - Standard PAM authentication (`pam_fprintd.so`) for `sudo` and login prompts.
  - Lock screen and user management support in KDE Plasma 6, SDDM, and GDM.
  - Compatible with standard CLI utilities (`fprintd-enroll`, `fprintd-verify`, `fprintd-delete`).
- **Visual feedback:** Controls the sensor's LED ring during capture and enrollment.

## Hardware Support

- **138a:0097** (Tested on ThinkPad X1 Carbon Gen 5, Fedora 44)
- **138a:0090** (Experimental)

## Installation

### Pre-built RPM (Fedora / RHEL)

Install the latest package directly from GitHub Releases:

```bash
sudo dnf install -y https://github.com/outlookhazy/validity-rs/releases/download/v0.1.1/validity-rs-0.1.1-1.fc44.x86_64.rpm
```

### Building from Source

Prerequisites: `rust`, `cargo`, `rpm-build`.

```bash
# Build RPM package
./packaging/build-rpm.sh

# Install
sudo dnf install -y target/rpmbuild/RPMS/*/*.rpm
```

### Enabling PAM Authentication

If fingerprint authentication is not yet enabled on Fedora:

```bash
sudo authselect enable-feature with-fingerprint
sudo authselect apply-changes
```

### Uninstallation

To remove the package and restore default system services:

```bash
sudo dnf remove -y validity-rs
```

## Usage

Because `validity-rs` implements `net.reactivated.Fprint`, use standard system utilities:

### Enrollment

```bash
# Enroll right index finger (default)
fprintd-enroll

# Enroll a specific finger
fprintd-enroll -f left-index-finger
```
Fingerprints can also be registered directly through desktop settings (e.g. **KDE System Settings → Users → Fingerprint**).

### Verification

```bash
fprintd-verify
```

### Listing and Deletion

```bash
# List enrolled fingers
fprintd-list $USER

# Delete enrolled fingers for current user
fprintd-delete $USER

# Delete enrolled fingers for root
sudo fprintd-delete root
```

## License & Acknowledgments

Licensed under the [MIT License](LICENSE).

Based on protocol reverse-engineering and research from:
- [python-validity](https://github.com/uunicorn/python-validity) by uunicorn
- [open-fprintd](https://github.com/uunicorn/open-fprintd) by uunicorn
