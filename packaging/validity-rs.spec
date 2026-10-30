Name:           validity-rs
Version:        0.1.4
Release:        1%{?dist}
Summary:        Native fingerprint authentication daemon for Validity sensors (138a:0097)

License:        MIT
URL:            https://github.com/outlookhazy/validity-rs


BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       fprintd-pam

%description
A native asynchronous fingerprint authentication daemon for Validity sensors
(138a:0097) found on Lenovo ThinkPad X1 Carbon and related laptops.
Implements the standard net.reactivated.Fprint D-Bus interface for seamless
integration with PAM, fprintd-enroll, fprintd-verify, and KDE Plasma 6.

%install
rm -rf $RPM_BUILD_ROOT
cp %{_sourcedir}/LICENSE .
install -D -p -m 0755 %{_sourcedir}/target/release/validity-rs $RPM_BUILD_ROOT%{_libexecdir}/validity-rs
install -D -p -m 0644 %{_sourcedir}/packaging/validity-rs.service $RPM_BUILD_ROOT%{_unitdir}/validity-rs.service
install -D -p -m 0644 %{_sourcedir}/packaging/65-validity.rules $RPM_BUILD_ROOT%{_udevrulesdir}/65-validity.rules

%post
/usr/bin/systemctl mask fprintd.service 2>/dev/null || :
%systemd_post validity-rs.service
if [ $1 -eq 1 ]; then
    # First install only: upgrades must not re-enable a service the admin disabled
    /usr/bin/systemctl daemon-reload 2>/dev/null || :
    /usr/bin/systemctl enable --now validity-rs.service 2>/dev/null || :
fi
/usr/bin/udevadm control --reload-rules 2>/dev/null || :
/usr/bin/udevadm trigger --subsystem-match=usb --attr-match=idVendor=138a 2>/dev/null || :

%preun
%systemd_preun validity-rs.service
if [ $1 -eq 0 ]; then
    /usr/bin/systemctl unmask fprintd.service 2>/dev/null || :
fi

%postun
/usr/bin/udevadm control --reload-rules 2>/dev/null || :
%systemd_postun_with_restart validity-rs.service

%files
%license LICENSE
%{_libexecdir}/validity-rs
%{_unitdir}/validity-rs.service
%{_udevrulesdir}/65-validity.rules

%changelog
* Thu Oct 29 2026 cgalant - 0.1.4-1
- Release open USB handle after 5s of idle time so 138a:0097 and usb1 enter kernel USB runtime suspend
- Cache enrolled user metadata in memory so ListEnrolledFingers and non-enrolled checks avoid USB wakeups
- Skip fingerprint verification/enrollment when laptop lid is closed (clamshell/docked mode) so PAM falls back immediately to password without waking USB
- Cancel unreachable active prompts if lid closes while staying awake, while preserving S3 sleep/resume lockscreen unlock
- Avoid redundant post-sleep reconnects and skip reconnecting on lid-closed wake
- Move udev rule to 65-validity.rules with MTP_NO_PROBE=1 and power/control=auto

* Fri Oct 23 2026 cgalant - 0.1.3-1
- Security: claim-scoped D-Bus methods (Enroll/Verify/Delete/Stop/Release) now require
  the caller to be the client that claimed the device
- Release the device automatically when the claiming client disconnects
- Restrict ListEnrolledFingers to the caller's own account (or root)
- Never time out verify/enroll on the daemon side; reconnect and keep going after resume
- Keep exactly one USB interrupt transfer outstanding; drop the connection on any I/O error
  so responses can never be paired with the wrong request
- Thread-safe passwd lookups (getpwnam_r/getpwuid_r)
- Re-enrolling a finger replaces the old record instead of duplicating it
- Reject invalid finger names; verify-no-match is always final per the fprintd API
- Handle SIGTERM: cancel capture and turn the LED off on stop
- Only enable the service on first install, not on every upgrade
- Log claim/verify/release calls and results to the journal for troubleshooting

* Fri Oct 23 2026 cgalant - 0.1.2-1
- Security: Enforce caller UID authorization on D-Bus Claim/Enroll/Delete to prevent LPE
- Fix single-finger deletion so deleting a finger does not wipe all user prints
- Drop active USB interface before reconnecting to prevent EBUSY
- Prevent write command replay on reconnect and fix UID vs DBID matching logic
- Guard fprintd unmasking in RPM preun so upgrades do not unmask fprintd
- Tighten udev rules and systemd service sandboxing

* Fri Oct 23 2026 cgalant - 0.1.1-1
- Add automatic reconnection and logind PrepareForSleep resume handling
- Fix device disconnected error across suspend/sleep cycles

* Thu Oct 22 2026 cgalant - 0.1.0-1
- Initial release with pure-Rust TLS 1.2 engine and D-Bus integration
