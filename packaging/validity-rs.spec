Name:           validity-rs
Version:        0.1.0
Release:        1%{?dist}
Summary:        Pure-Rust native fingerprint authentication daemon for Validity sensors (138a:0097)

License:        MIT
URL:            https://github.com/cgalant/validity-rs

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       fprintd-pam

%description
A pure-Rust, zero-Python, asynchronous fingerprint authentication daemon for
Validity sensors (138a:0097 and 138a:0090) found on Lenovo ThinkPad X1 Carbon
and related laptops. Implements the standard net.reactivated.Fprint D-Bus interface
for seamless integration with PAM, fprintd-enroll, fprintd-verify, and KDE Plasma 6.

%install
rm -rf $RPM_BUILD_ROOT
cp %{_sourcedir}/LICENSE .
install -D -p -m 0755 %{_sourcedir}/target/release/validity-rs $RPM_BUILD_ROOT%{_libexecdir}/validity-rs
install -D -p -m 0755 %{_sourcedir}/target/release/validity-rs $RPM_BUILD_ROOT%{_bindir}/validity-rs
install -D -p -m 0644 %{_sourcedir}/packaging/validity-rs.service $RPM_BUILD_ROOT%{_unitdir}/validity-rs.service
install -D -p -m 0644 %{_sourcedir}/packaging/70-validity.rules $RPM_BUILD_ROOT%{_udevrulesdir}/70-validity.rules

%post
/usr/bin/systemctl mask fprintd.service 2>/dev/null || :
%systemd_post validity-rs.service
/usr/bin/systemctl daemon-reload 2>/dev/null || :
/usr/bin/systemctl enable --now validity-rs.service 2>/dev/null || :
/usr/bin/udevadm control --reload-rules && /usr/bin/udevadm trigger 2>/dev/null || :

%preun
%systemd_preun validity-rs.service
/usr/bin/systemctl unmask fprintd.service 2>/dev/null || :

%postun
%systemd_postun_with_restart validity-rs.service

%files
%license LICENSE
%{_libexecdir}/validity-rs
%{_bindir}/validity-rs
%{_unitdir}/validity-rs.service
%{_udevrulesdir}/70-validity.rules

%changelog
* Thu Oct 22 2026 cgalant - 0.1.0-1
- Initial release with pure-Rust TLS 1.2 engine and D-Bus integration
