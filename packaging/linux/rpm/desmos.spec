Name:           desmos
Version:        1.0.0
Release:        1%{?dist}
Summary:        Cross-platform connection bonding VPN

License:        MIT
URL:            https://github.com/KilimcininKorOglu/desmos
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.75
BuildRequires:  rust >= 1.75

%description
Desmos combines multiple network interfaces (Wi-Fi, Ethernet, LTE)
into a single encrypted tunnel using ChaCha20-Poly1305. Supports
four bonding strategies, sub-second failover, and an embedded Web UI.

%prep
%autosetup

%build
cargo build --release --locked

%install
install -Dm755 target/release/desmos %{buildroot}%{_bindir}/desmos
install -Dm644 packaging/linux/systemd/desmos.service %{buildroot}%{_unitdir}/desmos.service
install -dm700 %{buildroot}%{_sysconfdir}/desmos

%post
%systemd_post desmos.service

%preun
%systemd_preun desmos.service

%postun
%systemd_postun_with_restart desmos.service

%files
%license LICENSE
%doc README.md docs/
%{_bindir}/desmos
%{_unitdir}/desmos.service
%dir %attr(0700,root,root) %{_sysconfdir}/desmos

%changelog
* Tue Apr 15 2026 KilimcininKorOglu - 1.0.0-1
- Initial package
