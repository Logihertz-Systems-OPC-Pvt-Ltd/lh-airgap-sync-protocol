Name:           lh-airgap-sync-protocol
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-airgap-sync - Galois Field GF(2^8) Cauchy Generator Matrix Invariant
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-airgap-sync-protocol
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Pure-Rust unidirectional optical/QR and UDP data-diode synchronization protocol featuring Galois Field GF(2^8) Cauchy erasure coding, HMAC-SHA256 frame authentication, monotonic anti-replay, and optical matrix rendering.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-airgap-sync ]; then
    install -m 0755 bin/lh-airgap-sync %{buildroot}%{_bindir}/lh-airgap-sync
elif [ -f lh-airgap-sync ]; then
    install -m 0755 lh-airgap-sync %{buildroot}%{_bindir}/lh-airgap-sync
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
