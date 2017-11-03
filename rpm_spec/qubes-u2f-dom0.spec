%{!?version: %define version %(cat version)}
%define _builddir %(pwd)

Name:		qubes-u2f
Version:	%{version}
Release:	1%{?dist}
Summary:    Qubes OS U2F proxy policy files

Group:		Qubes
License:	GPL2+
URL:		https://github.com/QubesOS/qubes-app-u2f

BuildArch:  noarch

Requires:   qubes-core-dom0

%description
Qubes OS U2F proxy policy files

%prep
rm -f %{name}-%{version}
ln -sf . %{name}-%{version}
%setup -T -D

%build

%install
make install-policy DESTDIR=$RPM_BUILD_ROOT

%files
/etc/qubes-rpc/policy/u2f.Register
/etc/qubes-rpc/policy/u2f.Authenticate
