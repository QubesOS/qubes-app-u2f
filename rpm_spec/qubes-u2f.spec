%{!?version: %define version %(cat version)}
%define _builddir %(pwd)

Name:		qubes-u2f
Version:	%{version}
Release:	1%{?dist}
Summary:	Qubes OS U2F proxy

Group:		Qubes
License:	GPL2+
URL:		https://github.com/QubesOS/qubes-app-u2f

BuildArch:  noarch
BuildRequires:	python3-devel
BuildRequires:	python3-sphinx

Requires:	python3
Requires:	python3-u2flib-host

%description
Qubes OS U2F proxy

%prep
rm -f %{name}-%{version}
ln -sf . %{name}-%{version}
%setup -T -D

%build
make PYTHON=%{__python3}
make -C Documentation man SPHINXBUILD=sphinx-build-%{python3_version}

%install
make install \
    UNITDIR=%{_unitdir} \
    UDEVRULESDIR=%{_udevrulesdir} \
    DESTDIR=$RPM_BUILD_ROOT

make -C Documentation install \
	MANDIR=%{_mandir} \
    DESTDIR=$RPM_BUILD_ROOT

%files
%doc
%{_mandir}/man1/qu2f-*.1*
%{_mandir}/man8/qu2f-*.8*

%{_bindir}/qu2f-*
%{_bindir}/u2fdump
%{_sysconfdir}/qubes-rpc/u2f.Register
%{_sysconfdir}/qubes-rpc/u2f.Authenticate

%{_unitdir}/qubes-u2fproxy@.service
%{_udevrulesdir}/60-qu2f-hidraw.rules

%{python3_sitelib}/qubesu2f-%{version}-*.egg-info

%{python3_sitelib}/qubesu2f/__init__.py
%{python3_sitelib}/qubesu2f/__pycache__/*
%{python3_sitelib}/qubesu2f/const.py
%{python3_sitelib}/qubesu2f/hidemu.py
%{python3_sitelib}/qubesu2f/proto.py
%{python3_sitelib}/qubesu2f/uhid.py
%{python3_sitelib}/qubesu2f/util.py

%{python3_sitelib}/qubesu2f/tests/__init__.py
%{python3_sitelib}/qubesu2f/tests/__pycache__/*
%{python3_sitelib}/qubesu2f/tests/browser.py
%{python3_sitelib}/qubesu2f/tests/conformance.py
%{python3_sitelib}/qubesu2f/tests/qu2f_authenticate.py
%{python3_sitelib}/qubesu2f/tests/qu2f_proxy.py
%{python3_sitelib}/qubesu2f/tests/u2f_support_add_on-1.0.1-fx-linux.xpi

%{python3_sitelib}/qubesu2f/tools/__init__.py
%{python3_sitelib}/qubesu2f/tools/__pycache__/*
%{python3_sitelib}/qubesu2f/tools/qu2f_authenticate.py
%{python3_sitelib}/qubesu2f/tools/qu2f_proxy.py
%{python3_sitelib}/qubesu2f/tools/qu2f_register.py
%{python3_sitelib}/qubesu2f/tools/u2fdump.py
