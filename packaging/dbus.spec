Name:		dbus
Summary:	D-Bus message bus with kdbus support
Version:	1.7.5+tv+kdbus
Release:	1
Group:		System/Libraries
License:	GPLv2+ or AFL
Source0:    	%{name}-%{version}.tar.gz
Source2:	dbus-user.socket
Source3:	dbus-user.service
Source4:	system.conf
Source5:	switch-to-dbus.sh
Source6:	switch-to-kdbus.sh
Source7:	conf_dbus.tar.gz
Source8:	conf_kdbus.tar.gz
BuildRequires:  which
BuildRequires:  expat-devel
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig(x11)


%description
D-Bus message bus with kdbus support

%package libs
Summary:    Libraries for accessing D-Bus
Group:      System/Libraries
#FIXME: This is circular dependency
Requires:   %{name} = %{version}-%{release}

%description libs
Lowlevel libraries for accessing D-Bus.

%package devel
Summary:    Libraries and headers for D-Bus
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   pkgconfig

%description devel
Headers and static libraries for D-Bus.

%prep
%setup -q -n %{name}-%{version}


%build
./autogen.sh --enable-abstract-sockets --enable-x11-autolaunch --with-x \
    --enable-kdbus-transport \
    --enable-kdbus-for-sbb \
    --disable-static \
    --exec-prefix=/ \
    --bindir=%{_bindir} \
    --libexecdir=%{_libdir}/dbus-1 \
    --sysconfdir=%{_sysconfdir} \
    --libdir=%{_libdir} \
    --includedir=%{_includedir} \
    --localstatedir=%{_localstatedir} \
    --docdir=%{_docdir} \
    --disable-asserts \
    --disable-xml-docs \
    --disable-selinux \
    --disable-libaudit \
    --enable-tests=no \
    --with-system-pid-file=%{_localstatedir}/run/messagebus.pid \
    --with-dbus-user=root \
    --with-systemdsystemunitdir=%{_libdir}/systemd/system

# When compiled using gbs with --enable-abstract-sockets param autogen.sh creates a config.h in
# /GBS-ROOT/local/BUILD-ROOTS/scratch.armv7l.0 with # /* #undef HAVE_ABSTRACT_SOCKETS */.
# Code changes it to #define HAVE_ABSTRACT_SOCKETS 1.
if grep -q "#define HAVE_ABSTRACT_SOCKETS\s1" config.h; then
	echo HAVE_ABSTRACT_SOCKETS found.
else
	echo HAVE_ABSTRACT_SOCKETS not found. Adding it.
	sed -i 's/\/\* #undef HAVE_ABSTRACT_SOCKETS \*\//#define HAVE_ABSTRACT_SOCKETS 1/' config.h
fi

make %{?jobs:-j%jobs}

%install
%make_install
%remove_docs

install -m644 %{SOURCE4} %{buildroot}/etc/dbus-1/system.conf.systemd
install -m644 %{SOURCE4} %{buildroot}/etc/dbus-1/system.conf

mkdir -p %{buildroot}%{_libdir}/pkgconfig
# Change the arch-deps.h include directory to /usr/lib instead of /lib
sed -e 's@-I${libdir}@-I${prefix}/%{_lib}@' %{buildroot}%{_libdir}/pkgconfig/dbus-1.pc

mkdir -p %{buildroot}%{_datadir}/dbus-1/interfaces

mkdir -p %{buildroot}%{_libdir}/systemd/user
install -m0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/user/dbus.socket
install -m0644 %{SOURCE3} %{buildroot}%{_libdir}/systemd/user/dbus.service

install -m0755 %{SOURCE5} %{buildroot}%{_bindir}/switch-to-dbus.sh
install -m0755 %{SOURCE6} %{buildroot}%{_bindir}/switch-to-kdbus.sh

tar -xvzf %{SOURCE7} -C %{buildroot}/etc/dbus-1
tar -xvzf %{SOURCE8} -C %{buildroot}/etc/dbus-1

%post
mkdir -p /opt/var/lib/dbus

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%{_bindir}/dbus-cleanup-sockets
%{_bindir}/dbus-daemon
%{_bindir}/dbus-monitor
%{_bindir}/dbus-send
%{_bindir}/dbus-uuidgen
%{_bindir}/dbus-launch
%{_bindir}/dbus-run-session
%dir %{_sysconfdir}/dbus-1
%config(noreplace) %{_sysconfdir}/dbus-1/session.conf
%dir %{_sysconfdir}/dbus-1/session.d
%config(noreplace) %{_sysconfdir}/dbus-1/system.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.conf.systemd
%dir %{_sysconfdir}/dbus-1/system.d
%dir %{_libdir}/dbus-1
%attr(4750,root,dbus) %{_libdir}/dbus-1/dbus-daemon-launch-helper
%{_libdir}/systemd/system/*
%{_libdir}/systemd/user/*
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/interfaces
%{_bindir}/switch-to-dbus.sh
%{_bindir}/switch-to-kdbus.sh
%{_sysconfdir}/dbus-1/conf_dbus
%{_sysconfdir}/dbus-1/conf_kdbus

%files libs
%{_libdir}/libdbus-1.so.3*

%files devel
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc
