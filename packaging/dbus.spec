%define dbus_user_uid           81

Name:           dbus
Url:            http://dbus.freedesktop.org/
Summary:        D-Bus Message Bus System
License:        GPL-2.0+ or AFL-2.1
Group:          Base/IPC
# COMMON1-BEGIN

%define with_systemd 1

BuildRequires:  doxygen
BuildRequires:  expat-devel
BuildRequires:  libtool
BuildRequires:  libxslt-tools
BuildRequires:  libzio
BuildRequires:  pkg-config
BuildRequires:  xmlto
%if %{with_systemd}
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(libsystemd-login)
%endif
Version:        1.8.2
Release:        0
Source0:        http://dbus.freedesktop.org/releases/dbus/dbus-%{version}.tar.gz
Source1:        rc.boot.dbus
Source3:        dbus_at_console.ck
Source4:        baselibs.conf
Source5:        dbus-user.service
Source6:        dbus-user.socket
Source7:        dbus.sh
Source1001:     dbus.manifest
BuildRequires:  libcap-ng-devel
BuildRequires:  pkgconfig(libsmack)
# COMMON1-END
Requires(pre):  /usr/sbin/groupadd /usr/sbin/useradd
Provides:       dbus-1



%package devel-doc

Summary:        Developer documentation package for D-Bus
Group:          Documentation
Requires:       %{name} = %{version}
BuildArch:      noarch

%description
D-Bus is a message bus system, a simple way for applications to talk to
one another. D-Bus supplies both a system daemon and a
per-user-login-session daemon. Also, the message bus is built on top of
a general one-to-one message passing framework, which can be used by
any two apps to communicate directly (without going through the message
bus daemon).

%description devel-doc
D-Bus is a message bus system, a simple way for applications to talk to
one another. D-BUS supplies both a system daemon and a
per-user-login-session daemon. Also, the message bus is built on top of
a general one-to-one message passing framework, which can be used by
any two apps to communicate directly (without going through the message
bus daemon).

%prep
# COMMON2-BEGIN
%setup -n dbus-%{version} -q
cp %{SOURCE1001} .

%build
autoreconf -fi
# We use -fpie/-pie for the whole build; this is the recommended way to harden
# the build upstream, see discussion in fdo#46570
export CFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing -fPIC -fpie"
export LDFLAGS="-pie"
export CXXFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing"
export CFLAGS="$CFLAGS -fstack-protector"
export CXXFLAGS="$CXXFLAGS -fstack-protector"
export V=1
%configure \
    --disable-static 							\
    --with-pic 								\
    --with-dbus-user=dbus 						\
    --libexecdir=%{_libdir}/%{name}					\
    --libdir=%{_libdir}							\
    --with-init-scripts=suse						\
    --enable-inotify							\
    --enable-doxygen-docs						\
%if %{with_systemd}
    --enable-systemd							\
%endif
    --with-console-auth-dir=/var/run/dbus/at_console/			\
    --with-systemdsystemunitdir=%{_unitdir}				\
    --enable-smack

make %{?_smp_mflags}

%install
# COMMON2-END
make DESTDIR=%{buildroot} install
mkdir -p %{buildroot}/usr/sbin
install -d %{buildroot}/%{_localstatedir}/run/dbus
mkdir -p %{buildroot}/%{_libdir}/pkgconfig
mkdir -p %{buildroot}/lib/dbus-1/system-services
mkdir -p %{buildroot}/%{_datadir}/dbus-1/system-services
mkdir -p %{buildroot}/%{_datadir}/dbus-1/interfaces
#
chmod a-x AUTHORS COPYING HACKING NEWS README doc/*.txt doc/file-boilerplate.c doc/TODO
#
install -d %{buildroot}%{_sysconfdir}/ConsoleKit/run-session.d
install -m 755 %{SOURCE3} %{buildroot}%{_sysconfdir}/ConsoleKit/run-session.d
mkdir -p %{buildroot}%{_localstatedir}/lib/dbus
touch %{buildroot}/%{_localstatedir}/lib/dbus/machine-id

mkdir -p %{buildroot}%{_unitdir_user}
install -m0644 %{SOURCE5} %{buildroot}%{_unitdir_user}/dbus.service
install -m0644 %{SOURCE6} %{buildroot}%{_unitdir_user}/dbus.socket
# File packaged by libdbus and dbus-devel
rm -rf %{buildroot}/%{_includedir}/*
rm -rf %{buildroot}/%{_libdir}/*.la
rm -rf %{buildroot}/%{_libdir}/libdbus-1.so
rm -rf %{buildroot}/%{_libdir}/libdbus-1.so.*
rm -rf %{buildroot}/%{_libdir}/dbus-1.0/include
rm -rf %{buildroot}/%{_libdir}/pkgconfig/dbus-1.pc
rm -rf %{buildroot}/%{_mandir}/man1/dbus-launch.1*
rm -rf %{buildroot}/%{_bindir}/dbus-launch

# install script for login shells (/etc/profile.d)
install -d %{buildroot}%{_sysconfdir}/profile.d
install -m0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/profile.d/dbus.sh

%pre
# Add the "dbus" user and group
/usr/sbin/groupadd -r -g %{dbus_user_uid} dbus 2>/dev/null || :
/usr/sbin/useradd -c 'System message bus' -u %{dbus_user_uid} -g %{dbus_user_uid} \
        -s /sbin/nologin -r -d '/' dbus 2> /dev/null || :

%docs_package
%manifest dbus.manifest

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%dir %{_localstatedir}/lib/dbus
%dir /lib/dbus-1
%dir /lib/dbus-1/system-services
%license  COPYING
%config(noreplace) %{_sysconfdir}/dbus-1/session.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.conf
%{_sysconfdir}/ConsoleKit
%{_bindir}/dbus-cleanup-sockets
%{_bindir}/dbus-daemon
%{_bindir}/dbus-monitor
%{_bindir}/dbus-run-session
%{_bindir}/dbus-send
%{_bindir}/dbus-uuidgen
# See doc/system-activation.txt in source tarball for the rationale
# behind these permissions
%attr(4750,root,dbus) %verify(not mode) %{_libdir}/dbus/dbus-daemon-launch-helper
%ghost %{_localstatedir}/run/dbus
%ghost %{_localstatedir}/lib/dbus/machine-id
%dir %{_unitdir}
%{_unitdir}/dbus.service
%{_unitdir}/dbus.socket
%{_unitdir_user}/dbus.service
%{_unitdir_user}/dbus.socket
%dir %{_unitdir}/dbus.target.wants
%{_unitdir}/dbus.target.wants/dbus.socket
%dir %{_unitdir}/multi-user.target.wants
%{_unitdir}/multi-user.target.wants/dbus.service
%dir %{_unitdir}/sockets.target.wants
%{_unitdir}/sockets.target.wants/dbus.socket
%dir %{_sysconfdir}/dbus-1
%dir %{_sysconfdir}/dbus-1/session.d
%dir %{_sysconfdir}/dbus-1/system.d
%dir %{_datadir}/dbus-1
%dir %{_datadir}/dbus-1/interfaces
%dir %{_datadir}/dbus-1/services
%dir %{_datadir}/dbus-1/system-services
%{_sysconfdir}/profile.d/dbus.sh

%files devel-doc
%manifest %{name}.manifest
%defattr(-,root,root)
%dir %{_datadir}/doc/dbus
%{_datadir}/doc/dbus/api/
%doc %{_datadir}/doc/dbus/dbus-cleanup-sockets.1.html
%doc %{_datadir}/doc/dbus/dbus-daemon.1.html
%doc %{_datadir}/doc/dbus/dbus-faq.html
%doc %{_datadir}/doc/dbus/dbus-launch.1.html
%doc %{_datadir}/doc/dbus/dbus-monitor.1.html
%doc %{_datadir}/doc/dbus/dbus-run-session.1.html
%doc %{_datadir}/doc/dbus/dbus-send.1.html
%doc %{_datadir}/doc/dbus/dbus-specification.html
%doc %{_datadir}/doc/dbus/dbus-test-plan.html
%doc %{_datadir}/doc/dbus/dbus-tutorial.html
%doc %{_datadir}/doc/dbus/dbus-uuidgen.1.html
%doc %{_datadir}/doc/dbus/dbus.devhelp
%doc %{_datadir}/doc/dbus/diagram.*
%doc %{_datadir}/doc/dbus/system-activation.txt
%doc doc/*.txt doc/file-boilerplate.c doc/TODO

%changelog
