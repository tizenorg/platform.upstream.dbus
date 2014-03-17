%define dbus_user_uid           81

Name:           libdbuspolicy
Url:            http://dbus.freedesktop.org/
Summary:        helper library for fine-grained userspace policy handling
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
Version:        1.6.12
Release:        0
Source0:        http://dbus.freedesktop.org/releases/dbus/dbus-%{version}.tar.gz
Source1:        rc.boot.dbus
Source3:        dbus_at_console.ck
Source4:        baselibs.conf
Source5:        dbus-user.service
Source6:        dbus-user.socket
BuildRequires:  libcap-ng-devel
BuildRequires:  pkgconfig(libsmack)
# COMMON1-END
Requires(pre):  /usr/sbin/groupadd /usr/sbin/useradd

%description
libdbuspolicy is a helper library for fine-grained userspace
policy handling (with SMACK support)

%prep
# COMMON2-BEGIN
%setup -n dbus-%{version} -q

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
%if %{with_systemd}
    --enable-systemd							\
%endif
    --with-console-auth-dir=/var/run/dbus/at_console/			\
    --with-systemdsystemunitdir=%{_unitdir}				\
    --enable-verbose-mode                                               \
    --enable-smack

make %{?_smp_mflags}

%install
# COMMON2-END
make DESTDIR=%{buildroot} install
make DESTDIR=%{buildroot} install-pkgconfigDATA

# File packaged by dbus, dbus-devel and libdbus

rm -rf %{buildroot}/%{_libdir}/libdbus-1.*
rm -rf %{buildroot}/%{_libdir}/libdbuspolicy/dbus*
rm -rf %{buildroot}/%{_libdir}/dbus-1.0
rm -rf %{buildroot}/%{_libdir}/pkgconfig

rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-types.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-threads.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-syntax.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-signature.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-shared.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-server.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-protocol.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-pending-call.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-misc.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-message.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-memory.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-macros.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-errors.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-connection.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-bus.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus-address.h
rm -rf %{buildroot}/%{_includedir}/dbus-1.0/dbus/dbus.h

rm -rf %{buildroot}/%{_mandir}/man1/dbus*
rm -rf %{buildroot}/%{_bindir}/dbus*

rm -rf %{buildroot}/%{_sysconfdir}/dbus-1/*
rm -rf %{buildroot}/%{_sysconfdir}/ConsoleKit

rm -rf %{buildroot}/%{_datadir}/doc/dbus
rm -rf %{buildroot}/%{_unitdir}/*

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libdbuspolicy-1.so.*
%{_libdir}/libdbuspolicy-1.la
%{_libdir}/libdbuspolicy-1.so

%changelog
