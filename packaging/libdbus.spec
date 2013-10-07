Name:           libdbus
Url:            http://dbus.freedesktop.org/
Summary:        Library package for D-Bus
License:        GPL-2.0+ or AFL-2.1
Group:          System/Libraries
Version:        1.6.12
Release:        0
Source0:        http://dbus.freedesktop.org/releases/dbus/dbus-%{version}.tar.gz

BuildRequires:  expat-devel
BuildRequires:  libtool
BuildRequires:  pkgconfig(libsmack)



%package -n dbus-devel
Summary:        Developer package for D-Bus
Group:          Development/Libraries
Requires:       libdbus = %{version}
Provides:       dbus-1



%description
D-Bus is a message bus system, a simple way for applications to talk to
one another. D-Bus supplies both a system daemon and a
per-user-login-session daemon. Also, the message bus is built on top of
a general one-to-one message passing framework, which can be used by
any two apps to communicate directly (without going through the message
bus daemon).



%description -n dbus-devel
D-Bus is a message bus system, a simple way for applications to talk to
one another. D-Bus supplies both a system daemon and a
per-user-login-session daemon. Also, the message bus is built on top of
a general one-to-one message passing framework, which can be used by
any two apps to communicate directly (without going through the message
bus daemon).



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
    --disable-static							\
    --with-pic								\
    --with-dbus-user=dbus						\
    --libexecdir=%{_libdir}/%{name}					\
    --libdir=%{_libdir}							\
    --with-init-scripts=suse						\
    --enable-inotify							\
    --with-console-auth-dir=/var/run/dbus/at_console/			\
    --with-systemdsystemunitdir=%{_unitdir}				\
    --enable-smack

make %{?_smp_mflags} -C dbus libdbus-1.la



%install
make DESTDIR=%{buildroot} -C dbus \
     lib_LTLIBRARIES=libdbus-1.la \
     install-libLTLIBRARIES \
     install-dbusincludeHEADERS \
     install-nodist_dbusarchincludeHEADERS

make DESTDIR=%{buildroot} install-pkgconfigDATA



%post -p /sbin/ldconfig



%postun -p /sbin/ldconfig



%files
%defattr(-, root, root)
%{_libdir}/libdbus-1.so.*
# Own those directories in the library instead of dbus-1, since dbus users
# often ship files there
#%dir %{_sysconfdir}/dbus-1
#%dir %{_sysconfdir}/dbus-1/session.d
#%dir %{_sysconfdir}/dbus-1/system.d
#%dir %{_datadir}/dbus-1
#%dir %{_datadir}/dbus-1/interfaces
#%dir %{_datadir}/dbus-1/services
#%dir %{_datadir}/dbus-1/system-services



%files -n dbus-devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libdbus-1.la
%{_libdir}/libdbus-1.so
%{_libdir}/dbus-1.0/include
%{_libdir}/pkgconfig/dbus-1.pc
%dir %{_libdir}/dbus-1.0
