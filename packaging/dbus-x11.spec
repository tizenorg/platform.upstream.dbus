%bcond_with x

Name:           dbus-x11
%define _name   dbus
BuildRequires:  pkgconfig(x11)
Url:            http://dbus.freedesktop.org/
License:        GPL2+ or AFL 2.1
Group:          Base/IPC
Summary:        D-Bus Message Bus System
# COMMON1-BEGIN
# COMMON1-BEGIN

# We can't enable this right now, because it will create a build cycle between
# dbus-1 and systemd. Fun!
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
Source1001: 	dbus-x11.manifest
BuildRequires:  libcap-ng-devel
BuildRequires:  pkgconfig(libsmack)
# COMMON1-END
# COMMON1-END

%if !%{with x}
ExclusiveArch:
%endif

%description
D-Bus contains some tools that require Xlib to be installed, those are
in this separate package so server systems need not install X.

%prep
# COMMON2-BEGIN
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
# COMMON2-END
tdir=$(mktemp -d)
make DESTDIR=$tdir install
mkdir -p %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_mandir}/man1
mv $tdir/%{_bindir}/dbus-launch %{buildroot}/%{_bindir}
mv $tdir/%{_mandir}/man1/dbus-launch.1* %{buildroot}/%{_mandir}/man1
rm -rf $tdir

%clean
%{__rm} -rf %{buildroot}

%files
%manifest %{name}.manifest
%defattr(-,root,root)
%{_bindir}/dbus-launch
%{_mandir}/man1/dbus-launch.1*

%changelog
