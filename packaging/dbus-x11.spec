#
# spec file for package dbus-x11
#
# Copyright (c) 2012 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           dbus-x11
%define _name   dbus
BuildRequires:  pkgconfig(x11)
Url:            http://dbus.freedesktop.org/
Summary:        D-Bus Message Bus System
License:        GPL-2.0+ or AFL-2.1
Group:          System/Daemons
# COMMON1-BEGIN
# COMMON1-BEGIN

# We can't enable this right now, because it will create a build cycle between
# dbus-1 and systemd. Fun!
%define with_systemd 0

BuildRequires:  doxygen
BuildRequires:  expat-devel
BuildRequires:  libtool
BuildRequires:  libzio
BuildRequires:  pkg-config
%if %{with_systemd}
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(libsystemd-login)
%endif
Version:        1.5.12
Release:        0
Source0:        http://dbus.freedesktop.org/releases/dbus/%{_name}-%{version}.tar.gz
Source1:        rc.boot.dbus
Source3:        dbus_at_console.ck
Source4:        baselibs.conf
Patch0:         dbus-log-deny.patch
# PATCH-FIX-OPENSUSE coolo@suse.de -- force a feature configure won't accept without x11 in buildrequires
Patch1:         dbus-do-autolaunch.patch
Patch2:         dbus-cve-2012-3524.patch
BuildRequires:  libcap-ng-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
# COMMON1-END
# COMMON1-END

%description
D-Bus contains some tools that require Xlib to be installed, those are
in this separate package so server systems need not install X.

%prep
# COMMON2-BEGIN
# COMMON2-BEGIN
%setup -n %{_name}-%{version} -q
%patch0 -p1
%patch1 -p1
%patch2 -p1

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
    --bindir=/bin							\
    --libexecdir=/lib/%{name}					\
    --libdir=/%{_lib}							\
    --with-init-scripts=suse						\
    --enable-inotify							\
    --enable-doxygen-docs						\
%if %{with_systemd}
    --enable-systemd							\
%endif
    --with-console-auth-dir=/var/run/dbus/at_console/			\
    --with-systemdsystemunitdir=/lib/systemd/system                     
make %{?_smp_mflags}
doxygen -u && doxygen
./cleanup-man-pages.sh

%install
# COMMON2-END
# COMMON2-END
tdir=$(mktemp -d)
make DESTDIR=$tdir install
mkdir -p %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_mandir}/man1
mv $tdir/bin/dbus-launch %{buildroot}/%{_bindir}
mv $tdir/%{_mandir}/man1/dbus-launch.1* %{buildroot}/%{_mandir}/man1
rm -rf $tdir

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root)
%{_bindir}/dbus-launch
%{_mandir}/man1/dbus-launch.1*

%changelog
