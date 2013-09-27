Name:		com.samsung.dbus
Summary:	D-Bus message bus with kdbus support
Version:	1.7.5
Release:	0
Group:		System/Libraries
License:	GPLv2+ or AFL
Source0:    	%{name}-%{version}.tar.gz
BuildRequires:  which
BuildRequires:  expat-devel
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig(x11)


%description
D-Bus message bus with kdbus support

%prep
%setup -q -n %{name}-%{version}


%build
./autogen.sh --enable-abstract-sockets --enable-x11-autolaunch --with-x

# When compiled using gbs with --enable-abstract-sockets param autogen.sh creates a config.h in
# /GBS-ROOT/local/BUILD-ROOTS/scratch.armv7l.0 with # /* #undef HAVE_ABSTRACT_SOCKETS */.
# Code changes it to #define HAVE_ABSTRACT_SOCKETS 1.
if grep -q "#define HAVE_ABSTRACT_SOCKETS\s1" config.h; then
	echo HAVE_ABSTRACT_SOCKETS found.
else
	echo HAVE_ABSTRACT_SOCKETS not found. Adding it.
	sed -i 's/\/\* #undef HAVE_ABSTRACT_SOCKETS \*\//#define HAVE_ABSTRACT_SOCKETS 1/' config.h
fi

#make %{?jobs:-j%jobs}
make -j8

%install

%post
mkdir -p /opt/var/lib/dbus


%files

