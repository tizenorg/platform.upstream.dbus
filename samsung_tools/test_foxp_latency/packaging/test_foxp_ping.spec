# 
# Do not Edit! Generated by:
# spectacle version 0.13
# 
# >> macros
# << macros

Name:       test_foxp_ping
Summary:    test_foxp_ping
Version:    1
Release:    1.0
Group:      System/Base
License:    GPLv2
URL:        none
Source0:    %{name}-%{version}.tar.gz
Source100:  test_foxp_ping.yaml
Source1001: %{name}.manifest
BuildRequires: pkgconfig(dbus-1)
#BuildRequires: pkgconfig(sqlite3)

%description
Test for foxp

%prep
%setup -q -n %{name}-%{version}

# >> setup
# << setup

%build
# >> build pre
# << build pre

cp %{SOURCE1001} .
make %{?jobs:-j%jobs}

# >> build post
# << build post
%install

