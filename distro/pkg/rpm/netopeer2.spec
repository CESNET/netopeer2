Name: netopeer2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: Netopeer2 NETCONF tools suite
Url: https://github.com/CESNET/netopeer2
Source: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source2: netopeer2-server.service
License: BSD-3-Clause

BuildRequires: gcc
BuildRequires: cmake
BuildRequires: pkgconfig(libyang) >= 2.0.194
BuildRequires: pkgconfig(libnetconf2) >= 2.1.11
BuildRequires: pkgconfig(sysrepo) >= 2.1.64
BuildRequires: sysrepo-tools
BuildRequires: libcurl-devel
BuildRequires: libssh-devel
BuildRequires: openssl-devel
BuildRequires: systemd-devel
BuildRequires: systemd

Requires: %{name}-server%{?_isa} = %{version}-%{release}
Requires: %{name}-cli%{?_isa} = %{version}-%{release}


%package server
Summary: netopeer2 NETCONF server

Requires: libyang >= 2.0.231
# needed by script merge_hostkey.sh (run in post)
Requires: openssl
# needed by script setup.sh (run in post)
Requires: sysrepo-tools
# for provided systemd units
Requires: systemd


%package cli
Summary: netopeer2 NETCONF CLI client


%description
Virtual package for both netopeer2-server and netopeer2-cli NETCONF tools.

%description server
netopeer2-server is a server for implementing network configuration management based
on the NETCONF Protocol. This is the second generation, originally available
as the Netopeer project. Netopeer2 is based on the new generation of the
NETCONF and YANG libraries - libyang and libnetconf2. The Netopeer2 server
uses sysrepo as a NETCONF datastore implementation.

Server configuration is stored as "ietf-netconf-server" YANG module
data in sysrepo. They are accessible for "root" and any user beloning to
the group "netconf", which is created if it does not exist.

%description cli
netopeer2-cli is a complex NETCONF command-line client with support for
a single established NETCONF session.


%prep
%autosetup -p1

%build
%cmake -DCMAKE_BUILD_TYPE=RELWITHDEBINFO \
       -DINSTALL_MODULES=OFF \
       -DGENERATE_HOSTKEY=OFF \
       -DMERGE_LISTEN_CONFIG=OFF \
       -DSERVER_DIR=%{_libdir}/netopeer2-server
%cmake_build

%install
%cmake_install
install -D -p -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/netopeer2-server.service
mkdir -p -m=700 %{buildroot}%{_libdir}/netopeer2-server

%post server
set -e
export NP2_MODULE_DIR=%{_datadir}/yang/modules/netopeer2
export NP2_MODULE_PERMS=600
export NP2_MODULE_OWNER=root

%{_datadir}/netopeer2/setup.sh
%{_datadir}/netopeer2/merge_hostkey.sh
%{_datadir}/netopeer2/merge_config.sh

%systemd_post netopeer2-server.service

%preun server
set -e
%{_datadir}/netopeer2/remove.sh


%files
# just a virtual package requiring -cli and -server

%files server
%license LICENSE
%{_sbindir}/netopeer2-server
%{_datadir}/man/man8/netopeer2-server.8.gz
%{_unitdir}/netopeer2-server.service
%{_datadir}/yang/modules/netopeer2/*.yang
%{_datadir}/netopeer2/*.sh
%dir %{_datadir}/yang/modules/netopeer2/
%dir %{_datadir}/netopeer2/
%dir %{_libdir}/netopeer2-server/

%files cli
%license LICENSE
%{_bindir}/netopeer2-cli
%{_datadir}/man/man1/netopeer2-cli.1.gz

%changelog
* {{ now }} Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
