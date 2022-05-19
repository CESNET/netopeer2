Name: netopeer2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: Netopeer2 NETCONF tools suite
Url: https://github.com/CESNET/netopeer2
Source: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source2: netopeer2-server.sysusers
Source3: netopeer2-server.service
License: BSD

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
BuildRequires: systemd-rpm-macros

%if 0%{?fedora}
# c_rehash needed by CLI
BuildRequires: openssl-perl
%endif

Requires: netopeer2-server
Requires: netopeer2-cli

%package server
Summary: netopeer2 NETCONF server

# needed by script setup.sh (run in post)
Requires: sysrepo-tools

# needed by script merge_hostkey.sh (run in post)
Requires: openssl

%package cli
Summary: netopeer2 NETCONF CLI client

%if 0%{?fedora}
Requires: openssl-perl
%endif

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
install -D -p -m 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/netopeer2-server.conf
install -D -p -m 0644 %{SOURCE3} %{buildroot}%{_unitdir}/netopeer2-server.service
mkdir -p -m=700 %{buildroot}%{_libdir}/netopeer2-server

%pre server
%if 0%{?fedora}
    %sysusers_create_compat %{SOURCE2}
%else
    usermod -a -G sysrepo root
%endif

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
%{_bindir}/netopeer2-server
%{_datadir}/man/man8/netopeer2-server.8.gz
%{_unitdir}/netopeer2-server.service
%{_sysusersdir}/netopeer2-server.conf
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
