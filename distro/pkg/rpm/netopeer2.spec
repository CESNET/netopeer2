Name: netopeer2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: Netopeer2 NETCONF server
Url: https://github.com/CESNET/netopeer2
Source: netopeer2-%{version}.tar.gz
License: BSD

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  cmake
BuildRequires:  pkgconfig(libyang) >= 2
BuildRequires:  pkgconfig(libnetconf2) >= 2
BuildRequires:  pkgconfig(sysrepo) >= 2
BuildRequires:  systemd-devel
BuildRequires:  systemd

# needed by scripts/setup.sh (run in post)
Requires: sysrepo-tools

# needed by scripts/merge_hostkey.sh (run in post)
Requires: openssl

%description
Netopeer2 is a server for implementing network configuration management based
on the NETCONF Protocol. This is the second generation, originally available
as the Netopeer project. Netopeer2 is based on the new generation of the
NETCONF and YANG libraries - libyang and libnetconf2. The Netopeer2 server
uses sysrepo as a NETCONF datastore implementation.

Netopeer2 configuration is stored as "ietf-netconf-server" YANG module
data in sysrepo. They are accessible for "root" and any user beloning to
the group "netconf", which is created if it does not exist.

%prep
%autosetup -p1
mkdir build

%build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX:PATH=%{_prefix} \
    -DCMAKE_BUILD_TYPE:String="Release" \
    -DINSTALL_MODULES=OFF \
    -DGENERATE_HOSTKEY=OFF \
    -DMERGE_LISTEN_CONFIG=OFF \
    -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${RPM_OPT_FLAGS}" \
    ..
make

%install
cd build
make DESTDIR=%{buildroot} install

%post
groupadd -f netconf

NP2_MODULE_DIR=%{_datadir}/yang/modules/netopeer2
NP2_MODULE_PERMS=660
NP2_MODULE_OWNER=root
NP2_MODULE_GROUP=netconf

{% include 'scripts/setup.sh' %}
{% include 'scripts/merge_hostkey.sh' %}
{% include 'scripts/merge_config.sh' %}

%postun
{% include 'scripts/remove.sh' %}

groupdel netconf &> /dev/null

%files
%license LICENSE
%{_bindir}/netopeer2-cli
%{_bindir}/netopeer2-server
%{_datadir}/man/man1/netopeer2-cli.1.gz
%{_datadir}/man/man8/netopeer2-server.8.gz
%{_unitdir}/netopeer2-server.service
%{_datadir}/yang/modules/netopeer2/*.yang
%dir %{_datadir}/yang/modules/netopeer2/

%changelog
* {{ now }} Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
