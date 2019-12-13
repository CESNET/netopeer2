# Netopeer2 – The NETCONF Toolset

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://secure.travis-ci.org/CESNET/Netopeer2.png?branch=master)](http://travis-ci.org/CESNET/Netopeer2)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/8416/badge.svg)](https://scan.coverity.com/projects/8416)
[![Ohloh Project Status](https://www.openhub.net/p/Netopeer2/widgets/project_thin_badge.gif)](https://www.openhub.net/p/Netopeer2)

**Netopeer2** is a set of tools implementing network configuration tools based
on the NETCONF Protocol. This is the second generation of the toolset, originally
available as the [Netopeer project](https://github.com/CESNET/netopeer). Netopeer2
is based on the new generation of the NETCONF and YANG libraries -
[libyang](https://github.com/CESNET/libyang) and [libnetconf2](https://github.com/CESNET/libnetconf2).
The Netopeer server uses [sysrepo](https://github.com/sysrepo/sysrepo) as a NETCONF
datastore implementation.

**Netopeer2** is maintained and further developed by the [Tools for
Monitoring and Configuration](https://www.liberouter.org/) department of
[CESNET](http://www.ces.net/). Any feedback, testing or feature requests are welcome.
Please contact us via the [issue tracker](https://github.com/CESNET/Netopeer2/issues).

## Branches

The project uses 2 main branches `master` and `devel-server`. Other branches should not be cloned. In `master` there are files of the
last official *release*. Any latest improvements and changes (of the server), which were tested at least briefly are found
in `devel-server`. On every new *release*, `devel-server` is merged into `master`.

This means that when only stable official releases are to be used, either `master` can be used or specific *releases* downloaded.
If all the latest bugfixes should be applied, `devel-server` branch is the  one to be used. Note that whenever **a new issue is created**
and it occurs on the `master` branch, the **first response will likely be** to use `devel-server` before any further provided support.

## Components
- **CLI** - simple command line interface to connect to a NETCONF server (device).
- **server** - NETCONF server with a modular datastore allowing interconnection and control of
  various applications.
