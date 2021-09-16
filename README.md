# Netopeer2 – NETCONF Server

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://secure.travis-ci.org/CESNET/Netopeer2.png?branch=master)](http://travis-ci.org/CESNET/Netopeer2)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/8416/badge.svg)](https://scan.coverity.com/projects/8416)
[![Ohloh Project Status](https://www.openhub.net/p/Netopeer2/widgets/project_thin_badge.gif)](https://www.openhub.net/p/Netopeer2)

**Netopeer2** is a server for implementing network configuration management based
on the NETCONF Protocol. This is the second generation, originally
available as the [Netopeer project](https://github.com/CESNET/netopeer). Netopeer2
is based on the new generation of the NETCONF and YANG libraries -
[libyang](https://github.com/CESNET/libyang) and [libnetconf2](https://github.com/CESNET/libnetconf2).
The Netopeer2 server uses [sysrepo](https://github.com/sysrepo/sysrepo) as a NETCONF
datastore implementation.

**Netopeer2** is maintained and further developed by the [Tools for
Monitoring and Configuration](https://www.liberouter.org/) department of
[CESNET](http://www.ces.net/). Any feedback, testing or feature requests are welcome.
Please contact us via the [issue tracker](https://github.com/CESNET/Netopeer2/issues).

## Branches

The project uses 2 main branches `master` and `devel`. Other branches should not be cloned. In `master` there are files of the
last official *release*. Any latest improvements and changes (of the server), which were tested at least briefly are found
in `devel`. On every new *release*, `devel` is merged into `master`.

This means that when only stable official releases are to be used, either `master` can be used or specific *releases* downloaded.
If all the latest bugfixes should be applied, `devel` branch is the  one to be used. Note that whenever **a new issue is created**
and it occurs on the `master` branch, the **first response will likely be** to use `devel` before any further provided support.

## Requirements

* [libyang](https://github.com/CESNET/libyang)
* [libnetconf2](https://github.com/CESNET/libnetconf2)
* [sysrepo](https://github.com/sysrepo/sysrepo)

## RFC Compliance

* [RFC 5277](https://www.rfc-editor.org/rfc/rfc5277.html) NETCONF Event Notifications
* [RFC 6022](https://datatracker.ietf.org/doc/html/rfc6022) YANG Module for NETCONF Monitoring
* [RFC 6241](https://datatracker.ietf.org/doc/html/rfc6241) Network Configuration Protocol (NETCONF)
* [RFC 6242](https://datatracker.ietf.org/doc/html/rfc6242) Using the NETCONF Protocol over Secure Shell (SSH)
* [RFC 6243](https://datatracker.ietf.org/doc/html/rfc6243) With-defaults Capability for NETCONF
* [RFC 6470](https://datatracker.ietf.org/doc/html/rfc6470) Network Configuration Protocol (NETCONF) Base Notifications
* [RFC 7589](https://datatracker.ietf.org/doc/html/rfc7589) Using the NETCONF Protocol over Transport Layer Security (TLS) with Mutual X.509 Authentication
* [RFC 8071](https://www.rfc-editor.org/rfc/rfc8071.html) NETCONF Call Home and RESTCONF Call Home
* [RFC 8341](https://datatracker.ietf.org/doc/html/rfc8341) Network Configuration Access Control Model
* [RFC 8525](https://datatracker.ietf.org/doc/html/rfc8525) YANG Library
* [RFC 8526](https://datatracker.ietf.org/doc/html/rfc8526) NETCONF Extensions to Support the Network Management Datastore Architecture
* [RFC 8639](https://www.rfc-editor.org/rfc/rfc8639.html) Subscription to YANG Notifications
* [RFC 8640](https://www.rfc-editor.org/rfc/rfc8640.html) Dynamic Subscription to YANG Events and Datastores over NETCONF
* [RFC 8641](https://www.rfc-editor.org/rfc/rfc8641.html) Subscription to YANG Notifications for Datastore Updates

## Compilation and installation

```
$ mkdir build; cd build
$ cmake ..
$ make
# make install
```

### Compilation options

The `netopeer2-server` requires *ietf-netconf-server* and all connected YANG modules to be installed in *sysrepo*
to work correctly. This is performed automatically during the installation process. Moreover, default
SSH configuration listening on all IPv4 interfaces and a newly generated SSH host key are imported
so that it can be connected to the server out-of-the-box. However, it may not always be desired
to perform all these steps even though the executed scripts check whether the modules/some configuration
already exist and do not repeat/overwrite any modules/configuration.

These are the options that affect the initial setup:
```
INSTALL_MODULES:ON
GENERATE_HOSTKEY:ON
MERGE_LISTEN_CONFIG:ON
```

If cross-compiling for a different architecture, you will likey want to turn all these options off
and then run the scripts `setup.sh`, `merge_hostkey.sh`, and `merge_config.sh` manually.

### Sysrepo callbacks

When implementing a *sysrepo* application with some callbacks, in case the particular event will be generated
by *netopeer2*, there will be the NETCONF session ID and NETCONF username of the originator NETCONF session provided.
It can be retrieved from the event *sysrepo* session and the originator name will be `netopeer2`. Following is
a table with the exact data format.

| Index | Type | Meaning |
|:----- |:----:|:-------:|
| 0 | `uint32_t` | NETCONF session ID |
| 1 | `char *` | NETCONF username |

It is also possible to communicate a specific NETCONF error back to the server. The error format must be `NETCONF`
and the meaning of every piece of data corresponds to the [rpc-error](https://tools.ietf.org/html/rfc6241#section-4.3)
elements. All the expected types are strings (`char *`). Arbitrary optional elements can be skipped by being set to
an empty string.

| Index | Mandatory | Name |
|:----- |:---------:|:----:|
| 0 | yes | `error-type` |
| 1 | yes | `error-tag` |
| 2 | yes | `error-message` |
| 3 | no | `error-app-tag` |
| 4 | no | `error-path` |
| n | no | `error-info` element |
| n + 1 | no | `error-info` value |

### CLI

A command-line NETCONF client `netopeer2-cli` is included and build/installed by default. This can be
adjusted by an option:
```
BUILD_CLI:ON
```

## NACM

This NETCONF server implements full *ietf-netconf-acm* access control that **bypasses** *sysrepo*
file system access control. NACM is enabled by default, so users other than `root` will not be
allowed to *write* any data but should be granted *read* and *execute* permissions unless
the access was modified by a NACM extension. When deploying this server, it is strongly advised
to configure NACM properly.

## Server configuration

Right after installation SSH listen and Call Home and TLS listen and Call Home are supported.
By default, only SSH listen configuration is imported so to enable any other connection methods,
they need to be configured manually. Example configuration XML files can be found in the `example_configuration`
directory. These files can be easily modified to create configuration specific for a particular
environment and configured authentication.

### SSH Call Home

To enable SSH Call Home, only `ssh_callhome.xml` file needs to be imported to *sysrepo* provided
that the default SSH host key `genkey` was imported into *ietf-keystore* configuration.

### TLS listen

To support clients connecting using TLS, configuration files `tls_keystore.xml`, `tls_truststore.xml`,
and `tls_listen.xml` needs to be merged into *sysrepo* configuration of modules *ietf-keystore*,
*ietf-truststore*, and *ietf-netconf-server*, respectively. After doing so, a NETCONF client can
connect using `client.crt` certificate and `client.key` private key and having `ca.pem` CA certificate
set as trusted. These example certificates can be found in `example_configuration/tls_certs`.
*netopeer2-cli* can easily be configured this way and the TLS connection tested.

Once connected, the client will be identified with `tls-test` NETCONF username.

### TLS Call Home

Using the same certificates and authorization options, a TLS client can be connected to using
Call Home when `tls_callhome.xml` file is imported. But `tls_keystore.xml` and `tls_truststore.xml`
need to be imported first.
