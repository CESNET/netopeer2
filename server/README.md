# Netopeer2 NETCONF server

## Requirements

* [libyang](https://github.com/CESNET/libyang)
* [libnetconf2](https://github.com/CESNET/libnetconf2)
* [sysrepo](https://github.com/sysrepo/sysrepo)

## Compilation and installation

```
$ mkdir build; cd build
$ cmake ..
$ make
# make install
```

### Compilation options

The server requires *ietf-netconf-server* and all connected YANG modules to be installed in *sysrepo*
to work correctly. This is performed autmatically during the installation process. Moreover, default
SSH configuration listening on all IPv4 interfaces and a newly generated SSH host key are imported
so that it can be connected to the server out-of-the-box. However, it may not always be desired
to perform all these steps.

These are the options that affect the initial setup:
```
INSTALL_MODULES:ON
GENERATE_HOSTKEY:ON
MERGE_LISTEN_CONFIG:ON
DEFAULT_HOSTKEY:genkey
```

For example, if there is already a host key imported in *ietf-keystore* configuration in *sysrepo*,
you can adjust these options so that the default listen configuration uses it:
```
INSTALL_MODULES:ON
GENERATE_HOSTKEY:OFF
MERGE_LISTEN_CONFIG:ON
DEFAULT_HOSTKEY:<imported-key-name>
```

If cross-compiling for a different architecture, you will likey want to turn all these options off
and then run the scripts `setup.sh`, `merge_hostkey.sh`, and `merge_config.sh` manually:
```
INSTALL_MODULES:OFF
GENERATE_HOSTKEY:OFF
MERGE_LISTEN_CONFIG:OFF
```

## NACM

This NETCONF server implements full *ietf-netconf-acm* access control that **bypasses** *sysrepo*
file system access control. However, NACM is disabled by default meaning all clients that successfully
authenticate and establish a NETCONF session have **unrestricted access to all configuration** stored
in *sysrepo*. Therefore, when deploying this server, it is strongly advised to enable NACM and
configure it properly.

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
