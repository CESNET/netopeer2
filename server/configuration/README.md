# Server Configuration

## How to Enable Configuration

For the server configuration to work you must have *sysrepo*, *keystored*, and *netopeer2-server* **installed** (`# make install`). **Critical** in having the configuration functional is paying attention to what installations of *keystored* and *netopeer2-server* display. In other words, whenever a problem is encountered, it should be displayed how to solve it. Best case scenario (all fairly recent and properly configured systems), you simply install all the applications and the configuration works out-of-the-box.

Having installed it all successfully, you need to start in order *sysrepo*, *sysrepo-plugind* (*keystored* plugin is enabled this way), and *netopeer2-server*. Among the last messages the server should inform about the reason for not using its configuration, if that is the case. Otherwise, if run with verbosity at least `-v2`, it should print information about applying the startup configuration. Then you know the configuration works properly.

## Basic Information

Next sections describe how to configure various parts of *netopeer2-server* with examples so that everything can be tried. All parts of the configuration include functional examples, but be careful not to use them on a server that is accessible publicly! The configuration includes a lot of testing authentication entries which could be abused as all of the certificates and private keys can be used by anyone.

All of the examples and explanations are based on the YANG models *ietf-netconf-server* (and its imports *ietf-ssh-server* and *ietf-tls-server*), *ietf-keystore*, *ietf-system*, and *ietf-x509-cert-to-name*. If you do not fully understand or wonder about something not covered here, feel free to look directly into those models (current copies can be found in `/netopeer2/modules`) for additional information.

Lastly, the snippets in all the *Configure* and *Action* sections are simplified parts of *tree* output of *yanglint* with brief explanation of the node meaning in some cases. *Choices*, *cases* and *features* were removed (in most cases) to reduce clutter because they can be ignored when configuring particular functionality. If you want to set some configuration, just follow the diagram to create a coresponding XML or use modified versions of the prepared XMLs. Once you have your XML, you can use it in either `edit-config` (configuration) or `user-rpc` (action) commands in *netopeer2-cli*.

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw session-options
          +--rw hello-timeout?   uint16 <600> (in seconds)
```

## Listen

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw listen
          +--rw max-sessions?   uint16 <0> (0 means unlimited)
          +--rw idle-timeout?   uint16 <3600> (in seconds)
```

### SSH

Testing SSH listen configuration is set during server installation because in this basic form is not a security risk (the usernames and passwords are read from the local system). With this configuration (`../stock_config.xml`) the server should listen on all IPv4 interfaces (0.0.0.0) on the port 830.

Also, the server must use a private key to authenticate to the client. A default OpenSSH RSA host key is imported during installation if available. Otherwise a host key must be loaded or generated manually (section [Private Keys](#private-keys)).

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw listen
          +--rw endpoint* [name]
             +--rw name         string (arbitrary string only for identification)
                +--rw ssh
                   +--rw address?            ietf-inet-types:ip-address
                   +--rw port?               ietf-inet-types:port-number <830>
                   +--rw host-keys
                      +--rw host-key* [name]
                         +--rw name           string (arbitrary string only for identification)
                         +--rw public-key?    -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:name
```

### TLS

To set up TLS listen, you first need to import server certificate private key. How to do so is described in the section [Private Keys](#private-keys). Then you need to configure the corresponding certificate. Use `load_server_certs.xml` to do this. It simply adds the certificate `tls/server.crt` content to the imported server key. In addition to that, it sets `tls/ca.pem` as a trusted CA certificate (more in [Trusted Certificates](#trusted-certificates)). This Certificate Authority was used to sign `tls/server.crt` and `tls/client.crt`.

Now that certificates are set, you can configure TLS listen itself. In the XML `tls_listen.xml`, which you need to send to the server, you will see that again all IPv4 interfaces are listened on and the port used si the default TLS one, 6513. Other than that, the server will use the certificate *test_server_cert* we configured in the step before.

Lastly, if a client authenticates using this configuration, their username will resolve to **test** (more information in [TLS cert-to-name Authentication](#tls-cert-to-name-authentication)). It is required that this username exists on the local system (just like for SSH), so you will need to (temporarily) create this user. The simplest way is executing `# useradd -MN test`, which creates the user without a home directory and user group.

#### Client

For a NETCONF client to connect to *netopeer2-server* listening for TLS connections as described above, it must use testing certificates for authentication. Following are the commands to configure this and connect using *netopeer2-cli* on `localhost` (paths relative to this directory).

```
cert add tls/ca.pem
cert replaceown tls/client.crt tls/client.key
connect --tls

```

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw listen
          +--rw endpoint* [name]
             +--rw name         string
                 +--rw tls
                   +--rw address?        ietf-inet-types:ip-address
                   +--rw port?           ietf-inet-types:port-number <6513>
                   +--rw certificates
                   |  +--rw certificate* [name]
                   |     +--rw name    -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:certificate-chains/ietf-keystore:certificate-chain/ietf-keystore:name
                   +--rw client-auth
                      +--rw trusted-ca-certs?       -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
                      +--rw trusted-client-certs?   -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
                      +--rw cert-maps (refer to TLS cert-to-name Authentication section)
                         ...
```

## Call Home

Call Home is a mechanism to enable servers to connect to clients instead the other way around. Every `netconf-client`, independently of the transport protocol, can be set up to use one of connection types and what reconnect strategy to use. The node names are quite self-explaning and for more details please look into *ietf-netconf-server*. Nevertheless, you should be fine if you leave all this values default, you just need to select the connection type.

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw call-home
          +--rw netconf-client* [name]
             +--rw name                  string
             +--rw connection-type
             |  +--rw (connection-type)?
             |     +--:(persistent-connection)
             |     |  +--rw persistent!
             |     |     +--rw idle-timeout?   uint32 <86400>
             |     +--:(periodic-connection)
             |        +--rw periodic!
             |           +--rw idle-timeout?        uint16 <300>
             |           +--rw reconnect-timeout?   uint16 <60>
             +--rw reconnect-strategy
                +--rw start-with?     enumeration <first-listed>
                +--rw max-attempts?   uint8 <3>
```

### SSH

Configuring SSH Call Home is no more difficult than configuring listening as the same parameters need to be set. The prepared XML `ssh_callhome.xml` includes connecting to a NETCONF client listening on `localhost`.

#### Client

To connect to *netopeer2-server* using Call Home on local machine, you can use this *netopeer2-cli* command. No parameters need to be set because all of the values are default.

```
listen
```

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw call-home
          +--rw netconf-client* [name]
             +--rw name                  string
                +--rw ssh
                   +--rw endpoints
                   |  +--rw endpoint* [name]
                   |     +--rw name       string
                   |     +--rw address    ietf-inet-types:host
                   |     +--rw port?      ietf-inet-types:port-number <4334>
                   +--rw host-keys
                      +--rw host-key* [name]
                         +--rw name             string
                            +--rw public-key?    -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:name
```

### TLS

For working TLS listen you are going to need to have imported server certificate and applied `load_server_certs.xml` (follow instructions in [Listen TLS](#tls)). Other than that, you need to set the Call Home configuration, which is prepared in `tls_callhome.xml`. Meaning of each node is similar to TLS listen nodes.

#### Client

Having set up client and trusted certificates the same way as for [Listen TLS Client](#client), just use the following *netopeer2-cli* command.

```
listen --tls
```

#### Configure

```
module: ietf-netconf-server
    +--rw netconf-server
       +--rw call-home
          +--rw netconf-client* [name]
             +--rw name                  string
                +--rw tls
                   +--rw endpoints
                   |  +--rw endpoint* [name]
                   |     +--rw name       string
                   |     +--rw address    ietf-inet-types:host
                   |     +--rw port?      ietf-inet-types:port-number <4335>
                   +--rw certificates
                   |  +--rw certificate* [name]
                   |     +--rw name    -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:certificate-chains/ietf-keystore:certificate-chain/ietf-keystore:name
                   +--rw client-auth
                      +--rw trusted-ca-certs?       -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
                      +--rw trusted-client-certs?   -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
                      +--rw cert-maps (refer to TLS cert-to-name Authentication section)
                         ...
```

### SSH publickey Authentication

In all the SSH examples you used either `password` or `interactive` authentication. It is also possible to use `publickey` authentication, but it needs to be configured. In this example, there is a prepared XML `load_auth_pubkey.xml`, but it needs to be filled with actual values first and only then sent to the server.

Now it will be explained how to make the SSH key for your account authorized so you can connect to the server using your current username (that is the most common and simple case). There is a prerequisite of having a SSH key pair generated. If you are unsure, check whether `~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub` files exist. If they do, you are fine, if not, you can use OpenSSH `ssh-keygen(1)` utility to generate them. Now open the public key (`~/.ssh/id_rsa.pub`) in a text editor. The file should look like this:

```
[key-algorithm] [key-data] [system-username]@[system-hostname]
```

If you open `load_auth_pubkey.xml`, you will see where you should copy the first 3 strings (`system-hostname` is not required). In addition to that, fill `[arbitrary-key-name]` with any value you want to identify this key with. After you send this modified XML using `edit-config` to the server, if the user `[system-username]` tries to authenticate using `publickey` authentication method with this particular key, they will succeed.

#### Client

Here it will be explained how to use *netopeer2-cli* to connect to a properly configured server (having performed what is described above) using `publickey` authentication. The first step, albeit optional, is giving `publickey` authentication the highest preference so that it is used first. The command `auth pref` will show the current preferences so just change it so that `publickey` has the highest value.

Next, you need to configure *netopeer2-cli* to use your SSH key for authentication. The command `auth keys` will display the keys that are currently used. If set properly and using the default OpenSSH keypair, you should see it. If not, just add your keys using `auth keys add` and then check again. Now if you try to connect to the server using either `connect` or `listen`, the key should be used automatically and you should not be asked for your password (except when the key you used is encrypted, then you always need to provide the passphrase for its decryption).

#### Configure

```
module: ietf-system
    +--rw system
       +--rw authentication
          +--rw user* [name]
             +--rw name              string
             +--rw authorized-key* [name]
                +--rw name         string
                +--rw algorithm    string
                +--rw key-data     binary
```

### TLS cert-to-name Authentication

NETCONF requires the transport protocol it communicates on to provide it with a username. In TLS this is a problem because authentication is based on certificates and not usernames. So, a mechanism was designed to get usernames from certificates called **cert-to-name**.

All TLS connection configuration includes the `cert-maps` container, which specifies exactly how the usernames are to be assigned to clients based on the certificate they present themselves with. For detailed explanation of all the ways this can be performed please look into *ietf-x509-cert-to-name*. The testing TLS authentication works directly with the client certificate (which is generally discouraged, but suits well for testing). `fingerprint` is that of `tls/client.crt` and once it matches, `map-type` says that a specific username should be used, the one specified in `name`.

The preferred approach, and one much more suitable for actual deployment, is to specify a `fingerprint` of a Certificate Authority that was used to sign more client certificates. Then `map-type` can be set to read the specific username from a field in the client certificate such as *Subject Alternative Name*. This way one CTN entry is used to authenticate several clients.

#### Configure

```
module: ietf-netconf-server
    ...
    +--rw cert-maps
       +--rw cert-to-name* [id]
          +--rw id             uint32
          +--rw fingerprint    ietf-x509-cert-to-name:tls-fingerprint
          +--rw map-type       identityref
          +--rw name           string
```

### Private Keys

To use additional private keys (add them to the *sysrepo* datastore) 2 actions from *ietf-keystore* can be used. To generate a new private key, the action **generate-private-key** is used. You can try it using *netopeer2-cli* command `user-rpc` with the content of `generate_private_key.xml`, but be aware of an issue with name uniqueness ([Known Issues](#known-issues)).

If you have a private key and just want to import it into *sysrepo*, use **load-private-key**. When setting up [TLS](#tls), you will need to import the key `tls/server.key`, which is prepared in `load_server_key.xml`. Again, be aware of [Known Issues](#known-issues).

#### Action

```
module: ietf-keystore
    +--rw keystore
       +--rw private-keys
          +--rw private-key* [name]
          +---x generate-private-key
          |  +---w input
          |     +---w name          string
          |     +---w algorithm     identityref
          |     +---w key-length?   uint32
          +---x load-private-key
             +---w input
                +---w name           string
                +---w private-key    binary
```

### Trusted Certificates

This configuration part is quite simple as it only adds trusted certificates that can then be referenced from TLS listen and Call Home configurations. It is a kind of trusted certificate store for NETCONF, your system and browsers have their own, too. However, in comparison, you can include client certificates themselves here as well and then use them in any TLS endpoint if you want to consider trusted only the one particular client and not all client certificates signed by that Certificate Authority.

#### Configure

```
module: ietf-keystore
    +--rw keystore
       +--rw trusted-certificates* [name]
          +--rw name                   string
          +--rw description?           string
          +--rw trusted-certificate* [name]
             +--rw name           string
             +--rw certificate?   binary
```

## Known Issues

All of the modules are still drafts and specially *ietf-keystore* has some issues that are yet to be solved. Partly because of this, private key management has some shortcomings:

- probably most importantly, **only RSA** keys are supported at the moment,
- uniqueness of `private-key` `name` key values is not checked, which means that if a key with an existing name is loaded/generated, it will overwrite the existing one,
- private keys themselves only support `running` datastore, which actually acts as a `startup` as well,
- `key-length` of a key is never returned,
- `generate-certificate-signing-request` action is not supported,
- `certificate-expiration` is not checked and the notification is never generated,
- NETCONF client configuration is completely custom and hence the whole subtree `user-auth-credentials` is not supported.

As for *ietf-netconf-server*, these are the limitations:

- `ssh-x509-certs` feature is not supported meaning X509 certificates cannot be used for SSH authentication,
- Call Home persistent connection does not send keep-alives and track client aliveness this way.

The unsupported configuration subtrees are also below.

### Non-implemented Configuration

```
module: ietf-keystore
    +--rw keystore
       +--rw private-keys
       |  +--rw private-key*
             +--ro key-length?           uint32
       |     +---x generate-certificate-signing-request
       |        +---w input
       |        |  +---w subject       binary
       |        |  +---w attributes?   binary
       |        +--ro output
       |           +--ro certificate-signing-request    binary
       +--rw trusted-ssh-host-keys* [name]
       |  +--rw name                string
       |  +--rw description?        string
       |  +--rw trusted-host-key* [name]
       |     +--rw name        string
       |     +--rw host-key    binary
       +--rw user-auth-credentials
          +--rw user-auth-credential* [username]
             +--rw username       string
             +--rw auth-method* [priority]
                +--rw priority     uint8
                +--rw (auth-type)?
                   +--:(certificate)
                   |  +--rw certificate*           -> /keystore/private-keys/private-key/certificate-chains/certificate-chain/name
                   +--:(public-key)
                   |  +--rw public-key*            -> /keystore/private-keys/private-key/name
                   +--:(ciphertext-password)
                   |  +--rw ciphertext-password?   string
                   +--:(cleartext-password)
                      +--rw cleartext-password?    string

  notifications:
    +---n certificate-expiration
       +--ro certificate        instance-identifier
       +--ro expiration-date    ietf-yang-types:date-and-time

module: ietf-netconf-server
    +--rw netconf-server
       +--rw listen
       |  +--rw endpoint*
       |     +--rw ssh
       |        +--rw host-keys
       |        |  +--rw host-key*
       |        |     +--rw (host-key-type)
       |        |        +--:(certificate) {ietf-ssh-server:ssh-x509-certs}?
       |        |           +--rw certificate?   -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:certificate-chains/ietf-keystore:certificate-chain/ietf-keystore:name {ietf-ssh-server:ssh-x509-certs}?
       |        +--rw client-cert-auth {ietf-ssh-server:ssh-x509-certs}?
       |           +--rw trusted-ca-certs?       -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
       |           +--rw trusted-client-certs?   -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
       +--rw call-home
          +--rw netconf-client*
          |  +--rw ssh
          |     +--rw endpoints
          |        +--rw endpoint*
          |           +--rw host-keys
          |           |  +--rw host-key*
          |           |     +--rw (host-key-type)
          |           |        +--:(certificate) {ietf-ssh-server:ssh-x509-certs}?
          |           |           +--rw certificate?   -> /ietf-keystore:keystore/ietf-keystore:private-keys/ietf-keystore:private-key/ietf-keystore:certificate-chains/ietf-keystore:certificate-chain/ietf-keystore:name {ietf-ssh-server:ssh-x509-certs}?
          |           +--rw client-cert-auth {ietf-ssh-server:ssh-x509-certs}?
          |              +--rw trusted-ca-certs?       -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
          |              +--rw trusted-client-certs?   -> /ietf-keystore:keystore/ietf-keystore:trusted-certificates/ietf-keystore:name
          +--rw connection-type
             +--rw persistent!
                +--rw keep-alives
                   +--rw max-wait?       uint16 <30>
                   +--rw max-attempts?   uint8 <3>
```
