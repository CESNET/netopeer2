NETCONF server

## Requirements

* [libyang](https://github.com/CESNET/libyang)
* [libnetconf2](https://github.com/CESNET/libnetconf2)
* [sysrepo](https://github.com/sysrepo/sysrepo)

## Install

### libyang

Follow [libyang instructions](https://github.com/CESNET/libyang/blob/master/README.md#building).

### libnetconf2

Follow [libnetconf2 instructions](https://github.com/CESNET/libnetconf2/blob/master/README.md#installation)

### sysrepo

Follow [sysrepo instructions](https://github.com/sysrepo/sysrepo/blob/master/INSTALL.md).
For the next section, we expect that the `REPOSITORY_LOC` is set to `/etc/sysrepo`. If you
have used another path, please reflect it when installing and setting up the Netopeer2 server.

### Netopeer2

#### Compile and install the server
```
$ mkdir build; cd build
$ cmake ..
$ make
# make install
```

#### Add the server's data models into the sysrepo
```
# cp ../modules/*.yang /etc/sysrepo/yang/
# cp ../modules/*.yin /etc/sysrepo/yang/
```

#### Starting the server

Before starting Netopeer2 server, there must be running `sysrepod`:
```
$ sysrepod
```

Netopeer2 server can be started by executing the following command:
```
$ netopeer2-server
```

The daemon accepts several arguments for specifying log verbosity level
or for debugging. You can display them by executing sysrepod -h:
```
$ netopeer2-server -h
Usage: netopeer2-server [-dhV] [-v level]
 -d                  debug mode (do not daemonize and print
                     verbose messages to stderr instead of syslog)
 -h                  display help
 -V                  show program version
 -v level            verbose output level:
                         0 - errors
                         1 - errors and warnings
                         2 - errors, warnings and verbose messages
                         3 - all messages including debug notes
```

#### Connecting to the server

After installation, server has a default startup configuration which enables SSH connections
on all the interfaces on the designated NETCONF SSH port 830. To connect to the server on localhost
the Netopeer2 CLI can be used:
```
$ netopeer2-cli
> connect
```

