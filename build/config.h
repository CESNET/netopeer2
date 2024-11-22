/**
 * @file config.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Various configuration constants for netopeer2-server
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_CONFIG_H_
#define NP2SRV_CONFIG_H_

/** @brief Netopeer2 Server version */
#define NP2SRV_VERSION "2.2.31"

/** @brief Netopeer2 Server PID file path
 * The default path /var/run/netopeer2-server.pid follows
 * the Filesystem Hierarchy Standard
 */
#define NP2SRV_PID_FILE_PATH "/var/run/netopeer2-server.pid"

/** @brief Netopeer2 Server UNIX socket file path
 * The default path /var/run/netopeer2-server.sock follows
 * the Filesystem Hierarchy Standard
 */
#define NP2SRV_UNIX_SOCK_PATH "/var/run/netopeer2-server.sock"

/** @brief Maximum number of threads handling session requests
 */
#ifndef NP2SRV_THREAD_COUNT
#   define NP2SRV_THREAD_COUNT 3
#endif

/** @brief NACM recovery session UID
 */
#define NP2SRV_NACM_RECOVERY_UID 

/** @brief Timeout for nc_ps_poll() call
 */
#define NP2SRV_POLL_IO_TIMEOUT 10

/** @brief Starting allocated length for a message
 */
#define NP2SRV_MSG_LEN_START 128

/** @brief Timeout for sending notifications (ms)
 * Should never be needed to be increased, libnetconf2
 * handles concurrency well.
 */
#define NP2SRV_NOTIF_SEND_TIMEOUT 1000

/** @brief Timeout for PS structure accessing in
 * case there is too much contention (ms).
 */
#define NP2SRV_PS_BACKOFF_SLEEP 200

/** @brief Sleep time when terminating sub-ntf subscriptions
 * to give a chance for another threads to wake up (ms).
 */
#define NP2SRV_SUB_NTF_TERMINATE_YIELD_SLEEP 50

/** @brief Timeout for locking a user session structure (ms).
 */
#define NP2SRV_USER_SESS_LOCK_TIMEOUT 5000

/** @brief URL capability support
 */
#define NP2SRV_URL_CAPAB

/** @brief URL capability file: protocol support
 */
/* #undef NP2SRV_URL_FILE_PROTO */

/** @brief Whether libsystemd is installed, decides general support for systemd
 */
#define NP2SRV_HAVE_SYSTEMD

/** @brief Whether sigaction and signals are supported
 */
#define HAVE_SIGACTION

/** @brief sshd-like pattern for path to the authorized_keys file
 */
#define NP2SRV_SSH_AUTHORIZED_KEYS_FORMAT "%h/.ssh/authorized_keys"

/** @brief directory for server files (only confirmed-commit backups at the moment)
 */
#define SERVER_DIR "/home/netconf/.netopeer2-server"

#endif /* NP2SRV_CONFIG_H_ */
