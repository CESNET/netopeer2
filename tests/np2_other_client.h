/**
 * @file np2_other_client.h
 * @author Adam Piecek <piecek@cesnet.cz>
 * @brief An alternative test interface for communicating with the NETCONF server.
 *
 * @copyright
 * Copyright (c) 2019 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _NP2_OTHER_CLIENT_H_
#define _NP2_OTHER_CLIENT_H_

#include "stdint.h"

/**
 * @brief Client session structure.
 */
struct np_other_client {
    int unixsock;           /**< file descriptor of unix socket */
    uint64_t msgid;         /**< message-id of the last message sent */
    char *buf;              /**< private buffer used when reading a message */
    uint64_t bufsize;       /**< size of np_other_client.buf */
};

/**
 * @brief Connect to Netopeer server by unix socket.
 *
 * Function do not cover authentication or any other manipulation with the transport layer,
 * it only establish NETCONF session by sending and processing NETCONF \<hello\> messages.
 *
 * @param[in] address Path to the unix socket.
 * @return Client session structure or NULL.
 */
struct np_other_client *oc_connect_unix(const char *address);

/**
 * @brief Send message to server.
 *
 * @param[in] oc_sess Client session.
 * @param[in] msg Message to send.
 * @return 0 on success.
 */
int oc_send_msg(struct np_other_client *oc_sess, const char *msg);

/**
 * @brief Send message to server.
 *
 * As expected, the first start tag '\n##number\n' is not present in @p msg. But if the response is long,
 * it will consist of several chunks, so there will be another start tag somewhere in the @p msg response.
 * The implementation does not delete these internal start tags because this API is used for testing error
 * messages that are not that long.
 *
 * @param[in] oc_sess Client session.
 * @param[out] msg Received message. Do not deallocate memory.
 * @return 0 on success.
 */
int oc_recv_msg(struct np_other_client *oc_sess, char **msg);

/**
 * @brief Release client session.
 *
 * @param[in] oc_sess Client session.
 */
void oc_session_free(struct np_other_client *oc_sess);

#endif /* _NP2_OTHER_CLIENT_H_ */
