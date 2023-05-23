/**
 * @file receivers.h
 * @author Jeremie Leska <jeremie.leska@6wind.com>
 * @brief ietf-subscribed-notifications describe receivers for configured
 * subcribed notification
 *
 * @copyright
 * Copyright 2023 6WIND S.A.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_RECEIVERS_H_
#define NP2SRV_RECEIVERS_H_

#include <unyte-udp-notif/unyte_sender.h>

enum csn_receiver_state {
    CSN_RECEIVER_STATE_NONE,
    CSN_RECEIVER_STATE_ACTIVE,
    CSN_RECEIVER_STATE_SUSPENDED,
    CSN_RECEIVER_STATE_CONNECTING,
    CSN_RECEIVER_STATE_DISCONNECTED
};

/**
 * @brief configured subscriptions notification transport type.
 */
struct csn_config_udp {
    char *address;
    char *port;
};

/**
 * @brief configured subscriptions notification transport type.
 */
struct csn_transport_udp {
    unyte_sender_options_t options;
    struct unyte_sender_socket *sender;
};

/**
 * @brief configured subscriptions notification transport type.
 */
enum csn_transport_type {
    CSN_TRANSPORT_UDP
};

/**
 * @brief configured subscriptions notification transport.
 */
struct csn_receiver_config {
    char *instance_name;
    enum csn_transport_type type;
    union {
        struct csn_config_udp udp;
    };
};

/**
 * @brief configured subscriptions notification reference.
 * The instance_ref of a configured subscription may point to the instance_name
 * of the csn_receiver
 */
struct csn_receiver {
    char *name;
    char *instance_ref;
    union {
        struct csn_transport_udp udp;
    };
    enum csn_receiver_state state;
    struct timespec reset_time;
};

/**
 * @brief configured subscriptions notification receivers information.
 * Several receivers references par subscription but only one local address
 * per subscription
 */
struct csn_receiver_info {
    struct csn_receiver *receivers;
    uint32_t count;
    char *local_address;
    char *interface;
};

#endif /* NP2SRV_RECEIVERS_H_ */
