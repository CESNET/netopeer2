/**
 * @file netconf_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server callbacks
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* asprintf() */

#include "netconf_server.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"

int
np2srv_sr_get_privkey(const struct lyd_node *asym_key, char **privkey_data, NC_SSH_KEY_TYPE *privkey_type)
{
    struct lyd_node_term *alg = NULL;
    struct lyd_node *node, *privkey = NULL;

    /* find the nodes */
    LY_LIST_FOR(lyd_child(asym_key), node) {
        if (!strcmp(node->schema->name, "algorithm")) {
            alg = (struct lyd_node_term *)node;
        } else if (!strcmp(node->schema->name, "private-key")) {
            privkey = node;
        }
    }
    if (!alg || !privkey) {
        ERR("Failed to find asymmetric key information.");
        return -1;
    }

    /* set algorithm */
    if (!strncmp(alg->value.ident->name, "rsa", 3)) {
        *privkey_type = NC_SSH_KEY_RSA;
    } else if (!strncmp(alg->value.ident->name, "secp", 4)) {
        *privkey_type = NC_SSH_KEY_ECDSA;
    } else {
        ERR("Unknown private key algorithm \"%s\".", lyd_get_value(&alg->node));
        return -1;
    }

    /* set data */
    *privkey_data = strdup(lyd_get_value(privkey));
    if (!*privkey_data) {
        EMEM;
        return -1;
    }

    return 0;
}

/* /ietf-netconf-server:netconf-server/listen/idle-timeout */
int
np2srv_idle_timeout_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* ignore other operations */
        if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
            nc_server_set_idle_timeout(((struct lyd_node_term *)node)->value.uint16);
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

static int
np2srv_tcp_keepalives(const char *client_name, const char *endpt_name, sr_session_ctx_t *session, const char *xpath)
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    int rc, idle_time = -1, max_probes = -1, probe_interval = -1;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "idle-time")) {
            if (op == SR_OP_DELETED) {
                idle_time = 1;
            } else {
                idle_time = ((struct lyd_node_term *)node)->value.uint16;
            }
        } else if (!strcmp(node->schema->name, "max-probes")) {
            if (op == SR_OP_DELETED) {
                max_probes = 10;
            } else {
                max_probes = ((struct lyd_node_term *)node)->value.uint16;
            }
        } else if (!strcmp(node->schema->name, "probe-interval")) {
            if (op == SR_OP_DELETED) {
                probe_interval = 5;
            } else {
                probe_interval = ((struct lyd_node_term *)node)->value.uint16;
            }
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    rc = 0;

    /* set new keepalive parameters */
    if (!client_name) {
        if (nc_server_is_endpt(endpt_name)) {
            rc = nc_server_endpt_set_keepalives(endpt_name, idle_time, max_probes, probe_interval);
        }
    } else {
        if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
            rc = nc_server_ch_client_endpt_set_keepalives(client_name, endpt_name, idle_time, max_probes, probe_interval);
        }
    }
    if (rc) {
        ERR("Keepalives configuration failed (%d).", rc);
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ * /tcp-server-parameters */
int
np2srv_endpt_tcp_params_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name;
    char *xpath2;
    int rc, failed = 0;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* find name */
        endpt_name = lyd_get_value(node->parent->parent->parent->child);

        if (!strcmp(node->schema->name, "local-address")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (nc_server_endpt_set_address(endpt_name, lyd_get_value(node))) {
                    failed = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "local-port")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (nc_server_endpt_set_port(endpt_name, ((struct lyd_node_term *)node)->value.uint16)) {
                    failed = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "keepalives")) {
            if (op == SR_OP_CREATED) {
                if (nc_server_endpt_enable_keepalives(endpt_name, 1)) {
                    failed = 1;
                }
            } else if (op == SR_OP_DELETED) {
                if (nc_server_is_endpt(endpt_name)) {
                    if (nc_server_endpt_enable_keepalives(endpt_name, 0)) {
                        failed = 1;
                    }
                }
            }

            /* set specific parameters */
            if (asprintf(&xpath2, "%s/keepalives/*", xpath) == -1) {
                EMEM;
                return SR_ERR_NO_MEMORY;
            }
            if (np2srv_tcp_keepalives(NULL, endpt_name, session, xpath2)) {
                failed = 1;
            }
            free(xpath2);
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return failed ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int
np2srv_ch_periodic_connection_params(const char *client_name, sr_session_ctx_t *session, const char *xpath)
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    int rc;
    time_t t;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "period")) {
            if (op == SR_OP_DELETED) {
                if (nc_server_ch_is_client(client_name)) {
                    /* set default */
                    rc = nc_server_ch_client_periodic_set_period(client_name, 60);
                }
            } else {
                rc = nc_server_ch_client_periodic_set_period(client_name, ((struct lyd_node_term *)node)->value.uint16);
            }
        } else if (!strcmp(node->schema->name, "anchor-time")) {
            if (op == SR_OP_DELETED) {
                if (nc_server_ch_is_client(client_name)) {
                    /* set default */
                    rc = nc_server_ch_client_periodic_set_anchor_time(client_name, 0);
                }
            } else {
                ly_time_str2time(lyd_get_value(node), &t, NULL);
                rc = nc_server_ch_client_periodic_set_anchor_time(client_name, t);
            }
        } else if (!strcmp(node->schema->name, "idle-timeout")) {
            if (op == SR_OP_DELETED) {
                if (nc_server_ch_is_client(client_name)) {
                    /* set default */
                    rc = nc_server_ch_client_periodic_set_idle_timeout(client_name, 120);
                }
            } else {
                rc = nc_server_ch_client_periodic_set_idle_timeout(client_name,
                        ((struct lyd_node_term *)node)->value.uint16);
            }
        }
        if (rc) {
            sr_free_change_iter(iter);
            return SR_ERR_INTERNAL;
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/call-home/netconf-client */
int
np2srv_ch_client_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *client_name;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* get name */
        client_name = lyd_get_value(lyd_child(node));

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_ch_add_client(client_name);
            if (!rc) {
                rc = nc_connect_ch_client_dispatch(client_name, np2srv_new_session_cb);
            }
        } else if (op == SR_OP_DELETED) {
            rc = nc_server_ch_del_client(client_name);
        }
        if (rc) {
            sr_free_change_iter(iter);
            return SR_ERR_INTERNAL;
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ * /tcp-client-parameters */
int
np2srv_ch_client_endpt_tcp_params_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name, *client_name;
    char *xpath2;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* find names */
        endpt_name = lyd_get_value(node->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);

        if (!strcmp(node->schema->name, "remote-address")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (nc_server_ch_client_endpt_set_address(client_name, endpt_name, lyd_get_value(node))) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            }
        } else if (!strcmp(node->schema->name, "remote-port")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (nc_server_ch_client_endpt_set_port(client_name, endpt_name, ((struct lyd_node_term *)node)->value.uint16)) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            }
        } else if (!strcmp(node->schema->name, "keepalives")) {
            if (op == SR_OP_CREATED) {
                rc = nc_server_ch_client_endpt_enable_keepalives(client_name, endpt_name, 1);
            } else if (op == SR_OP_DELETED) {
                if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
                    rc = nc_server_ch_client_endpt_enable_keepalives(client_name, endpt_name, 0);
                }
            }
            if (rc) {
                sr_free_change_iter(iter);
                return SR_ERR_INTERNAL;
            }

            /* set specific parameters */
            if (asprintf(&xpath2, "%s/keepalives/*", xpath) == -1) {
                EMEM;
                return SR_ERR_NO_MEMORY;
            }
            rc = np2srv_tcp_keepalives(client_name, endpt_name, session, xpath2);
            free(xpath2);
            if (rc != SR_ERR_OK) {
                sr_free_change_iter(iter);
                return rc;
            }
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/connection-type */
int
np2srv_ch_connection_type_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *client_name;
    char *xpath2;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* find names */
        client_name = lyd_get_value(node->parent->parent->child);

        /* connection type */
        if (op == SR_OP_CREATED) {
            if (!strcmp(node->schema->name, "persistent")) {
                if (nc_server_ch_client_set_conn_type(client_name, NC_CH_PERSIST)) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            } else if (!strcmp(node->schema->name, "periodic")) {
                if (nc_server_ch_client_set_conn_type(client_name, NC_CH_PERIOD)) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            }
        }

        /* periodic connection type params */
        if (!strcmp(node->schema->name, "periodic")) {
            if (asprintf(&xpath2, "%s/periodic/*", xpath) == -1) {
                EMEM;
                return SR_ERR_NO_MEMORY;
            }
            rc = np2srv_ch_periodic_connection_params(client_name, session, xpath2);
            free(xpath2);
            if (rc != SR_ERR_OK) {
                return rc;
            }
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/reconnect-strategy */
int
np2srv_ch_reconnect_strategy_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *client_name, *str;
    char *xpath2;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* find name */
        client_name = lyd_get_value(node->parent->parent->child);

        if (!strcmp(node->schema->name, "start-with")) {
            if (op == SR_OP_DELETED) {
                if (nc_server_ch_is_client(client_name)) {
                    /* set default */
                    rc = nc_server_ch_client_set_start_with(client_name, NC_CH_FIRST_LISTED);
                }
            } else {
                str = lyd_get_value(node);
                if (!strcmp(str, "first-listed")) {
                    rc = nc_server_ch_client_set_start_with(client_name, NC_CH_FIRST_LISTED);
                } else if (!strcmp(str, "last-connected")) {
                    rc = nc_server_ch_client_set_start_with(client_name, NC_CH_LAST_CONNECTED);
                } else if (!strcmp(str, "random-selection")) {
                    rc = nc_server_ch_client_set_start_with(client_name, NC_CH_RANDOM);
                }
            }
        } else if (!strcmp(node->schema->name, "max-attempts")) {
            if (op == SR_OP_DELETED) {
                if (nc_server_ch_is_client(client_name)) {
                    /* set default */
                    rc = nc_server_ch_client_set_max_attempts(client_name, 3);
                }
            } else {
                rc = nc_server_ch_client_set_max_attempts(client_name, ((struct lyd_node_term *)node)->value.uint8);
            }
        }

        if (rc) {
            sr_free_change_iter(iter);
            return SR_ERR_INTERNAL;
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}
