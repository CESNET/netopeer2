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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <nc_server.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "log.h"

/* /ietf-netconf-server:netconf-server/listen/idle-timeout */
int
np2srv_idle_timeout_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    bool prev_dflt;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* ignore other operations */
        if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
            nc_server_set_idle_timeout(((struct lyd_node_leaf_list *)node)->value.uint16);
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
np2srv_ch_periodic_connection_params(const char *client_name, sr_session_ctx_t *session, const char *xpath)
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    bool prev_dflt;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "period")) {
            if (op == SR_OP_DELETED) {
                /* set default */
                rc = nc_server_ch_client_periodic_set_period(client_name, 60);
            } else {
                rc = nc_server_ch_client_periodic_set_period(client_name, ((struct lyd_node_leaf_list *)node)->value.uint16);
            }
        } else if (!strcmp(node->schema->name, "anchor-time")) {
            if (op == SR_OP_DELETED) {
                /* set default */
                rc = nc_server_ch_client_periodic_set_anchor_time(client_name, 0);
            } else {
                rc = nc_server_ch_client_periodic_set_anchor_time(client_name,
                        nc_datetime2time(((struct lyd_node_leaf_list *)node)->value.string));
            }
        } else if (!strcmp(node->schema->name, "idle-timeout")) {
            if (op == SR_OP_DELETED) {
                /* set default */
                rc = nc_server_ch_client_periodic_set_idle_timeout(client_name, 120);
            } else {
                rc = nc_server_ch_client_periodic_set_idle_timeout(client_name,
                        ((struct lyd_node_leaf_list *)node)->value.uint16);
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
np2srv_ch_client_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list, *client_name;
    bool prev_dflt;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* get name */
        client_name = ((struct lyd_node_leaf_list *)node->child)->value_str;

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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/connection-type */
int
np2srv_ch_connection_type_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list, *client_name;
    char *xpath2;
    bool prev_dflt;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* find names */
        client_name = ((struct lyd_node_leaf_list *)node->parent->parent->child)->value_str;

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

        /* periodic connection type params */
        } else if (op == SR_OP_MODIFIED) {
            assert(!strcmp(node->schema->name, "periodic"));

            if (asprintf(&xpath2, "%s/periodic/*", xpath) == -1) {
                EMEM;
                return SR_ERR_NOMEM;
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
np2srv_ch_reconnect_strategy_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list, *client_name, *str;
    char *xpath2;
    bool prev_dflt;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* find name */
        client_name = ((struct lyd_node_leaf_list *)node->parent->parent->child)->value_str;

        if (!strcmp(node->schema->name, "start-with")) {
            if (op == SR_OP_DELETED) {
                /* set default */
                rc = nc_server_ch_client_set_start_with(client_name, NC_CH_FIRST_LISTED);
            } else {
                str = ((struct lyd_node_leaf_list *)node)->value_str;
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
                /* set default */
                rc = nc_server_ch_client_set_max_attempts(client_name, 3);
            } else {
                rc = nc_server_ch_client_set_max_attempts(client_name, ((struct lyd_node_leaf_list *)node)->value.uint8);
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
