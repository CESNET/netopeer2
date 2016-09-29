/**
 * @file ietf_netconf_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server ietf-netconf-server model subscription and configuration
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"

/* setters */

static int
set_session_options_hello_timeout(sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_set_hello_timeout(sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        nc_server_set_hello_timeout(600);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_listen_max_sessions(sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        np2srv.nc_max_sessions = sr_new_val->data.uint16_val;
        rc = EXIT_SUCCESS;
        break;
    case SR_OP_DELETED:
        np2srv.nc_max_sessions = 0;
        rc = EXIT_SUCCESS;
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_listen_idle_timeout(sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_set_idle_timeout(sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        nc_server_set_idle_timeout(3600);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_endpoint_ssh_address(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                         sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_ssh_endpt_set_address(endpt_name, sr_new_val->data.string_val);
        break;
    case SR_OP_DELETED:
        rc = nc_server_ssh_endpt_set_address(endpt_name, "0.0.0.0");
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_endpoint_ssh_port(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                      sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_ssh_endpt_set_port(endpt_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        rc = nc_server_ssh_endpt_set_port(endpt_name, 830);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_endpoint_tls_address(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                         sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_tls_endpt_set_address(endpt_name, sr_new_val->data.string_val);
        break;
    case SR_OP_DELETED:
        rc = nc_server_tls_endpt_set_address(endpt_name, "0.0.0.0");
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_endpoint_tls_port(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                      sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_tls_endpt_set_port(endpt_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        rc = nc_server_tls_endpt_set_port(endpt_name, 6513);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_endpoint_ssh_host_key(const char *endpt_name, sr_change_oper_t UNUSED(sr_oper), sr_val_t *sr_old_val,
                          sr_val_t *sr_new_val)
{
    int rc = EXIT_SUCCESS;
    char *path;

    /* TODO broken order (if creating, not called on move for now) */
    if (sr_new_val) {
        path = malloc(strlen(NP2SRV_KCD_DIR) + strlen(sr_new_val->data.string_val) + 1);
        sprintf(path, NP2SRV_KCD_DIR "%s", sr_new_val->data.string_val);
        rc = nc_server_ssh_endpt_add_hostkey(endpt_name, sr_new_val->data.string_val);
        free(path);
    }
    if (!rc && sr_old_val) {
        path = malloc(strlen(NP2SRV_KCD_DIR) + strlen(sr_old_val->data.string_val) + 1);
        sprintf(path, NP2SRV_KCD_DIR "%s", sr_old_val->data.string_val);
        rc = nc_server_ssh_endpt_del_hostkey(endpt_name, sr_old_val->data.string_val);
        free(path);
    }

    return rc;
}

/* logic */

/* moves the string after the predicate, returns key_val in the dictionary */
static void
parse_list_key(const char **predicate, const char **key_val, const char *key_name)
{
    const char *key_end;
    char quot;

    assert((*predicate)[0] == '[');
    ++(*predicate);

    assert(!strncmp(*predicate, key_name, strlen(key_name)));
    *predicate += strlen(key_name);

    assert((*predicate)[0] == '=');
    ++(*predicate);

    assert(((*predicate)[0] == '\'') || ((*predicate)[0] == '\"'));
    quot = (*predicate)[0];
    ++(*predicate);

    key_end = strchr(*predicate, quot);
    assert(key_end);
    if (key_val) {
        *key_val = lydict_insert(np2srv.ly_ctx, *predicate, key_end - (*predicate));
    }
    *predicate = key_end + 1;

    assert((*predicate)[0] == ']');
    ++(*predicate);
}

static int
module_change_resolve(sr_change_oper_t sr_oper, sr_val_t *sr_old_val, sr_val_t *sr_new_val, const char **endpt_name_del)
{
    int rc = -1;
    const char *xpath, *endpt_name = NULL, *hostkey_name = NULL;

    xpath = (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath);
    assert(!strncmp(xpath, "/ietf-netconf-server:netconf-server/", 36));
    xpath += 36;

    if (!strncmp(xpath, "session-options/", 16)) {
        xpath += 16;
        if (!strcmp(xpath, "hello-timeout")) {
            rc = set_session_options_hello_timeout(sr_oper, sr_old_val, sr_new_val);
        }
    } else if (!strncmp(xpath, "listen/", 7)) {
        xpath += 7;
        if (!strcmp(xpath, "max-sessions")) {
            rc = set_listen_max_sessions(sr_oper, sr_old_val, sr_new_val);
        } else if (!strcmp(xpath, "idle-timeout")) {
            rc = set_listen_idle_timeout(sr_oper, sr_old_val, sr_new_val);
        } else if (!strncmp(xpath, "endpoint", 8)) {
            xpath += 8;
            assert(xpath[0] == '[');

            parse_list_key(&xpath, &endpt_name, "name");

            assert(xpath[0] == '/');
            ++xpath;

            if (*endpt_name_del && (sr_oper == SR_OP_DELETED) && !strcmp(endpt_name, *endpt_name_del)) {
                /* whole endpoint already deleted */
                lydict_remove(np2srv.ly_ctx, endpt_name);
                return EXIT_SUCCESS;
            }

            if (!strcmp(xpath, "name")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_add_endpt(sr_new_val->data.string_val);
                } else if (sr_oper == SR_OP_DELETED) {
                    rc = nc_server_del_endpt(sr_new_val->data.string_val);
                    if (!rc) {
                        if (*endpt_name_del) {
                            lydict_remove(np2srv.ly_ctx, *endpt_name_del);
                        }
                        *endpt_name_del = endpt_name;
                        endpt_name = NULL;
                    }
                } else {
                    EINT;
                    rc = EXIT_FAILURE;
                }
            } else if (!strncmp(xpath, "ssh/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "address")) {
                    rc = set_endpoint_ssh_address(endpt_name, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "port")) {
                    rc = set_endpoint_ssh_port(endpt_name, sr_oper, sr_old_val, sr_new_val);
                } else if (!strncmp(xpath, "host-keys/", 10)) {
                    xpath += 10;
                    if (!strncmp(xpath, "host-key", 8)) {
                        xpath += 8;
                        assert(xpath[0] == '[');

                        parse_list_key(&xpath, &hostkey_name, "name");

                        if (!xpath[0]) {
                            /* TODO list moved */
                        } else if (xpath[0] == '/') {
                            ++xpath;

                            if (!strcmp(xpath, "name")) {
                                /* we just don't care  */
                                rc = EXIT_SUCCESS;
                            } else if (!strcmp(xpath, "public-key")) {
                                rc = set_endpoint_ssh_host_key(endpt_name, sr_oper, sr_old_val, sr_new_val);
                            }
                        }
                    }
                }
            } else if (!strncmp(xpath, "tls/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "address")) {
                    rc = set_endpoint_tls_address(endpt_name, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "port")) {
                    rc = set_endpoint_tls_port(endpt_name, sr_oper, sr_old_val, sr_new_val);
                } else if (!strncmp(xpath, "certificates/", 13)) {
                    xpath += 13;
                    /* TODO */
                } else if (!strncmp(xpath, "client-auth/", 12)) {
                    xpath += 12;
                    /* TODO */
                }
            }
        }
    } else if (!strncmp(xpath, "call-home/", 10)) {
        xpath += 10;
        /* TODO */
    }

    lydict_remove(np2srv.ly_ctx, endpt_name);
    lydict_remove(np2srv.ly_ctx, hostkey_name);
    if (rc == -1) {
        ERR("Unknown value \"%s\" change.", (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath));
        rc = EXIT_FAILURE;
    }
    return rc;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), sr_notif_event_t event,
                 void *UNUSED(private_ctx))
{
    int rc, rc2, sr_rc = SR_ERR_OK;
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    const char *endpt_name_del = NULL;

    if (event != SR_EV_APPLY) {
        ERR("%s: unexpected event.", __func__);
        return SR_ERR_INVAL_ARG;
    }

    rc = sr_get_changes_iter(session, "/ietf-netconf-server:netconf-server//*", &sr_iter);
    if (rc != SR_ERR_OK) {
        ERR("%s: sr_get_changes_iter error: %s", __func__, sr_strerror(rc));
        return rc;
    }
    while ((rc = sr_get_change_next(session, sr_iter, &sr_oper, &sr_old_val, &sr_new_val)) == SR_ERR_OK) {
        if ((sr_old_val
                && (((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)) || (sr_old_val->type == SR_CONTAINER_T)))
                || (sr_new_val
                && (((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)) || (sr_new_val->type == SR_CONTAINER_T)))) {
            /* no semantic meaning */
            continue;
        }

        rc2 = module_change_resolve(sr_oper, sr_old_val, sr_new_val, &endpt_name_del);

        sr_free_val(sr_old_val);
        sr_free_val(sr_new_val);

        if (rc2) {
            sr_rc = SR_ERR_OPERATION_FAILED;
            break;
        }
    }
    lydict_remove(np2srv.ly_ctx, endpt_name_del);
    sr_free_change_iter(sr_iter);
    if ((rc != SR_ERR_OK) && (rc != SR_ERR_NOT_FOUND)) {
        ERR("%s: sr_get_change_next error: %s", __func__, sr_strerror(rc));
        return rc;
    }

    return sr_rc;
}

static void
feature_change_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx)
{
    int rc, rc2;
    const char *path = NULL, *endpt_name_del = NULL;
    sr_val_iter_t *sr_iter;
    sr_val_t *sr_val;

    if (private_ctx) {
        *((int *)private_ctx) = EXIT_SUCCESS;
    }

    if (!feature_name) {
        path = "/ietf-netconf-server:netconf-server//*";
    } else if (!strcmp(feature_name, "listen")) {
        path = "/ietf-netconf-server:netconf-server/listen//*";
    } else if (!strcmp(feature_name, "ssh-listen")) {
        path = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh//*";
    } else if (!strcmp(feature_name, "tls-listen")) {
        path = "/ietf-netconf-server:netconf-server/listen/endpoint/tls//*";
    } else if (!strcmp(feature_name, "call-home")) {
        path = "/ietf-netconf-server:netconf-server/call-home//*";
    } else if (!strcmp(feature_name, "ssh-call-home")) {
        path = "/ietf-netconf-server:netconf-server/call-home/netconf-client/ssh//*";
    } else if (!strcmp(feature_name, "tls-call-home")) {
        path = "/ietf-netconf-server:netconf-server/call-home/netconf-client/tls//*";
    } else {
        WRN("Unknown or unsupported feature \"%s\" %s, ignoring.", feature_name, (enabled ? "enabled" : "disabled"));
        if (private_ctx) {
            *((int *)private_ctx) = EXIT_FAILURE;
        }
    }

    if (path) {
        rc = sr_get_items_iter(np2srv.sr_sess.srs, path, &sr_iter);
        if (rc != SR_ERR_OK) {
            ERR("Failed to get \"%s\" values iterator from sysrepo (%s).", sr_strerror(rc));
            if (private_ctx) {
                *((int *)private_ctx) = EXIT_FAILURE;
            }
            return;
        }

        while ((rc = sr_get_item_next(np2srv.sr_sess.srs, sr_iter, &sr_val)) == SR_ERR_OK) {
            if ((sr_val->type == SR_LIST_T) || (sr_val->type == SR_CONTAINER_T)) {
                /* no semantic meaning */
                continue;
            }

            if (enabled) {
                rc2 = module_change_resolve(SR_OP_CREATED, NULL, sr_val, &endpt_name_del);
            } else {
                rc2 = module_change_resolve(SR_OP_DELETED, sr_val, NULL, &endpt_name_del);
            }
            sr_free_val(sr_val);
            if (rc2) {
                if (feature_name) {
                    ERR("Failed to %s nodes depending on the \"%s\" %s feature.",
                        (enabled ? "enable" : "disable"), feature_name, module_name);
                } else {
                    ERR("Failed to %s all the nodes of %s.",
                        (enabled ? "enable" : "disable"), module_name);
                }
                if (private_ctx) {
                    *((int *)private_ctx) = EXIT_FAILURE;
                }
                break;
            }
        }
        sr_free_val_iter(sr_iter);
        lydict_remove(np2srv.ly_ctx, endpt_name_del);
        if ((rc != SR_ERR_OK) && (rc != SR_ERR_NOT_FOUND)) {
            ERR("Failed to get the next value from sysrepo iterator (%s).", sr_strerror(rc));
            if (private_ctx) {
                *((int *)private_ctx) = EXIT_FAILURE;
            }
        }
    }
}

int
ietf_netconf_server_init(void)
{
    int rc;

    rc = sr_module_change_subscribe(np2srv.sr_sess.srs, "ietf-netconf-server", module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT,
                                    &np2srv.sr_sub);
    if (rc != SR_ERR_OK) {
        ERR("Failed to subscribe to \"ietf-netconf-server\" module changes (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    rc = sr_feature_enable_subscribe(np2srv.sr_sess.srs, feature_change_cb, NULL, SR_SUBSCR_CTX_REUSE, &np2srv.sr_sub);
    if (rc != SR_ERR_OK) {
        ERR("Failed to subscribe to \"ietf-netconf-server\" module feature changes (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    /* applies the whole current configuration */
    feature_change_cb("ietf-netconf-server", NULL, 1, &rc);
    if (rc) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
