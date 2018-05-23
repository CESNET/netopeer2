/**
 * @file ietf_system.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server ietf-system model subtree subscription
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <nc_server.h>

#include "common.h"
#include "operations.h"

static int
subtree_change_resolve(sr_session_ctx_t *srs, sr_change_oper_t sr_oper, sr_val_t *sr_old_val,
                       sr_val_t *sr_new_val, NC_SSH_KEY_TYPE *prev_keytype)
{
    int rc = -2;
    const char *xpath, *key_end, *oper_str = NULL;
    char *path = NULL, quot;
    char *list1_key = NULL, *list2_key = NULL;
    sr_val_t *keydata_val = NULL;
    NC_SSH_KEY_TYPE keytype;

    xpath = (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath);

    if (strncmp(xpath, "/ietf-system:system/authentication/user[name=", 45)) {
        /* we only care about changes on users */
        return 0;
    }

    switch (sr_oper) {
    case SR_OP_CREATED:
        oper_str = "created";
        break;
    case SR_OP_DELETED:
        oper_str = "deleted";
        break;
    case SR_OP_MODIFIED:
        oper_str = "modified";
        break;
    default:
        EINT;
        return -1;
    }
    VRB("Path \"%s\" %s.", xpath, oper_str);

    xpath += 45;

    quot = xpath[0];
    ++xpath;

    key_end = strchr(xpath, quot);
    if (!key_end) {
        EINT;
        return -1;
    }
    list1_key = strndup(xpath, key_end - xpath);
    xpath = key_end + 1;

    if (strncmp(xpath, "]/authorized-key[name=", 22)) {
        /* other field than authorized-key, don't care */
        rc = 0;
        goto cleanup;
    }
    xpath += 22;

    quot = xpath[0];
    ++xpath;

    key_end = strchr(xpath, quot);
    if (!key_end) {
        EINT;
        rc = -1;
        goto cleanup;
    }
    list2_key = strndup(xpath, key_end - xpath);
    xpath = key_end + 1;

    if (strncmp(xpath, "]/", 2)) {
        EINT;
        rc = -1;
        goto cleanup;
    }
    xpath += 2;

    if (!strcmp(xpath, "name")) {
        /* we actually don't care */
        rc = 0;
    } else if (!strcmp(xpath, "algorithm")) {
        if (sr_oper == SR_OP_DELETED) {
            /* it will all get deleted when removing "key-data" */
            rc = 0;
            goto cleanup;
        }

        if (strcmp(sr_new_val->data.string_val, "ssh-dss") && strcmp(sr_new_val->data.string_val, "ssh-rsa")
                && strncmp(sr_new_val->data.string_val, "ecdsa-sha2-", 11)) {
            ERR("Unsupported SSH key algorithm \"%s\".", sr_new_val->data.string_val);
            rc = -1;
            goto cleanup;
        }
        if (!strcmp(sr_new_val->data.string_val, "ssh-dss")) {
            keytype = NC_SSH_KEY_DSA;
        } else if (!strcmp(sr_new_val->data.string_val, "ssh-rsa")) {
            keytype = NC_SSH_KEY_RSA;
        } else {
            keytype = NC_SSH_KEY_ECDSA;
        }

        if (sr_oper == SR_OP_CREATED) {
            /* just store it */
            *prev_keytype = keytype;
        } else {
            np2srv_sr_session_refresh(srs, NULL);

            /* we must remove the key first, then re-add it */
            asprintf(&path, "/ietf-system:system/authentication/user[name='%s']/authorized-key[name='%s']/key-data",
                     list1_key, list2_key);
            if (np2srv_sr_get_item(srs, path, &keydata_val, NULL)) {
                rc = -1;
                goto cleanup;
            }

            if (nc_server_ssh_del_authkey(NULL, keydata_val->data.binary_val, 0, list1_key)) {
                EINT;
                rc = -1;
                goto cleanup;
            }

            if (nc_server_ssh_add_authkey(keydata_val->data.binary_val, keytype, list1_key)) {
                EINT;
                rc = -1;
                goto cleanup;
            }
        }

        rc = 0;
    } else if (!strcmp(xpath, "key-data")) {
        if (sr_oper != SR_OP_CREATED) {
            /* key-data should be unique */
            if (nc_server_ssh_del_authkey(NULL, sr_old_val->data.binary_val, 0, list1_key)) {
                EINT;
                rc = -1;
                goto cleanup;
            }
        }

        if (sr_oper != SR_OP_DELETED) {
            if (!prev_keytype || nc_server_ssh_add_authkey(sr_new_val->data.binary_val, *prev_keytype, list1_key)) {
                EINT;
                rc = -1;
                goto cleanup;
            }
        }

        rc = 0;
    }

cleanup:
    free(list1_key);
    free(list2_key);
    free(path);
    sr_free_val(keydata_val);
    if (rc == -2) {
        ERR("Unknown value \"%s\" change.", (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath));
        rc = -1;
    }
    return rc;
}

static int
subtree_change_cb(sr_session_ctx_t *session, const char *UNUSED(xpath), sr_notif_event_t event, void *UNUSED(private_ctx))
{
    int rc;
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    NC_SSH_KEY_TYPE prev_keytype = 0;

    if (event != SR_EV_APPLY) {
        EINT;
        return -1;
    }

    if (np2srv_sr_get_changes_iter(session, "/ietf-system:system/authentication/user/authorized-key//*", &sr_iter, NULL)) {
        return -1;
    }
    while (!(rc = np2srv_sr_get_change_next(session, sr_iter, &sr_oper, &sr_old_val, &sr_new_val, NULL))) {
        if ((sr_old_val && ((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))
                || (sr_new_val && ((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))
                || (sr_old_val && (sr_old_val->type == SR_CONTAINER_T)) || (sr_new_val && (sr_new_val->type == SR_CONTAINER_T))) {
            /* no semantic meaning */
            continue;
        }

        rc = subtree_change_resolve(session, sr_oper, sr_old_val, sr_new_val, &prev_keytype);

        sr_free_val(sr_old_val);
        sr_free_val(sr_new_val);

        if (rc) {
            break;
        }
    }
    sr_free_change_iter(sr_iter);
    if (rc == 1) {
        return 0;
    }

    return rc;
}

int
feature_change_ietf_system(sr_session_ctx_t *srs, const char *feature_name, bool enabled)
{
    int rc;
    sr_val_iter_t *sr_iter;
    sr_val_t *sr_val;
    NC_SSH_KEY_TYPE prev_keytype = 0;

    assert(feature_name);
    if (strcmp(feature_name, "local-users")) {
        VRB("Unknown or unsupported feature \"%s\" %s, ignoring.", feature_name, (enabled ? "enabled" : "disabled"));
        return 0;
    }

    if (enabled) {
        np2srv_sr_session_refresh(srs, NULL);

        if (np2srv_sr_get_items_iter(srs, "/ietf-system:system/authentication/user/authorized-key//*",
                &sr_iter, NULL)) {
            return -1;
        }

        while (!(rc = np2srv_sr_get_item_next(srs, sr_iter, &sr_val, NULL))) {
            if (sr_val->type == SR_LIST_T) {
                /* no semantic meaning */
                continue;
            }

            rc = subtree_change_resolve(srs, SR_OP_CREATED, NULL, sr_val, &prev_keytype);
            sr_free_val(sr_val);
            if (rc) {
                ERR("Failed to enable nodes depending on the \"%s\" ietf-system feature.", feature_name);
                break;
            }
        }
        sr_free_val_iter(sr_iter);
        if (rc == -1) {
            return -1;
        }
    } else {
        nc_server_ssh_del_authkey(NULL, NULL, 0, NULL);
    }

    return 0;
}

int
ietf_system_init(const struct lys_module *module)
{
    if (np2srv_sr_subtree_change_subscribe(np2srv.sr_sess.srs, "/ietf-system:system/authentication/user",
                subtree_change_cb, NULL, 0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr, NULL)) {
        return -1;
    }

    /* applies the whole current configuration */
    if (lys_features_state(module, "local-users") == 1) {
        if (feature_change_ietf_system(np2srv.sr_sess.srs, "local-users", 1)) {
            return -1;
        }
    }

    return 0;
}
