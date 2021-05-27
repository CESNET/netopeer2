/**
 * @file netconf_server_ssh.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server SSH callbacks
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

#include "netconf_server_tls.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <nc_server.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "netconf_server.h"

int
np2srv_cert_cb(const char *name, void *UNUSED(user_data), char **UNUSED(cert_path), char **cert_data,
        char **UNUSED(privkey_path), char **privkey_data, NC_SSH_KEY_TYPE *privkey_type)
{
    sr_session_ctx_t *sr_sess;
    char *xpath;
    struct lyd_node *data = NULL;
    int r, rc = -1;

    r = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (r != SR_ERR_OK) {
        return -1;
    }

    /* get private key data from sysrepo */
    if (asprintf(&xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[certificates/certificate/name='%s']", name) == -1) {
        EMEM;
        goto cleanup;
    }
    r = sr_get_subtree(sr_sess, xpath, 0, &data);
    free(xpath);
    if (r != SR_ERR_OK) {
        goto cleanup;
    } else if (!data) {
        ERR("Server certificate \"%s\" not found.", name);
        goto cleanup;
    }

    /* parse private key values */
    if (np2srv_sr_get_privkey(data, privkey_data, privkey_type)) {
        goto cleanup;
    }

    /* get cert data from sysrepo */
    if (asprintf(&xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/"
                "certificate[name='%s']/cert", name) == -1) {
        EMEM;
        goto cleanup;
    }
    lyd_free_siblings(data);
    r = sr_get_subtree(sr_sess, xpath, 0, &data);
    free(xpath);
    if (r != SR_ERR_OK) {
        goto cleanup;
    } else if (!data) {
        ERR("Server certificate \"%s\" not found.", name);
        goto cleanup;
    }

    /* set cert data */
    *cert_data = strdup(lyd_get_value(data));
    if (!*cert_data) {
        EMEM;
        goto cleanup;
    }

    /* success */
    rc = 0;

cleanup:
    lyd_free_siblings(data);
    sr_session_stop(sr_sess);
    return rc;
}

int
np2srv_cert_list_cb(const char *name, void *UNUSED(user_data), char ***UNUSED(cert_paths), int *UNUSED(cert_path_count),
        char ***cert_data, int *cert_data_count)
{
    sr_session_ctx_t *sr_sess;
    char *xpath;
    struct lyd_node *data = NULL;
    struct ly_set *set = NULL;
    int r, rc = -1;
    uint32_t i, j;

    r = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (r != SR_ERR_OK) {
        return -1;
    }

    /* get cert list data from sysrepo */
    if (asprintf(&xpath, "/ietf-truststore:truststore/certificates[name='%s']", name) == -1) {
        EMEM;
        goto cleanup;
    }
    r = sr_get_subtree(sr_sess, xpath, 0, &data);
    free(xpath);
    if (r != SR_ERR_OK) {
        goto cleanup;
    } else if (!data) {
        ERR("Certificate list \"%s\" not found.", name);
        goto cleanup;
    }

    /* find all certificates */
    if (lyd_find_xpath(data, "certificate/cert", &set)) {
        /* libyang error printed */
        goto cleanup;
    } else if (!set->count) {
        WRN("Certificate list \"%s\" does not define any actual certificates.");
        rc = 0;
        goto cleanup;
    }

    *cert_data = malloc(set->count * sizeof **cert_data);
    if (!*cert_data) {
        EMEM;
        goto cleanup;
    }

    /* collect all cert data */
    for (i = 0; i < set->count; ++i) {
        (*cert_data)[i] = strdup(lyd_get_value(set->dnodes[i]));
        if (!(*cert_data)[i]) {
            EMEM;
            for (j = 0; j < i - 1; ++j) {
                free((*cert_data)[i]);
            }
            free(*cert_data);
            goto cleanup;
        }
    }
    *cert_data_count = set->count;

    /* success */
    rc = 0;

cleanup:
    lyd_free_siblings(data);
    ly_set_free(set, NULL);
    sr_session_stop(sr_sess);
    return rc;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/tls */
int
np2srv_endpt_tls_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* get name */
        endpt_name = lyd_get_value(node->parent->child);

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_add_endpt(endpt_name, NC_TI_OPENSSL);
        } else if (op == SR_OP_DELETED) {
            rc = nc_server_del_endpt(endpt_name, NC_TI_OPENSSL);
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/server-identity/keystore-reference */
int
np2srv_endpt_tls_servercert_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name;
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
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);

        /* we do not care about the "asymmetric-key", the certificate is enough */
        if (!strcmp(node->schema->name, "certificate")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                rc = nc_server_tls_endpt_set_server_cert(endpt_name, lyd_get_value(node));
            } else if (op == SR_OP_DELETED) {
                if (nc_server_is_endpt(endpt_name)) {
                    rc = nc_server_tls_endpt_set_server_cert(endpt_name, NULL);
                }
            }
            if (rc) {
                sr_free_change_iter(iter);
                return SR_ERR_INTERNAL;
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/client-authentication */
int
np2srv_endpt_tls_client_auth_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *endpt_name;
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

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL)) == SR_ERR_OK) {
        /* find name */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->child);

        if (!strcmp(node->schema->name, "optional")) {
            /* it is always required */
            ERR("TLS client authentication is always required.");
            sr_free_change_iter(iter);
            return SR_ERR_UNSUPPORTED;
        } else if (!strcmp(node->schema->name, "ca-certs") || !strcmp(node->schema->name, "client-certs")) {
            if (op == SR_OP_CREATED) {
                rc = nc_server_tls_endpt_add_trusted_cert_list(endpt_name, lyd_get_value(node));
            } else if (op == SR_OP_DELETED) {
                if (nc_server_is_endpt(endpt_name)) {
                    rc = nc_server_tls_endpt_del_trusted_cert_list(endpt_name, lyd_get_value(node));
                }
            } else if (op == SR_OP_MODIFIED) {
                nc_server_tls_endpt_del_trusted_cert_list(endpt_name, prev_val);
                rc = nc_server_tls_endpt_add_trusted_cert_list(endpt_name, lyd_get_value(node));
            }
            if (rc) {
                sr_free_change_iter(iter);
                return SR_ERR_INTERNAL;
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

static NC_TLS_CTN_MAPTYPE
np2srv_tls_ctn_str2map_type(const char *map_type)
{
    NC_TLS_CTN_MAPTYPE ret = 0;

    if (strncmp(map_type, "ietf-x509-cert-to-name:", 23)) {
        return ret;
    }
    map_type += 23;

    if (!strcmp(map_type, "specified")) {
        ret = NC_TLS_CTN_SPECIFIED;
    } else if (!strcmp(map_type, "san-rfc822-name")) {
        ret = NC_TLS_CTN_SAN_RFC822_NAME;
    } else if (!strcmp(map_type, "san-dns-name")) {
        ret = NC_TLS_CTN_SAN_DNS_NAME;
    } else if (!strcmp(map_type, "san-ip-address")) {
        ret = NC_TLS_CTN_SAN_IP_ADDRESS;
    } else if (!strcmp(map_type, "san-any")) {
        ret = NC_TLS_CTN_SAN_ANY;
    } else if (!strcmp(map_type, "common-name")) {
        ret = NC_TLS_CTN_COMMON_NAME;
    }

    return ret;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/client-authentication/cert-maps */
int
np2srv_endpt_tls_client_ctn_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node, *child;
    const char *endpt_name, *fingerprint, *name;
    char *xpath2;
    int rc;
    uint32_t id;
    NC_TLS_CTN_MAPTYPE map_type;

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
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);

        /* collect all attributes */
        id = 0;
        fingerprint = NULL;
        map_type = 0;
        name = NULL;
        LY_LIST_FOR(lyd_child(node), child) {
            if (!strcmp(child->schema->name, "id")) {
                id = ((struct lyd_node_term *)child)->value.uint32;
            } else if (!strcmp(child->schema->name, "fingerprint")) {
                fingerprint = lyd_get_value(child);
            } else if (!strcmp(child->schema->name, "map-type")) {
                map_type = np2srv_tls_ctn_str2map_type(lyd_get_value(child));
            } else if (!strcmp(child->schema->name, "name")) {
                name = lyd_get_value(child);
            }
        }
        /* it was validated */
        assert(fingerprint && map_type);

        if (op == SR_OP_CREATED) {
            rc = nc_server_tls_endpt_add_ctn(endpt_name, id, fingerprint, map_type, name);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_is_endpt(endpt_name)) {
                rc = nc_server_tls_endpt_del_ctn(endpt_name, id, fingerprint, map_type, name);
            }
        } else if (op == SR_OP_MODIFIED) {
            nc_server_tls_endpt_del_ctn(endpt_name, id, NULL, 0, NULL);
            rc = nc_server_tls_endpt_add_ctn(endpt_name, id, fingerprint, map_type, name);
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls */
int
np2srv_ch_client_endpt_tls_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name, *client_name;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        /* get names */
        endpt_name = lyd_get_value(node->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->child);

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_ch_client_add_endpt(client_name, endpt_name, NC_TI_OPENSSL);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_ch_is_client(client_name)) {
                rc = nc_server_ch_client_del_endpt(client_name, endpt_name, NC_TI_OPENSSL);
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
 * server-identity/keystore-reference */
int
np2srv_ch_client_endpt_tls_servercert_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id),
        const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id),
        void *UNUSED(private_data))
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
        /* get names */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->parent->child);

        /* we do not care about the "asymmetric-key", the certificate is enough */
        if (!strcmp(node->schema->name, "certificate")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                rc = nc_server_tls_ch_client_endpt_set_server_cert(client_name, endpt_name, lyd_get_value(node));
            } else if (op == SR_OP_DELETED) {
                if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
                    rc = nc_server_tls_ch_client_endpt_set_server_cert(client_name, endpt_name, NULL);
                }
            }
            if (rc) {
                sr_free_change_iter(iter);
                return SR_ERR_INTERNAL;
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
 * client-authentication */
int
np2srv_ch_client_endpt_tls_client_auth_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id),
        const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id),
        void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *endpt_name, *client_name;
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

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL)) == SR_ERR_OK) {
        /* get names */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->child);

        if (!strcmp(node->schema->name, "optional")) {
            /* it is always required */
            ERR("TLS client authentication is always required.");
            sr_free_change_iter(iter);
            return SR_ERR_UNSUPPORTED;
        } else if (!strcmp(node->schema->name, "ca-certs") || !strcmp(node->schema->name, "client-certs")) {
            if (op == SR_OP_CREATED) {
                rc = nc_server_tls_ch_client_endpt_add_trusted_cert_list(client_name, endpt_name, lyd_get_value(node));
            } else if (op == SR_OP_DELETED) {
                if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
                    rc = nc_server_tls_ch_client_endpt_del_trusted_cert_list(client_name, endpt_name, lyd_get_value(node));
                }
            } else if (op == SR_OP_MODIFIED) {
                nc_server_tls_ch_client_endpt_del_trusted_cert_list(client_name, endpt_name, prev_val);
                rc = nc_server_tls_ch_client_endpt_add_trusted_cert_list(client_name, endpt_name, lyd_get_value(node));
            }
            if (rc) {
                sr_free_change_iter(iter);
                return SR_ERR_INTERNAL;
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
 * client-authentication/cert-maps */
int
np2srv_ch_client_endpt_tls_client_ctn_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id),
        const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id),
        void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node, *child;
    const char *endpt_name, *client_name, *fingerprint, *name;
    char *xpath2;
    int rc;
    uint32_t id;
    NC_TLS_CTN_MAPTYPE map_type;

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
        /* get names */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->parent->child);

        /* collect all attributes */
        id = 0;
        fingerprint = NULL;
        map_type = 0;
        name = NULL;
        LY_LIST_FOR(lyd_child(node), child) {
            if (!strcmp(child->schema->name, "id")) {
                id = ((struct lyd_node_term *)child)->value.uint32;
            } else if (!strcmp(child->schema->name, "fingerprint")) {
                fingerprint = lyd_get_value(child);
            } else if (!strcmp(child->schema->name, "map-type")) {
                map_type = np2srv_tls_ctn_str2map_type(lyd_get_value(child));
            } else if (!strcmp(child->schema->name, "name")) {
                name = lyd_get_value(child);
            }
        }
        /* it was validated */
        assert(fingerprint && map_type);

        if (op == SR_OP_CREATED) {
            rc = nc_server_tls_ch_client_endpt_add_ctn(client_name, endpt_name, id, fingerprint, map_type, name);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
                rc = nc_server_tls_ch_client_endpt_del_ctn(client_name, endpt_name, id, fingerprint, map_type, name);
            }
        } else if (op == SR_OP_MODIFIED) {
            nc_server_tls_ch_client_endpt_del_ctn(client_name, endpt_name, id, NULL, 0, NULL);
            rc = nc_server_tls_ch_client_endpt_add_ctn(client_name, endpt_name, id, fingerprint, map_type, name);
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
