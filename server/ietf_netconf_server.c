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

#define _GNU_SOURCE

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
set_listen_endpoint_address(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                            sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_endpt_set_address(endpt_name, sr_new_val->data.string_val);
        break;
    case SR_OP_DELETED:
        rc = nc_server_endpt_set_address(endpt_name, "0.0.0.0");
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_listen_endpoint_port(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                         sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_endpt_set_port(endpt_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_listen_endpoint_ssh_host_key(const char *endpt_name, sr_change_oper_t UNUSED(sr_oper), sr_val_t *sr_old_val,
                                 sr_val_t *sr_new_val)
{
    int rc = EXIT_SUCCESS;
    char *path;

    /* TODO broken order (if creating, not called on move for now) */
    if (sr_new_val) {
        asprintf(&path, NP2SRV_AUTHD_DIR "/%s.pem", sr_new_val->data.string_val);
        rc = nc_server_ssh_endpt_add_hostkey(endpt_name, path);
        free(path);
    }
    if (!rc && sr_old_val) {
        asprintf(&path, NP2SRV_AUTHD_DIR "/%s.pem", sr_old_val->data.string_val);
        rc = nc_server_ssh_endpt_del_hostkey(endpt_name, path);
        free(path);
    }

    return rc;
}

static int
set_tls_cert(sr_session_ctx_t *session, const char *config_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
             sr_val_t *sr_new_val, int listen_or_ch)
{
    int rc = EXIT_FAILURE, ret;
    char *path, *key_begin, *key_end;
    sr_val_t *sr_cert;

    switch (sr_oper) {
    case SR_OP_DELETED:
        if (!listen_or_ch) {
            nc_server_tls_endpt_set_key_path(config_name, NULL);
            nc_server_tls_endpt_set_cert_path(config_name, NULL);
        } else {
            nc_server_tls_ch_client_set_key_path(config_name, NULL);
            nc_server_tls_ch_client_set_cert_path(config_name, NULL);
        }
        rc = 0;
        break;
    case SR_OP_CREATED:
        ret = asprintf(&path, "/ietf-system-keychain:keychain/private-keys/private-key/certificate-chains/"
                              "certificate-chain[name='%s']/certificate[1]", sr_new_val->data.string_val);
        if (ret == -1) {
            EMEM;
            return -1;
        }

        ret = sr_get_item(session, path, &sr_cert);
        if (ret != SR_ERR_OK) {
            ERR("Failed to get \"%s\" from sysrepo (%s).", path, sr_strerror(ret));
            free(path);
            return ret;
        }
        free(path);

        /* get the private key name */
        key_begin = strstr(sr_cert->xpath, "private-key[name='");
        if (!key_begin) {
            EINT;
            sr_free_val(sr_cert);
            return -1;
        }
        key_begin += 18;

        key_end = strchr(key_begin, '\'');
        if (!key_end) {
            EMEM;
            sr_free_val(sr_cert);
            return -1;
        }

        ret = asprintf(&path, NP2SRV_AUTHD_DIR "/%.*s.pem", (int)(key_end - key_begin), key_begin);
        if (ret == -1) {
            EMEM;
            sr_free_val(sr_cert);
            return -1;
        }

        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_set_key_path(config_name, path);
        } else {
            rc = nc_server_tls_ch_client_set_key_path(config_name, path);
        }
        free(path);
        if (rc) {
            sr_free_val(sr_cert);
            break;
        }

        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_set_cert(config_name, sr_cert->data.binary_val);
        } else {
            rc = nc_server_tls_ch_client_set_cert(config_name, sr_cert->data.binary_val);
        }

        sr_free_val(sr_cert);
        break;
    case SR_OP_MODIFIED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
add_tls_trusted_cert(sr_session_ctx_t *session, const char *config_name, sr_change_oper_t sr_oper, sr_val_t *sr_old_val,
                     sr_val_t *sr_new_val, int listen_or_ch)
{
    int rc = EXIT_FAILURE, ret;
    char *str;
    const char *key_begin, *key_end;
    sr_val_t *sr_certs;
    size_t sr_cert_count, i;

    switch (sr_oper) {
    case SR_OP_DELETED:
        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_del_trusted_cert(config_name, sr_old_val->data.string_val);
        } else {
            rc = nc_server_tls_ch_client_del_trusted_cert(config_name, sr_old_val->data.string_val);
        }
        break;
    case SR_OP_CREATED:
        ret = asprintf(&str, "/ietf-system-keychain:keychain/trusted-certificates[name='%s']/trusted-certificate/certificate",
                       sr_new_val->data.string_val);
        if (ret == -1) {
            EMEM;
            return -1;
        }

        ret = sr_get_items(session, str, &sr_certs, &sr_cert_count);
        if (ret != SR_ERR_OK) {
            ERR("Failed to get \"%s\" from sysrepo (%s).", str, sr_strerror(ret));
            free(str);
            return ret;
        }
        free(str);

        for (i = 0; i < sr_cert_count; ++i) {
            key_begin = strstr(sr_certs[i].xpath, "trusted-certificate[name='");
            if (!key_begin) {
                rc = EXIT_FAILURE;
                break;
            }
            key_begin += 26;

            key_end = strchr(key_begin, '\'');
            if (!key_end) {
                rc = EXIT_FAILURE;
                break;
            }

            str = strndup(key_begin, key_end - key_begin);
            if (!str) {
                EMEM;
                rc = EXIT_FAILURE;
                break;
            }

            if (!listen_or_ch) {
                rc = nc_server_tls_endpt_add_trusted_cert(config_name, str, sr_certs[i].data.binary_val);
            } else {
                rc = nc_server_tls_ch_client_add_trusted_cert(config_name, str, sr_certs[i].data.binary_val);
            }
            free(str);
            if (rc) {
                break;
            }
        }

        sr_free_values(sr_certs, sr_cert_count);
        break;
    case SR_OP_MODIFIED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static NC_TLS_CTN_MAPTYPE
convert_str_to_map_type(const char *map_type)
{
    NC_TLS_CTN_MAPTYPE ret = 0;

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

static int
add_tls_ctn(const char *xpath, const char *config_name, sr_change_oper_t sr_oper, sr_val_t *sr_old_val,
            sr_val_t *sr_new_val, int listen_or_ch)
{
    int rc = EXIT_SUCCESS;
    uint32_t cur_id;
    sr_val_t *sr_val;
    char *set_fingerprint = NULL;
    NC_TLS_CTN_MAPTYPE set_map_type = 0;
    char *set_name = NULL;

    static uint32_t id = 0;
    static char *fingerprint = NULL;
    static NC_TLS_CTN_MAPTYPE map_type = 0;
    static const char *name = NULL;

    assert(!strncmp(xpath, "cert-to-name[id='", 17));
    xpath += 17;

    cur_id = atoi(xpath);
    assert(!id || (cur_id == id));

    xpath = strchr(xpath, '\'');
    assert(!strncmp(xpath, "']/", 3));
    xpath += 3;

    sr_val = (sr_new_val ? sr_new_val : sr_old_val);

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_DELETED:
        if (!strcmp(xpath, "id")) {
            assert(!id);
            id = sr_val->data.uint32_val;
        } else if (!strcmp(xpath, "fingerprint")) {
            assert(!fingerprint);
            fingerprint = strdup(sr_val->data.string_val);
        } else if (!strcmp(xpath, "map-type")) {
            assert(!map_type);
            map_type = convert_str_to_map_type(sr_val->data.identityref_val);
            if (!map_type) {
                EINT;
                return EXIT_FAILURE;
            }
        } else if (!strcmp(xpath, "name")) {
            assert(!name && (map_type == NC_TLS_CTN_SPECIFIED));
            name = sr_val->data.string_val;
        } else {
            EINT;
            return EXIT_FAILURE;
        }

        if (map_type && ((map_type != NC_TLS_CTN_SPECIFIED) || name)) {
            /* we have all the information about the entry */
            if (sr_oper == SR_OP_CREATED) {
                if (!listen_or_ch) {
                    rc = nc_server_tls_endpt_add_ctn(config_name, id, fingerprint, map_type, name);
                } else {
                    rc = nc_server_tls_ch_client_add_ctn(config_name, id, fingerprint, map_type, name);
                }
            } else {
                if (!listen_or_ch) {
                    rc = nc_server_tls_endpt_del_ctn(config_name, id, fingerprint, map_type, name);
                } else {
                    rc = nc_server_tls_ch_client_del_ctn(config_name, id, fingerprint, map_type, name);
                }
            }

            id = 0;
            free(fingerprint);
            fingerprint = NULL;
            map_type = 0;
            name = NULL;
        }
        break;
    case SR_OP_MODIFIED:
        /* get the entry */
        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_get_ctn(config_name, &cur_id, &set_fingerprint, &set_map_type, &set_name);
        } else {
            rc = nc_server_tls_ch_client_get_ctn(config_name, &cur_id, &set_fingerprint, &set_map_type, &set_name);
        }
        if (!rc) {
            /* remove the entry */
            if (!listen_or_ch) {
                nc_server_tls_endpt_del_ctn(config_name, cur_id, set_fingerprint, set_map_type, set_name);
            } else {
                nc_server_tls_ch_client_del_ctn(config_name, cur_id, set_fingerprint, set_map_type, set_name);
            }
            if (!strcmp(xpath, "fingerprint")) {
                free(set_fingerprint);
                set_fingerprint = strdup(sr_val->data.string_val);
            } else if (!strcmp(xpath, "map-type")) {
                set_map_type = convert_str_to_map_type(sr_val->data.identityref_val);
                if (!set_map_type) {
                    EINT;
                    rc = EXIT_FAILURE;
                }
            } else if (!strcmp(xpath, "name")) {
                free(set_name);
                set_name = strdup(sr_val->data.string_val);
            } else {
                EINT;
                rc = EXIT_FAILURE;
            }

            if (!rc) {
                /* re-add modified entry */
                if (!listen_or_ch) {
                    rc = nc_server_tls_endpt_add_ctn(config_name, cur_id, set_fingerprint, set_map_type, set_name);
                } else {
                    rc = nc_server_tls_ch_client_add_ctn(config_name, cur_id, set_fingerprint, set_map_type, set_name);
                }
            }
        }
        break;
    case SR_OP_MOVED:
        EINT;
        return EXIT_FAILURE;
    }

    return rc;
}

static int
set_ch_client_endpoint_address(const char *client_name, const char *endpt_name, sr_change_oper_t sr_oper,
                               sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_ch_client_endpt_set_address(client_name, endpt_name, sr_new_val->data.string_val);
        break;
    case SR_OP_DELETED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_ch_client_endpoint_port(const char *client_name, const char *endpt_name, sr_change_oper_t sr_oper,
                            sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    int rc = EXIT_FAILURE;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        rc = nc_server_ch_client_endpt_set_port(client_name, endpt_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
set_ch_client_ssh_host_key(const char *client_name, sr_change_oper_t UNUSED(sr_oper), sr_val_t *sr_old_val,
                           sr_val_t *sr_new_val)
{
    int rc = EXIT_SUCCESS;
    char *path;

    /* TODO broken order (if creating, not called on move for now) */
    if (sr_new_val) {
        path = malloc(strlen(NP2SRV_AUTHD_DIR) + 1 + strlen(sr_new_val->data.string_val) + 4 + 1);
        sprintf(path, NP2SRV_AUTHD_DIR "/%s.pem", sr_new_val->data.string_val);
        rc = nc_server_ssh_ch_client_add_hostkey(client_name, path);
        free(path);
    }
    if (!rc && sr_old_val) {
        path = malloc(strlen(NP2SRV_AUTHD_DIR) + 1 + strlen(sr_old_val->data.string_val) + 4 + 1);
        sprintf(path, NP2SRV_AUTHD_DIR "/%s.pem", sr_old_val->data.string_val);
        rc = nc_server_ssh_ch_client_del_hostkey(client_name, path);
        free(path);
    }

    return rc;
}

static int
set_ch_persist_idle_timeout(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                            sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_persist_set_idle_timeout(client_name, sr_new_val->data.uint32_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_persist_set_idle_timeout(client_name, 86400);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_persist_ka_max_wait(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                           sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_persist_set_keep_alive_max_wait(client_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_persist_set_keep_alive_max_wait(client_name, 30);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_persist_ka_max_attempts(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                               sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_persist_set_keep_alive_max_attempts(client_name, sr_new_val->data.uint8_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_persist_set_keep_alive_max_attempts(client_name, 3);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_period_idle_timeout(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                           sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_period_set_idle_timeout(client_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_period_set_idle_timeout(client_name, 300);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_period_reconnect_timeout(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                                sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_period_set_reconnect_timeout(client_name, sr_new_val->data.uint16_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_period_set_reconnect_timeout(client_name, 60);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_rs_start_with(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                            sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        if (!strcmp(sr_new_val->data.enum_val, "first-listed")) {
            nc_server_ch_client_set_start_with(client_name, NC_CH_FIRST_LISTED);
        } else if (!strcmp(sr_new_val->data.enum_val, "last-connected")) {
            nc_server_ch_client_set_start_with(client_name, NC_CH_LAST_CONNECTED);
        } else {
            EINT;
        }
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_set_start_with(client_name, NC_CH_FIRST_LISTED);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
}

static int
set_ch_rs_max_attempts(const char *client_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                       sr_val_t *sr_new_val)
{
    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        nc_server_ch_client_set_max_attempts(client_name, sr_new_val->data.uint8_val);
        break;
    case SR_OP_DELETED:
        nc_server_ch_client_set_max_attempts(client_name, 3);
        break;
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return EXIT_SUCCESS;
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
module_change_resolve(sr_session_ctx_t *session, sr_change_oper_t sr_oper, sr_val_t *sr_old_val, sr_val_t *sr_new_val,
                      const char **list1_key_del, const char **list2_key_del)
{
    int rc = -2;
    const char *xpath, *list1_key = NULL, *list2_key = NULL, *oper_str;

    xpath = (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath);
    assert(!strncmp(xpath, "/ietf-netconf-server:netconf-server/", 36));

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
    case SR_OP_MOVED:
        oper_str = "moved";
        break;
    }

    VRB("Path \"%s\" %s.", xpath, oper_str);

    xpath += 36;

    if (!strcmp(xpath, "session-options")) {
        rc = 0;
    } else if (!strncmp(xpath, "session-options/", 16)) {
        xpath += 16;
        if (!strcmp(xpath, "hello-timeout")) {
            rc = set_session_options_hello_timeout(sr_oper, sr_old_val, sr_new_val);
        }
    } else if (!strcmp(xpath, "listen")) {
        rc = 0;
    } else if (!strncmp(xpath, "listen/", 7)) {
        xpath += 7;
        if (!strcmp(xpath, "max-sessions")) {
            rc = set_listen_max_sessions(sr_oper, sr_old_val, sr_new_val);
        } else if (!strcmp(xpath, "idle-timeout")) {
            rc = set_listen_idle_timeout(sr_oper, sr_old_val, sr_new_val);
        } else if (!strncmp(xpath, "endpoint", 8)) {
            xpath += 8;
            assert(xpath[0] == '[');

            parse_list_key(&xpath, &list1_key, "name");

            assert(xpath[0] == '/');
            ++xpath;

            if (list1_key_del && *list1_key_del && (sr_oper == SR_OP_DELETED) && !strcmp(list1_key, *list1_key_del)) {
                /* whole endpoint already deleted */
                lydict_remove(np2srv.ly_ctx, list1_key);
                return EXIT_SUCCESS;
            }

            if (!strcmp(xpath, "name")) {
                if (sr_oper == SR_OP_DELETED) {
                    assert(list1_key_del);
                    rc = nc_server_del_endpt(sr_old_val->data.string_val, 0);
                    if (!rc) {
                        if (*list1_key_del) {
                            lydict_remove(np2srv.ly_ctx, *list1_key_del);
                        }
                        *list1_key_del = list1_key;
                        list1_key = NULL;
                    }
                } else {
                    /* we don't care it was created, ssh or tls container will be created too */
                    rc = 0;
                }
            } else if (!strcmp(xpath, "ssh")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_add_endpt(list1_key, NC_TI_LIBSSH);
                } else {
                    rc = 0;
                }
            } else if (!strncmp(xpath, "ssh/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "address")) {
                    rc = set_listen_endpoint_address(list1_key, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "port")) {
                    rc = set_listen_endpoint_port(list1_key, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "host-keys")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "host-keys/", 10)) {
                    xpath += 10;
                    if (!strncmp(xpath, "host-key", 8)) {
                        xpath += 8;
                        assert(xpath[0] == '[');

                        parse_list_key(&xpath, &list2_key, "name");

                        if (!xpath[0]) {
                            /* TODO list moved */
                        } else if (xpath[0] == '/') {
                            ++xpath;

                            if (!strcmp(xpath, "name")) {
                                /* we just don't care  */
                                rc = EXIT_SUCCESS;
                            } else if (!strcmp(xpath, "public-key")) {
                                rc = set_listen_endpoint_ssh_host_key(list1_key, sr_oper, sr_old_val, sr_new_val);
                            }
                        }
                    }
                }
            } else if (!strcmp(xpath, "tls")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_add_endpt(list1_key, NC_TI_OPENSSL);
                } else {
                    rc = 0;
                }
            } else if (!strncmp(xpath, "tls/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "address")) {
                    rc = set_listen_endpoint_address(list1_key, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "port")) {
                    rc = set_listen_endpoint_port(list1_key, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "certificates")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "certificates/", 13)) {
                    xpath += 13;
                    if (!strncmp(xpath, "certificate", 11)) {
                        xpath += 11;
                        assert(!strncmp(xpath, "[name='", 7));
                        xpath += 7;
                        xpath = strchr(xpath, '\'');
                        assert(!strncmp(xpath, "']/", 3));
                        xpath += 3;

                        if (!strcmp(xpath, "name")) {
                            rc = set_tls_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                        }
                    }
                } else if (!strcmp(xpath, "client-auth")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "client-auth/", 12)) {
                    xpath += 12;
                    if (!strcmp(xpath, "trusted-ca-certs")) {
                        rc = add_tls_trusted_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    } else if (!strcmp(xpath, "trusted-client-certs")) {
                        rc = add_tls_trusted_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    } else if (!strcmp(xpath, "cert-maps")) {
                        /* ignore */
                        rc = 0;
                    } else if (!strncmp(xpath, "cert-maps/", 10)) {
                        xpath += 10;
                        rc = add_tls_ctn(xpath, list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    }
                }
            }
        }
    } else if (!strcmp(xpath, "call-home")) {
        /* ignore */
        rc = 0;
    } else if (!strncmp(xpath, "call-home/", 10)) {
        xpath += 10;
        if (!strncmp(xpath, "netconf-client", 14)) {
            xpath += 14;
            assert(xpath[0] == '[');

            parse_list_key(&xpath, &list1_key, "name");

            assert(xpath[0] == '/');
            ++xpath;

            if (list1_key_del && *list1_key_del && (sr_oper == SR_OP_DELETED) && !strcmp(list1_key, *list1_key_del)) {
                /* whole client already deleted */
                lydict_remove(np2srv.ly_ctx, list1_key);
                return EXIT_SUCCESS;
            }

            if (!strcmp(xpath, "name")) {
                if (sr_oper == SR_OP_DELETED) {
                    assert(list1_key_del);
                    rc = nc_server_ch_del_client(sr_old_val->data.string_val, 0);
                    if (!rc) {
                        if (*list1_key_del) {
                            lydict_remove(np2srv.ly_ctx, *list1_key_del);
                        }
                        *list1_key_del = list1_key;
                        list1_key = NULL;
                    }
                } else {
                    /* we don't care it was created, ssh or tls container will be created too */
                    rc = 0;
                }
            } else if (!strcmp(xpath, "ssh")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_ch_add_client(list1_key, NC_TI_LIBSSH);
                    if (!rc) {
                        rc = nc_connect_ch_client_dispatch(list1_key, np2srv_new_ch_session_clb);
                    }
                } else {
                    rc = 0;
                }
            } else if (!strncmp(xpath, "ssh/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "endpoints")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "endpoints/", 10)) {
                    xpath += 10;
                    if (!strncmp(xpath, "endpoint", 8)) {
                        xpath += 8;
                        assert(xpath[0] == '[');

                        parse_list_key(&xpath, &list2_key, "name");

                        assert(xpath[0] == '/');
                        ++xpath;

                        if (list2_key_del && *list2_key_del && (sr_oper == SR_OP_DELETED) && !strcmp(list2_key, *list2_key_del)) {
                            /* whole endpoint already deleted */
                            lydict_remove(np2srv.ly_ctx, list2_key);
                            return EXIT_SUCCESS;
                        }

                        if (!strcmp(xpath, "name")) {
                            if (sr_oper == SR_OP_DELETED) {
                                assert(list2_key_del);
                                rc = nc_server_ch_client_del_endpt(list1_key, sr_old_val->data.string_val);
                                if (!rc) {
                                    if (*list2_key_del) {
                                        lydict_remove(np2srv.ly_ctx, *list2_key_del);
                                    }
                                    *list2_key_del = list2_key;
                                    list2_key = NULL;
                                }
                            } else {
                                assert(sr_oper == SR_OP_CREATED);
                                rc = nc_server_ch_client_add_endpt(list1_key, sr_new_val->data.string_val);
                            }
                        } else if (!strcmp(xpath, "address")) {
                            rc = set_ch_client_endpoint_address(list1_key, list2_key, sr_oper, sr_old_val, sr_new_val);
                        } else if (!strcmp(xpath, "port")) {
                            rc = set_ch_client_endpoint_port(list1_key, list2_key, sr_oper, sr_old_val, sr_new_val);
                        }
                    }
                } else if (!strcmp(xpath, "host-keys")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "host-keys/", 10)) {
                    xpath += 10;
                    if (!strncmp(xpath, "host-key", 8)) {
                        xpath += 8;
                        assert(xpath[0] == '[');

                        parse_list_key(&xpath, &list2_key, "name");

                        if (!xpath[0]) {
                            /* TODO list moved */
                        } else if (xpath[0] == '/') {
                            ++xpath;

                            if (!strcmp(xpath, "name")) {
                                /* we just don't care  */
                                rc = EXIT_SUCCESS;
                            } else if (!strcmp(xpath, "public-key")) {
                                rc = set_ch_client_ssh_host_key(list1_key, sr_oper, sr_old_val, sr_new_val);
                            }
                        }
                    }
                }
            } else if (!strcmp(xpath, "tls")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_ch_add_client(list1_key, NC_TI_OPENSSL);
                    if (!rc) {
                        rc = nc_connect_ch_client_dispatch(list1_key, np2srv_new_ch_session_clb);
                    }
                } else {
                    rc = 0;
                }
            } else if (!strncmp(xpath, "tls/", 4)) {
                xpath += 4;
                if (!strcmp(xpath, "endpoints")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "endpoints/", 10)) {
                    xpath += 10;
                    if (!strncmp(xpath, "endpoint", 8)) {
                        xpath += 8;
                        assert(xpath[0] == '[');

                        parse_list_key(&xpath, &list2_key, "name");

                        assert(xpath[0] == '/');
                        ++xpath;

                        if (list2_key_del && *list2_key_del && (sr_oper == SR_OP_DELETED) && !strcmp(list2_key, *list2_key_del)) {
                            /* whole endpoint already deleted */
                            lydict_remove(np2srv.ly_ctx, list2_key);
                            return EXIT_SUCCESS;
                        }

                        if (!strcmp(xpath, "name")) {
                            if (sr_oper == SR_OP_DELETED) {
                                assert(list2_key_del);
                                rc = nc_server_ch_client_del_endpt(list1_key, sr_old_val->data.string_val);
                                if (!rc) {
                                    if (*list2_key_del) {
                                        lydict_remove(np2srv.ly_ctx, *list2_key_del);
                                    }
                                    *list2_key_del = list2_key;
                                    list2_key = NULL;
                                }
                            } else {
                                assert(sr_oper == SR_OP_CREATED);
                                rc = nc_server_ch_client_add_endpt(list1_key, sr_new_val->data.string_val);
                            }
                        } else if (!strcmp(xpath, "address")) {
                            rc = set_ch_client_endpoint_address(list1_key, list2_key, sr_oper, sr_old_val, sr_new_val);
                        } else if (!strcmp(xpath, "port")) {
                            rc = set_ch_client_endpoint_port(list1_key, list2_key, sr_oper, sr_old_val, sr_new_val);
                        }
                    }
                } else if (!strcmp(xpath, "certificates")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "certificates/", 13)) {
                    xpath += 13;
                    if (!strncmp(xpath, "certificate", 11)) {
                        xpath += 11;
                        assert(!strncmp(xpath, "[name='", 7));
                        xpath += 7;
                        xpath = strchr(xpath, '\'');
                        assert(!strncmp(xpath, "']/", 3));
                        xpath += 3;

                        if (!strcmp(xpath, "name")) {
                            rc = set_tls_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                        }
                    }
                } else if (!strcmp(xpath, "client-auth")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "client-auth/", 12)) {
                    xpath += 12;
                    if (!strcmp(xpath, "trusted-ca-certs")) {
                        rc = add_tls_trusted_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    } else if (!strcmp(xpath, "trusted-client-certs")) {
                        rc = add_tls_trusted_cert(session, list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    } else if (!strcmp(xpath, "cert-maps")) {
                        /* ignore */
                        rc = 0;
                    } else if (!strncmp(xpath, "cert-maps/", 10)) {
                        xpath += 10;
                        rc = add_tls_ctn(xpath, list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    }
                }
            } else if (!strcmp(xpath, "connection-type")) {
                /* ignore */
                rc = 0;
            } else if (!strncmp(xpath, "connection-type/", 16)) {
                xpath += 16;
                if (!strcmp(xpath, "persistent")) {
                    if (sr_oper == SR_OP_CREATED) {
                        rc = nc_server_ch_client_set_conn_type(list1_key, NC_CH_PERSIST);
                    } else {
                        rc = 0;
                    }
                } else if (!strncmp(xpath, "persistent/", 11)) {
                    xpath += 11;
                    if (!strcmp(xpath, "idle-timeout")) {
                        rc = set_ch_persist_idle_timeout(list1_key, sr_oper, sr_old_val, sr_new_val);
                    } else if (!strcmp(xpath, "keep-alives")) {
                        /* ignore */
                        rc = 0;
                    } else if (!strncmp(xpath, "keep-alives/", 12)) {
                        xpath += 12;
                        if (!strcmp(xpath, "max-wait")) {
                            rc = set_ch_persist_ka_max_wait(list1_key, sr_oper, sr_old_val, sr_new_val);
                        } else if (!strcmp(xpath, "max-attempts")) {
                            rc = set_ch_persist_ka_max_attempts(list1_key, sr_oper, sr_old_val, sr_new_val);
                        }
                    }
                } else if (!strcmp(xpath, "periodic")) {
                    if (sr_oper == SR_OP_CREATED) {
                        rc = nc_server_ch_client_set_conn_type(list1_key, NC_CH_PERIOD);
                    } else {
                        rc = 0;
                    }
                } else if (!strncmp(xpath, "periodic/", 9)) {
                    xpath += 9;
                    if (!strcmp(xpath, "idle-timeout")) {
                        rc = set_ch_period_idle_timeout(list1_key, sr_oper, sr_old_val, sr_new_val);
                    } else if (!strcmp(xpath, "reconnect-timeout")) {
                        rc = set_ch_period_reconnect_timeout(list1_key, sr_oper, sr_old_val, sr_new_val);
                    }
                }
            } else if (!strcmp(xpath, "reconnect-strategy")) {
                /* ignore */
                rc = 0;
            } else if (!strncmp(xpath, "reconnect-strategy/", 19)) {
                xpath += 19;
                if (!strcmp(xpath, "start-with")) {
                    rc = set_ch_rs_start_with(list1_key, sr_oper, sr_old_val, sr_new_val);
                } else if (!strcmp(xpath, "max-attempts")) {
                    rc = set_ch_rs_max_attempts(list1_key, sr_oper, sr_old_val, sr_new_val);
                }
            }
        }
    }

    lydict_remove(np2srv.ly_ctx, list1_key);
    lydict_remove(np2srv.ly_ctx, list2_key);
    if (rc == -2) {
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
    const char *list1_key_del = NULL, *list2_key_del = NULL;

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
                && ((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))
                || (sr_new_val
                && ((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))) {
            /* no semantic meaning */
            continue;
        }

        rc2 = module_change_resolve(session, sr_oper, sr_old_val, sr_new_val, &list1_key_del, &list2_key_del);

        sr_free_val(sr_old_val);
        sr_free_val(sr_new_val);

        if (rc2) {
            sr_rc = SR_ERR_OPERATION_FAILED;
            break;
        }
    }
    lydict_remove(np2srv.ly_ctx, list1_key_del);
    lydict_remove(np2srv.ly_ctx, list2_key_del);
    sr_free_change_iter(sr_iter);
    if ((rc != SR_ERR_OK) && (rc != SR_ERR_NOT_FOUND)) {
        ERR("%s: sr_get_change_next error: %s", __func__, sr_strerror(rc));
        return rc;
    }

    return sr_rc;
}

int
feature_change_ietf_netconf_server(sr_session_ctx_t *session, const char *feature_name, bool enabled)
{
    int rc, rc2 = 0;
    const char *path = NULL;
    sr_val_iter_t *sr_iter;
    sr_val_t *sr_val;

    assert(feature_name);

    if (enabled) {
        if (!strcmp(feature_name, "ssh-listen")) {
            path = "/ietf-netconf-server:netconf-server/listen/endpoint[ssh]//*";
        } else if (!strcmp(feature_name, "tls-listen")) {
            path = "/ietf-netconf-server:netconf-server/listen/endpoint[tls]/*";
        } else if (!strcmp(feature_name, "ssh-call-home")) {
            path = "/ietf-netconf-server:netconf-server/call-home/netconf-client[ssh]//*";
        } else if (!strcmp(feature_name, "tls-call-home")) {
            path = "/ietf-netconf-server:netconf-server/call-home/netconf-client[tls]//*";
        } else {
            VRB("Unknown or unsupported feature \"%s\" enabled, ignoring.", feature_name);
            return EXIT_SUCCESS;
        }

        rc = sr_get_items_iter(np2srv.sr_sess.srs, path, &sr_iter);
        if (rc != SR_ERR_OK) {
            ERR("Failed to get \"%s\" values iterator from sysrepo (%s).", sr_strerror(rc));
            return EXIT_FAILURE;
        }

        while ((rc = sr_get_item_next(np2srv.sr_sess.srs, sr_iter, &sr_val)) == SR_ERR_OK) {
            if (sr_val->type == SR_LIST_T) {
                /* no semantic meaning */
                continue;
            }

            rc2 = module_change_resolve(session, SR_OP_CREATED, NULL, sr_val, NULL, NULL);
            sr_free_val(sr_val);
            if (rc2) {
                ERR("Failed to enable nodes depending on the \"%s\" ietf-netconf-server feature.", feature_name);
                break;
            }
        }
        sr_free_val_iter(sr_iter);
        if (rc2) {
            return EXIT_FAILURE;
        } else if ((rc != SR_ERR_OK) && (rc != SR_ERR_NOT_FOUND)) {
            ERR("Failed to get the next value from sysrepo iterator (%s).", sr_strerror(rc));
            return EXIT_FAILURE;
        }
    } else {
        if (!strcmp(feature_name, "ssh-listen")) {
            nc_server_del_endpt(NULL, NC_TI_LIBSSH);
        } else if (!strcmp(feature_name, "tls-listen")) {
            nc_server_del_endpt(NULL, NC_TI_OPENSSL);
        } else if (!strcmp(feature_name, "ssh-call-home")) {
            nc_server_ch_del_client(NULL, NC_TI_LIBSSH);
        } else if (!strcmp(feature_name, "tls-call-home")) {
            nc_server_ch_del_client(NULL, NC_TI_OPENSSL);
        } else {
            VRB("Unknown or unsupported feature \"%s\" disabled, ignoring.", feature_name);
            return EXIT_SUCCESS;
        }
    }

    return EXIT_SUCCESS;
}

int
ietf_netconf_server_init(const struct lys_module *module)
{
    int rc;

    rc = sr_module_change_subscribe(np2srv.sr_sess.srs, "ietf-netconf-server", module_change_cb, NULL, 0,
                                    SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr);
    if (rc != SR_ERR_OK) {
        ERR("Failed to subscribe to \"ietf-netconf-server\" module changes (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    /* applies the whole current configuration */
    if (lys_features_state(module, "ssh-listen") == 1) {
        if (feature_change_ietf_netconf_server(np2srv.sr_sess.srs, "ssh-listen", 1)) {
            return EXIT_FAILURE;
        }
    }
    if (lys_features_state(module, "tls-listen") == 1) {
        if (feature_change_ietf_netconf_server(np2srv.sr_sess.srs, "tls-listen", 1)) {
            return EXIT_FAILURE;
        }
    }
    if (lys_features_state(module, "ssh-call-home") == 1) {
        if (feature_change_ietf_netconf_server(np2srv.sr_sess.srs, "ssh-call-home", 1)) {
            return EXIT_FAILURE;
        }
    }
    if (lys_features_state(module, "tls-call-home") == 1) {
        if (feature_change_ietf_netconf_server(np2srv.sr_sess.srs, "tls-call-home", 1)) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
