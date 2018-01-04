/**
 * @file ietf_netconf_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server ietf-netconf-server model subscription and configuration
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
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
#include <ctype.h>
#include <pthread.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "ietf_keystore.h"
#include "operations.h"

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

    return 0;
}

static int
set_listen_max_sessions(sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    int rc = -1;

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_MODIFIED:
        np2srv.nc_max_sessions = sr_new_val->data.uint16_val;
        rc = 0;
        break;
    case SR_OP_DELETED:
        np2srv.nc_max_sessions = 0;
        rc = 0;
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

    return 0;
}

static int
set_listen_endpoint_address(const char *endpt_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val),
                            sr_val_t *sr_new_val)
{
    int rc = -1;

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
    int rc = -1;

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

struct thread_arg {
    sr_session_ctx_t *srs;
    int listen_or_ch;
    const char *endpt_client_name;
    const char *key_name;
};

static void *
get_ssh_host_key_public_key(void *arg)
{
    struct thread_arg *targ = (struct thread_arg *)arg;
    char *path, *value;
    sr_val_t *sr_val = NULL;

    if (targ->listen_or_ch) {
        asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/host-keys/host-key[name='%s']/public-key", targ->endpt_client_name, targ->key_name);
        np2srv_sr_get_item(targ->srs, path, &sr_val, NULL);
        free(path);
    } else {
        asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/ssh/host-keys/host-key[name='%s']/public-key", targ->endpt_client_name, targ->key_name);
        np2srv_sr_get_item(targ->srs, path, &sr_val, NULL);
        free(path);
    }

    value = (sr_val ? strdup(sr_val->data.string_val) : NULL);
    sr_free_val(sr_val);
    return value;
}

static int
set_listen_endpoint_ssh_host_key(sr_session_ctx_t *srs, const char *endpt_name, sr_change_oper_t sr_oper,
                                 sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    int rc = 0;
    char *key1, *key2, quot;
    const char *ptr;
    pthread_t tid;
    struct thread_arg targ;

    switch (sr_oper) {
    case SR_OP_DELETED:
        rc = nc_server_ssh_endpt_del_hostkey(endpt_name, sr_old_val->data.string_val, -1);
        break;
    case SR_OP_MODIFIED:
        rc = nc_server_ssh_endpt_mod_hostkey(endpt_name, sr_old_val->data.string_val, sr_new_val->data.string_val);
        break;
    case SR_OP_CREATED:
        rc = nc_server_ssh_endpt_add_hostkey(endpt_name, sr_new_val->data.string_val, -1);
        break;
    case SR_OP_MOVED:
        /* old and new_val are different in this case (nodes one level up) */

        targ.srs = srs;
        targ.listen_or_ch = 1;
        targ.endpt_client_name = endpt_name;

        ptr = strrchr(sr_new_val->xpath, '[');
        assert(!strncmp(ptr, "[name=", 6));
        ptr += 6;
        quot = ptr[0];
        ++ptr;
        targ.key_name = strndup(ptr, strchr(ptr, quot) - ptr);

        pthread_create(&tid, NULL, get_ssh_host_key_public_key, &targ);
        pthread_join(tid, (void **)&key1);
        free((char *)targ.key_name);
        if (!key1) {
            ERR("Failed to get a public key from sysrepo.");
            return -1;
        }

        ptr = strrchr(sr_old_val->xpath, '[');
        assert(!strncmp(ptr, "[name=", 6));
        ptr += 6;
        quot = ptr[0];
        ++ptr;
        targ.key_name = strndup(ptr, strchr(ptr, quot) - ptr);

        pthread_create(&tid, NULL, get_ssh_host_key_public_key, &targ);
        pthread_join(tid, (void **)&key2);
        free((char *)targ.key_name);
        if (!key2) {
            ERR("Failed to get a public key from sysrepo.");
            return -1;
        }

        rc = nc_server_ssh_endpt_mov_hostkey(endpt_name, key1, key2);
        break;
    }

    return rc;
}

#ifdef NC_ENABLED_TLS

static int
set_tls_cert(const char *config_name, sr_change_oper_t sr_oper, sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val,
             int listen_or_ch)
{
    int rc = -1;

    switch (sr_oper) {
    case SR_OP_DELETED:
        if (!listen_or_ch) {
            nc_server_tls_endpt_set_server_cert(config_name, NULL);
        } else {
            nc_server_tls_ch_client_set_server_cert(config_name, NULL);
        }
        rc = 0;
        break;
    case SR_OP_CREATED:
        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_set_server_cert(config_name, sr_new_val->data.string_val);
        } else {
            rc = nc_server_tls_ch_client_set_server_cert(config_name, sr_new_val->data.string_val);
        }
        break;
    case SR_OP_MODIFIED:
    case SR_OP_MOVED:
        EINT;
        break;
    }

    return rc;
}

static int
add_tls_trusted_cert(const char *config_name, sr_change_oper_t sr_oper, sr_val_t *sr_old_val, sr_val_t *sr_new_val,
                     int listen_or_ch)
{
    int rc = -1;

    switch (sr_oper) {
    case SR_OP_DELETED:
        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_del_trusted_cert_list(config_name, sr_old_val->data.string_val);
        } else {
            rc = nc_server_tls_ch_client_del_trusted_cert_list(config_name, sr_old_val->data.string_val);
        }
        break;
    case SR_OP_CREATED:
        if (!listen_or_ch) {
            rc = nc_server_tls_endpt_add_trusted_cert_list(config_name, sr_new_val->data.string_val);
        } else {
            rc = nc_server_tls_ch_client_add_trusted_cert_list(config_name, sr_new_val->data.string_val);
        }
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

static int
add_tls_ctn(const char *xpath, const char *config_name, sr_change_oper_t sr_oper, sr_val_t *sr_old_val,
            sr_val_t *sr_new_val, int listen_or_ch)
{
    int rc = 0;
    sr_val_t *sr_val;
    char quot;
    uint32_t id;
    const char *fingerprint = NULL, *name = NULL;
    NC_TLS_CTN_MAPTYPE map_type = 0;

    assert(!strncmp(xpath, "cert-to-name[id=", 16));
    xpath += 16;
    quot = xpath[0];
    ++xpath;

    assert(isdigit(xpath[0]));
    id = atoi(xpath);

    xpath = strchr(xpath, quot);
    ++xpath;
    assert(!strncmp(xpath, "]/", 2));
    xpath += 2;

    sr_val = (sr_new_val ? sr_new_val : sr_old_val);

    switch (sr_oper) {
    case SR_OP_CREATED:
    case SR_OP_DELETED:
    case SR_OP_MODIFIED:
        if (!strcmp(xpath, "id")) {
            assert(id == sr_val->data.uint32_val);
        } else if (!strcmp(xpath, "fingerprint")) {
            fingerprint = sr_val->data.string_val;
        } else if (!strcmp(xpath, "map-type")) {
            map_type = convert_str_to_map_type(sr_val->data.identityref_val);
            if (!map_type) {
                EINT;
                return -1;
            }
        } else if (!strcmp(xpath, "name")) {
            name = sr_val->data.string_val;
        } else {
            EINT;
            return -1;
        }

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
        break;
    case SR_OP_MOVED:
        EINT;
        return -1;
    }

    return rc;
}

#endif

static int
set_ch_client_endpoint_address(const char *client_name, const char *endpt_name, sr_change_oper_t sr_oper,
                               sr_val_t *UNUSED(sr_old_val), sr_val_t *sr_new_val)
{
    int rc = -1;

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
    int rc = -1;

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
set_ch_client_ssh_host_key(sr_session_ctx_t *srs, const char *client_name, sr_change_oper_t sr_oper,
                           sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    int rc = 0;
    char *key1, *key2, quot;
    const char *ptr;
    pthread_t tid;
    struct thread_arg targ;

    switch (sr_oper) {
    case SR_OP_DELETED:
        rc = nc_server_ssh_ch_client_del_hostkey(client_name, sr_old_val->data.string_val, -1);
        break;
    case SR_OP_MODIFIED:
        rc = nc_server_ssh_ch_client_mod_hostkey(client_name, sr_old_val->data.string_val, sr_new_val->data.string_val);
        break;
    case SR_OP_CREATED:
        rc = nc_server_ssh_ch_client_add_hostkey(client_name, sr_new_val->data.string_val, -1);
        break;
    case SR_OP_MOVED:
        /* old and new_val are different in this case (nodes one level up) */
        targ.srs = srs;
        targ.listen_or_ch = 0;
        targ.endpt_client_name = client_name;

        ptr = strrchr(sr_new_val->xpath, '[');
        assert(!strncmp(ptr, "[name=", 6));
        ptr += 6;
        quot = ptr[0];
        ++ptr;
        targ.key_name = strndup(ptr, strchr(ptr, quot) - ptr);

        pthread_create(&tid, NULL, get_ssh_host_key_public_key, &targ);
        pthread_join(tid, (void **)&key1);
        free((char *)targ.key_name);
        if (!key1) {
            ERR("Failed to get a public key from sysrepo.");
            return -1;
        }

        ptr = strrchr(sr_old_val->xpath, '[');
        assert(!strncmp(ptr, "[name=", 6));
        ptr += 6;
        quot = ptr[0];
        ++ptr;
        targ.key_name = strndup(ptr, strchr(ptr, quot) - ptr);

        pthread_create(&tid, NULL, get_ssh_host_key_public_key, &targ);
        pthread_join(tid, (void **)&key2);
        free((char *)targ.key_name);
        if (!key2) {
            ERR("Failed to get a public key from sysrepo.");
            return -1;
        }

        rc = nc_server_ssh_ch_client_mov_hostkey(client_name, key1, key2);
        break;
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

    return 0;
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

    return 0;
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
module_change_resolve(sr_session_ctx_t *srs, sr_change_oper_t sr_oper, sr_val_t *sr_old_val, sr_val_t *sr_new_val,
                      const char **list1_key_del, const char **list2_key_del)
{
    int rc = -2;
    const char *xpath, *list1_key = NULL, *list2_key = NULL, *oper_str = NULL;
#ifdef NC_ENABLED_TLS
    char quot;
#endif

    xpath = (sr_old_val ? sr_old_val->xpath : sr_new_val->xpath);
    assert(!strncmp(xpath, "/ietf-netconf-server:netconf-server", 35));

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

    xpath += 35;

    if (!xpath[0]) {
        /* while container was deleted/created, ok, whatever */
        return 0;
    }

    assert(xpath[0] == '/');
    ++xpath;

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
                return 0;
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
                            /* list moved */
                            rc = set_listen_endpoint_ssh_host_key(srs, list1_key, sr_oper, sr_old_val, sr_new_val);
                        } else if (xpath[0] == '/') {
                            ++xpath;

                            if (!strcmp(xpath, "name")) {
                                /* we just don't care  */
                                rc = 0;
                            } else if (!strcmp(xpath, "public-key")) {
                                rc = set_listen_endpoint_ssh_host_key(srs, list1_key, sr_oper, sr_old_val, sr_new_val);
                            }
                        }
                    }
                }
#ifdef NC_ENABLED_TLS
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
                        assert(!strncmp(xpath, "[name=", 6));
                        xpath += 6;
                        quot = xpath[0];
                        ++xpath;
                        xpath = strchr(xpath, quot);
                        ++xpath;
                        assert(!strncmp(xpath, "]/", 2));
                        xpath += 2;

                        if (!strcmp(xpath, "name")) {
                            rc = set_tls_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                        }
                    }
                } else if (!strcmp(xpath, "client-auth")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "client-auth/", 12)) {
                    xpath += 12;
                    if (!strcmp(xpath, "trusted-ca-certs")) {
                        rc = add_tls_trusted_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    } else if (!strcmp(xpath, "trusted-client-certs")) {
                        rc = add_tls_trusted_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    } else if (!strcmp(xpath, "cert-maps")) {
                        /* ignore */
                        rc = 0;
                    } else if (!strncmp(xpath, "cert-maps/", 10)) {
                        xpath += 10;
                        rc = add_tls_ctn(xpath, list1_key, sr_oper, sr_old_val, sr_new_val, 0);
                    }
                }
#endif
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
                        rc = nc_connect_ch_client_dispatch(list1_key, np2srv_new_session_clb);
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
                            /* list moved */
                            rc = set_ch_client_ssh_host_key(srs, list1_key, sr_oper, sr_old_val, sr_new_val);
                        } else if (xpath[0] == '/') {
                            ++xpath;

                            if (!strcmp(xpath, "name")) {
                                /* we just don't care  */
                                rc = EXIT_SUCCESS;
                            } else if (!strcmp(xpath, "public-key")) {
                                rc = set_ch_client_ssh_host_key(srs, list1_key, sr_oper, sr_old_val, sr_new_val);
                            }
                        }
                    }
                }
#ifdef NC_ENABLED_TLS
            } else if (!strcmp(xpath, "tls")) {
                if (sr_oper == SR_OP_CREATED) {
                    rc = nc_server_ch_add_client(list1_key, NC_TI_OPENSSL);
                    if (!rc) {
                        rc = nc_connect_ch_client_dispatch(list1_key, np2srv_new_session_clb);
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
                        assert(!strncmp(xpath, "[name=", 6));
                        xpath += 6;
                        quot = xpath[0];
                        ++xpath;
                        xpath = strchr(xpath, quot);
                        ++xpath;
                        assert(!strncmp(xpath, "]/", 2));
                        xpath += 2;

                        if (!strcmp(xpath, "name")) {
                            rc = set_tls_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                        }
                    }
                } else if (!strcmp(xpath, "client-auth")) {
                    /* ignore */
                    rc = 0;
                } else if (!strncmp(xpath, "client-auth/", 12)) {
                    xpath += 12;
                    if (!strcmp(xpath, "trusted-ca-certs")) {
                        rc = add_tls_trusted_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    } else if (!strcmp(xpath, "trusted-client-certs")) {
                        rc = add_tls_trusted_cert(list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    } else if (!strcmp(xpath, "cert-maps")) {
                        /* ignore */
                        rc = 0;
                    } else if (!strncmp(xpath, "cert-maps/", 10)) {
                        xpath += 10;
                        rc = add_tls_ctn(xpath, list1_key, sr_oper, sr_old_val, sr_new_val, 1);
                    }
                }
#endif
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
                    } else if (!strcmp(xpath, "reconnect_timeout")) {
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
        rc = -1;
    }
    return rc;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), sr_notif_event_t event,
                 void *UNUSED(private_ctx))
{
    int rc;
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    const char *list1_key_del = NULL, *list2_key_del = NULL;

    if (event != SR_EV_APPLY) {
        ERR("%s: unexpected event.", __func__);
        return -1;
    }

    if (np2srv_sr_get_changes_iter(session, "/ietf-netconf-server:netconf-server//*", &sr_iter, NULL)) {
        return -1;
    }
    while (!(rc = np2srv_sr_get_change_next(session, sr_iter, &sr_oper, &sr_old_val, &sr_new_val, NULL))) {
        if ((sr_old_val
                && ((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))
                || (sr_new_val
                && ((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED)))) {
            /* no semantic meaning */
            continue;
        }

        rc = module_change_resolve(session, sr_oper, sr_old_val, sr_new_val, &list1_key_del, &list2_key_del);

        sr_free_val(sr_old_val);
        sr_free_val(sr_new_val);

        if (rc) {
            break;
        }
    }
    lydict_remove(np2srv.ly_ctx, list1_key_del);
    lydict_remove(np2srv.ly_ctx, list2_key_del);
    sr_free_change_iter(sr_iter);

    if (rc == 1) {
        /* it's fine */
        return 0;
    }
    return rc;
}

int
feature_change_ietf_netconf_server(const char *feature_name, bool enabled)
{
    int rc = 0;
    const char *path = NULL;
    sr_val_iter_t *sr_iter;
    sr_val_t *sr_val;

    assert(feature_name);

    if (enabled) {
        if (!strcmp(feature_name, "ssh-listen")) {
            path = "/ietf-netconf-server:netconf-server/listen/endpoint[ssh]//*";
        } else if (!strcmp(feature_name, "ssh-call-home")) {
            path = "/ietf-netconf-server:netconf-server/call-home/netconf-client[ssh]//*";
#ifdef NC_ENABLED_TLS
        } else if (!strcmp(feature_name, "tls-listen")) {
            path = "/ietf-netconf-server:netconf-server/listen/endpoint[tls]//*";
        } else if (!strcmp(feature_name, "tls-call-home")) {
            path = "/ietf-netconf-server:netconf-server/call-home/netconf-client[tls]//*";
#endif
        } else {
            VRB("Unknown or unsupported feature \"%s\" enabled, ignoring.", feature_name);
            return 0;
        }

        if (np2srv_sr_get_items_iter(np2srv.sr_sess.srs, path, &sr_iter, NULL)) {
            return -1;
        }

        while (!(rc = np2srv_sr_get_item_next(np2srv.sr_sess.srs, sr_iter, &sr_val, NULL))) {
            if (sr_val->type == SR_LIST_T) {
                /* no semantic meaning */
                continue;
            }

            rc = module_change_resolve(np2srv.sr_sess.srs, SR_OP_CREATED, NULL, sr_val, NULL, NULL);
            sr_free_val(sr_val);
            if (rc) {
                break;
            }
        }
        sr_free_val_iter(sr_iter);
        if (rc == -1) {
            return rc;
        }
    } else {
        if (!strcmp(feature_name, "ssh-listen")) {
            nc_server_del_endpt(NULL, NC_TI_LIBSSH);
        } else if (!strcmp(feature_name, "ssh-call-home")) {
            nc_server_ch_del_client(NULL, NC_TI_LIBSSH);
#ifdef NC_ENABLED_TLS
        } else if (!strcmp(feature_name, "tls-listen")) {
            nc_server_del_endpt(NULL, NC_TI_OPENSSL);
        } else if (!strcmp(feature_name, "tls-call-home")) {
            nc_server_ch_del_client(NULL, NC_TI_OPENSSL);
#endif
        } else {
            VRB("Unknown or unsupported feature \"%s\" disabled, ignoring.", feature_name);
            return 0;
        }
    }

    return 0;
}

int
ietf_netconf_server_init(const struct lys_module *module)
{
    if (np2srv_sr_module_change_subscribe(np2srv.sr_sess.srs, "ietf-netconf-server", module_change_cb, NULL, 0,
            SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr, NULL)) {
        return -1;
    }

    /* set callbacks */
    nc_server_ssh_set_hostkey_clb(np_hostkey_clb, NULL, NULL);
#ifdef NC_ENABLED_TLS
    nc_server_tls_set_server_cert_clb(np_server_cert_clb, NULL, NULL);
    nc_server_tls_set_trusted_cert_list_clb(np_trusted_cert_list_clb, NULL, NULL);
#endif

    /* applies the whole current configuration */
    if (lys_features_state(module, "ssh-listen") == 1) {
        if (feature_change_ietf_netconf_server("ssh-listen", 1)) {
            return -1;
        }
    }
    if (lys_features_state(module, "ssh-call-home") == 1) {
        if (feature_change_ietf_netconf_server("ssh-call-home", 1)) {
            return -1;
        }
    }
#ifdef NC_ENABLED_TLS
    if (lys_features_state(module, "tls-listen") == 1) {
        if (feature_change_ietf_netconf_server("tls-listen", 1)) {
            return -1;
        }
    }
    if (lys_features_state(module, "tls-call-home") == 1) {
        if (feature_change_ietf_netconf_server("tls-call-home", 1)) {
            return -1;
        }
    }
#endif

    return 0;
}
