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
#define _DEFAULT_SOURCE /* getpwent() */
#define _POSIX_C_SOURCE 200809L /* getline() */

#include "netconf_server_ssh.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <ctype.h>

#include <libssh/libssh.h>
#include <nc_server.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "config.h"
#include "common.h"
#include "log.h"
#include "netconf_server.h"

int
np2srv_hostkey_cb(const char *name, void *UNUSED(user_data), char **UNUSED(privkey_path), char **privkey_data,
        NC_SSH_KEY_TYPE *privkey_type)
{
    sr_session_ctx_t *sr_sess;
    char *xpath;
    struct lyd_node *data = NULL;
    int r, rc = -1;

    r = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (r != SR_ERR_OK) {
        return -1;
    }

    /* get hostkey data from sysrepo */
    if (asprintf(&xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']", name) == -1) {
        EMEM;
        goto cleanup;
    }
    r = sr_get_subtree(sr_sess, xpath, 0, &data);
    free(xpath);
    if (r != SR_ERR_OK) {
        goto cleanup;
    } else if (!data) {
        ERR("Hostkey \"%s\" not found.", name);
        goto cleanup;
    }

    /* parse private key values */
    if (np2srv_sr_get_privkey(data, privkey_data, privkey_type)) {
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
np2srv_pubkey_auth_cb(const struct nc_session *session, ssh_key key, void *UNUSED(user_data))
{
    FILE *f = NULL;
    struct passwd *pwd;
    ssh_key pub_key = NULL;
    enum ssh_keytypes_e ktype;
    const char *username;
    char *line = NULL, *ptr, *ptr2;
    size_t n;
    int r, ret = 1, line_num = 0;

    username = nc_session_get_username(session);

    errno = 0;
    pwd = getpwnam(username);
    if (!pwd) {
        ERR("Failed to find user entry for \"%s\" (%s).", username, errno ? strerror(errno) : "User not found");
        goto cleanup;
    }

    /* check any authorized keys */
    r = asprintf(&line, NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN, NP2SRV_SSH_AUTHORIZED_KEYS_ARG_IS_USERNAME ? pwd->pw_name : pwd->pw_dir);
    if (r == -1) {
        EMEM;
        line = NULL;
        goto cleanup;
    }
    n = r;

    f = fopen(line, "r");
    if (!f) {
        if (errno == ENOENT) {
            VRB("User \"%s\" has no authorized_keys file.", username);
        } else {
            ERR("Failed to open \"%s\" authorized_keys file (%s).", line, strerror(errno));
        }
        goto cleanup;
    }

    while (getline(&line, &n, f) > -1) {
        ++line_num;

        /* separate key type */
        ptr = line;
        for (ptr2 = ptr; !isspace(ptr2[0]); ++ptr2);
        if (ptr2[0] == '\0') {
            WRN("Invalid authorized key format of \"%s\" (line %d).", username, line_num);
            continue;
        }
        ptr2[0] = '\0';

        /* detect key type */
        ktype = ssh_key_type_from_name(ptr);
        if (ktype == SSH_KEYTYPE_UNKNOWN) {
            WRN("Unknown key type \"%s\" (line %d).", ptr, line_num);
            continue;
        }

        /* separate key data */
        ptr = ptr2 + 1;
        for (ptr2 = ptr; !isspace(ptr2[0]); ++ptr2);
        ptr2[0] = '\0';

        r = ssh_pki_import_pubkey_base64(ptr, ktype, &pub_key);
        if (r != SSH_OK) {
            WRN("Failed to import authorized key of \"%s\" (%s, line %d).",
                    username, r == SSH_EOF ? "Unexpected end-of-file" : "SSH error", line_num);
            continue;
        }

        /* compare public keys */
        if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
            /* key matches */
            ret = 0;
            goto cleanup;
        }

        /* not a match, next key */
        ssh_key_free(pub_key);
        pub_key = NULL;
    }
    if (!feof(f)) {
        WRN("Failed reading from authorized_keys file of \"%s\".", username);
        goto cleanup;
    }

    /* no match */

cleanup:
    if (f) {
        fclose(f);
    }
    free(line);
    ssh_key_free(pub_key);
    return ret;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh */
int
np2srv_endpt_ssh_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name;
    int rc, failed = 0;

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
            if (nc_server_add_endpt(endpt_name, NC_TI_LIBSSH)) {
                failed = 1;
            }
            /* turn off all auth methods by default */
            nc_server_ssh_endpt_set_auth_methods(endpt_name, 0);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_del_endpt(endpt_name, NC_TI_LIBSSH)) {
                failed = 1;
            }
        }
    }
    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return failed ? SR_ERR_INTERNAL : SR_ERR_OK;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/server-identity/host-key/public-key/
 * keystore-reference */
int
np2srv_endpt_ssh_hostkey_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *endpt_name;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL)) == SR_ERR_OK) {
        /* find name */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->child);

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_ssh_endpt_add_hostkey(endpt_name, lyd_get_value(node), -1);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_is_endpt(endpt_name)) {
                rc = nc_server_ssh_endpt_del_hostkey(endpt_name, lyd_get_value(node), -1);
            }
        } else if (op == SR_OP_MOVED) {
            rc = nc_server_ssh_endpt_mov_hostkey(endpt_name, lyd_get_value(node), prev_val);
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

static int
np2srv_ssh_update_auth_method(const struct lyd_node *node, sr_change_oper_t op, int cur_auth)
{
    int auth;

    auth = cur_auth;

    if (!strcmp(node->schema->name, "publickey")) {
        if (op == SR_OP_CREATED) {
            auth |= NC_SSH_AUTH_PUBLICKEY;
        } else if (op == SR_OP_DELETED) {
            auth &= ~NC_SSH_AUTH_PUBLICKEY;
        }
    } else if (!strcmp(node->schema->name, "passsword")) {
        if (op == SR_OP_CREATED) {
            auth |= NC_SSH_AUTH_PASSWORD;
        } else if (op == SR_OP_DELETED) {
            auth &= ~NC_SSH_AUTH_PASSWORD;
        }
    } else if (!strcmp(node->schema->name, "hostbased") || !strcmp(node->schema->name, "none")) {
        WRN("SSH authentication \"%s\" not supported.", node->schema->name);
    } else if (!strcmp(node->schema->name, "other")) {
        if (!strcmp(lyd_get_value(node), "interactive")) {
            if (op == SR_OP_CREATED) {
                auth |= NC_SSH_AUTH_INTERACTIVE;
            } else if (op == SR_OP_DELETED) {
                auth &= ~NC_SSH_AUTH_INTERACTIVE;
            }
        } else {
            WRN("SSH authentication \"%s\" not supported.", lyd_get_value(node));
        }
    }

    return auth;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/
 * supported-authentication-methods */
int
np2srv_endpt_ssh_auth_methods_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name;
    char *xpath2;
    int rc, auth;

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

        if ((op == SR_OP_DELETED) && !nc_server_is_endpt(endpt_name)) {
            /* endpt deleted */
            continue;
        }

        /* current methods */
        auth = nc_server_ssh_endpt_get_auth_methods(endpt_name);

        auth = np2srv_ssh_update_auth_method(node, op, auth);

        /* updated methods */
        if (nc_server_ssh_endpt_set_auth_methods(endpt_name, auth)) {
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

static int
np2srv_user_add_auth_key(const char *alg, size_t alg_len, const char *key, size_t key_len, struct lyd_node *user,
        uint8_t *key_idx)
{
    char name[7], *str;
    struct lyd_node *authkey;

    /* list with name */
    sprintf(name, "key%d", (*key_idx)++);
    if (lyd_new_list(user, NULL, "authorized-key", 0, &authkey, name)) {
        return -1;
    }

    /* algorithm */
    str = strndup(alg, alg_len);
    if (!str) {
        EMEM;
        return -1;
    }
    lyd_new_term(authkey, NULL, "algorithm", str, 0, NULL);
    free(str);

    /* key-data */
    str = strndup(key, key_len);
    if (!str) {
        EMEM;
        return -1;
    }
    lyd_new_term(authkey, NULL, "key-data", str, 0, NULL);
    free(str);

    return 0;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/users */
/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/ssh-server-parameters/
 * client-authentication/users */
int
np2srv_endpt_ssh_auth_users_oper_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id),
        const char *UNUSED(module_name), const char *UNUSED(path), const char *UNUSED(request_xpath),
        uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct passwd *pwd;
    struct lyd_node *users, *user;
    char *path, *line = NULL, *ptr, *alg, *data;
    size_t line_len = 0;
    FILE *f = NULL;
    int rc = SR_ERR_INTERNAL;
    uint8_t key_idx;

    if (lyd_new_inner(*parent, NULL, "users", 0, &users)) {
        return SR_ERR_INTERNAL;
    }

    while ((pwd = getpwent())) {
        /* create user with name */
        if (lyd_new_list(users, NULL, "user", 0, &user, pwd->pw_name)) {
            return SR_ERR_INTERNAL;
        }

        /* check any authorized keys */
        if (asprintf(&path, NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN, NP2SRV_SSH_AUTHORIZED_KEYS_ARG_IS_USERNAME ?
                pwd->pw_name : pwd->pw_dir) == -1) {
            EMEM;
            goto cleanup;
        }
        f = fopen(path, "r");
        if (!f) {
            if ((errno != ENOENT) && (errno != ENOTDIR) && (errno != EACCES)) {
                ERR("Opening \"%s\" authorized key file failed (%s).", path, strerror(errno));
                free(path);
                goto cleanup;
            }

            if (errno == EACCES) {
                VRB("Skipping \"%s\" authorized key file (%s).", path, strerror(errno));
            }

            free(path);
            continue;
        }
        free(path);

        /* create authorized keys */
        key_idx = 1;
        while (getline(&line, &line_len, f) != -1) {
            if ((line[0] == '\0') || (line[0] == '#')) {
                continue;
            }

            /* find algorithm */
            ptr = line;
            while (strncmp(ptr, "ssh-dss", 7) && strncmp(ptr, "ssh-rsa", 7) && strncmp(ptr, "ecdsa", 5)) {
                ptr = strchr(ptr, ' ');
                if (!ptr) {
                    break;
                }
                ++ptr;
            }
            if (!ptr) {
                /* unrecognized line */
                continue;
            }
            alg = ptr;

            /* find data */
            ptr = strchr(ptr, ' ');
            if (!ptr) {
                /* unrecognized line */
                continue;
            }

            ++ptr;
            data = ptr;
            if (!(ptr = strchr(data, ' ')) && !(ptr = strchr(data, '\n'))) {
                ptr = data + strlen(data);
            }

            /* create new authorized key */
            if (np2srv_user_add_auth_key(alg, strchr(alg, ' ') - alg, data, ptr - data, user, &key_idx)) {
                goto cleanup;
            }
        }
        if (ferror(f)) {
            ERR("Reading from an authorized keys file failed (%s).", strerror(errno));
            goto cleanup;
        }
        fclose(f);
        f = NULL;
    }

    /* success */
    rc = SR_ERR_OK;

cleanup:
    free(line);
    if (f) {
        fclose(f);
    }
    endpwent();
    return rc;
}

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh */
int
np2srv_ch_client_endpt_ssh_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
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
            rc = nc_server_ch_client_add_endpt(client_name, endpt_name, NC_TI_LIBSSH);
            /* turn off all auth methods by default */
            nc_server_ssh_ch_client_endpt_set_auth_methods(client_name, endpt_name, 0);
        } else if (op == SR_OP_DELETED) {
            rc = nc_server_ch_client_del_endpt(client_name, endpt_name, NC_TI_LIBSSH);
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/ssh-server-parameters/
 * server-identity/host-key/public-key/keystore-reference */
int
np2srv_ch_endpt_ssh_hostkey_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *endpt_name, *client_name;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL)) == SR_ERR_OK) {
        /* find name */
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->parent->parent->child);

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_ssh_ch_client_endpt_add_hostkey(client_name, endpt_name, lyd_get_value(node), -1);
        } else if (op == SR_OP_DELETED) {
            if (nc_server_ch_client_is_endpt(client_name, endpt_name)) {
                rc = nc_server_ssh_ch_client_endpt_del_hostkey(client_name, endpt_name, lyd_get_value(node), -1);
            }
        } else if (op == SR_OP_MOVED) {
            rc = nc_server_ssh_ch_client_endpt_mov_hostkey(client_name, endpt_name, lyd_get_value(node), prev_val);
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

/* /ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/ssh-server-parameters/
 * client-authentication/supported-authentication-methods */
int
np2srv_ch_endpt_ssh_auth_methods_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *endpt_name, *client_name;
    char *xpath2;
    int rc, auth;

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
        endpt_name = lyd_get_value(node->parent->parent->parent->parent->parent->child);
        client_name = lyd_get_value(node->parent->parent->parent->parent->parent->parent->parent->child);

        if ((op == SR_OP_DELETED) && !nc_server_ch_client_is_endpt(client_name, endpt_name)) {
            continue;
        }

        /* current methods */
        auth = nc_server_ssh_ch_client_endpt_get_auth_methods(client_name, endpt_name);

        auth = np2srv_ssh_update_auth_method(node, op, auth);

        /* updated methods */
        if (nc_server_ssh_ch_client_endpt_set_auth_methods(client_name, endpt_name, auth)) {
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
