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
#define _DEFAULT_SOURCE /* getpwent() */
#define _POSIX_C_SOURCE 200809L /* getline() */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>

#include <libssh/libssh.h>
#include <nc_server.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

int
np2srv_hostkey_cb(const char *name, void *UNUSED(user_data), char **UNUSED(privkey_path), char **privkey_data,
        NC_SSH_KEY_TYPE *privkey_type)
{
    sr_session_ctx_t *sr_sess;
    char *xpath;
    struct lyd_node *data = NULL, *node;
    struct lyd_node_leaf_list *alg = NULL, *privkey = NULL;
    int r, rc = -1;

    r = sr_session_start(np2srv.sr_conn, SR_DS_OPERATIONAL, &sr_sess);
    if (r != SR_ERR_OK) {
        return -1;
    }

    /* get hostkey data from sysrepo */
    if (asprintf(&xpath, "/ietf-netconf-server:netconf-server//endpoint/ssh/ssh-server-parameters/"
                "server-identity/host-key[name='%s']/public-key/local-definition", name) == -1) {
        EMEM;
        goto cleanup;
    }
    r = sr_get_subtree(sr_sess, xpath, &data);
    free(xpath);
    if (r != SR_ERR_OK) {
        goto cleanup;
    } else if (!data) {
        ERR("Hostkey \"%s\" not found.", name);
        goto cleanup;
    }

    /* find the nodes */
    LY_TREE_FOR(data->child, node) {
        if (!strcmp(node->schema->name, "algorithm")) {
            alg = (struct lyd_node_leaf_list *)node;
        } else if (!strcmp(node->schema->name, "private-key")) {
            privkey = (struct lyd_node_leaf_list *)node;
        }
    }
    if (!alg || !privkey) {
        ERR("Failed to find hostkey \"%s\" private key information.", name);
        goto cleanup;
    }

    /* set algorithm */
    if (!strncmp(alg->value.ident->name, "rsa", 3)) {
        *privkey_type = NC_SSH_KEY_RSA;
    } else if (!strncmp(alg->value.ident->name, "secp", 4)) {
        *privkey_type = NC_SSH_KEY_ECDSA;
    } else {
        ERR("Unknown private key algorithm \"%s\".", alg->value_str);
        goto cleanup;
    }

    /* set data */
    *privkey_data = strdup(privkey->value_str);
    if (!*privkey_data) {
        EMEM;
        goto cleanup;
    }

    /* success */
    rc = 0;

cleanup:
    while (data->parent) {
        data = data->parent;
    }
    lyd_free_withsiblings(data);
    sr_session_stop(sr_sess);
    return rc;
}

int
np2srv_pubkey_auth_cb(const struct nc_session *session, ssh_key key, void *UNUSED(user_data))
{
    struct passwd *pwd;
    ssh_key pub_key;
    const char *username;
    char *path;
    int ret;

    username = nc_session_get_username(session);

    errno = 0;
    pwd = getpwnam(username);
    if (!pwd) {
        ERR("Failed to find user entry for \"%s\" (%s).", username, errno ? strerror(errno) : "User not found");
        return 1;
    }

    /* check any authorized keys */
    if (asprintf(&path, "%s/.ssh/authorized_keys", pwd->pw_dir) == -1) {
        EMEM;
        return 1;
    }

    ret = ssh_pki_import_pubkey_file(path, &pub_key);
    free(path);
    if (ret != SSH_OK) {
        WRN("Failed to import authorized keys of \"%s\" (%s).", username, ret == SSH_EOF ? "Unexpected end-of-file" : "SSH error");
        return 1;
    }

        /*case NC_SSH_KEY_DSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_DSS, &pub_key);
            break;
        case NC_SSH_KEY_RSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_RSA, &pub_key);
            break;
        case NC_SSH_KEY_ECDSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_ECDSA, &pub_key);
            break;
        }*/

    if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
        ssh_key_free(pub_key);
        return 0;
    }

    ssh_key_free(pub_key);
    return 1;
}

/* /ietf-netconf-server:netconf-server/listen/idle-timeout */
int
np2srv_idle_timeout_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_notif_event_t UNUSED(event), void *UNUSED(private_data))
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh */
int
np2srv_endpt_ssh_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_notif_event_t UNUSED(event), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list, *name;
    bool prev_dflt;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* get name */
        name = ((struct lyd_node_leaf_list *)node->parent->child)->value_str;

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_add_endpt(name, NC_TI_LIBSSH);
            /* turn off all auth methods by default */
            nc_server_ssh_endpt_set_auth_methods(name, 0);
        } else if (op == SR_OP_DELETED) {
            rc = nc_server_del_endpt(name, NC_TI_LIBSSH);
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/tcp-server-parameters */
int
np2srv_endpt_tcp_params_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_notif_event_t UNUSED(event), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node, *tmp;
    const char *prev_val, *prev_list, *endpt_name = NULL;
    char *xpath2;
    bool prev_dflt;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return -1;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* ignore other operations */
        if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
            /* find endpoint name */
            for (tmp = node; tmp && strcmp(tmp->schema->name, "endpoint"); tmp = tmp->parent);
            assert(tmp);
            endpt_name = ((struct lyd_node_leaf_list *)tmp->child)->value_str;

            if (!strcmp(node->schema->name, "local-address")) {
                if (nc_server_endpt_set_address(endpt_name, ((struct lyd_node_leaf_list *)node)->value_str)) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            } else if (!strcmp(node->schema->name, "local-port")) {
                if (nc_server_endpt_set_port(endpt_name, ((struct lyd_node_leaf_list *)node)->value.uint16)) {
                    sr_free_change_iter(iter);
                    return SR_ERR_INTERNAL;
                }
            } else if (!strcmp(node->schema->name, "keepalives")) {
                WRN("keepalives configuration not supported.");
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/server-identity/host-key */
int
np2srv_endpt_ssh_hostkey_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_notif_event_t UNUSED(event), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node, *tmp;
    const char *prev_val, *prev_list, *endpt_name;
    bool prev_dflt;
    int rc;

    rc = sr_get_changes_iter(session, xpath, &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* find endpoint name */
        for (tmp = node; tmp && strcmp(tmp->schema->name, "endpoint"); tmp = tmp->parent);
        assert(tmp);
        endpt_name = ((struct lyd_node_leaf_list *)tmp->child)->value_str;

        /* ignore other operations */
        if (op == SR_OP_CREATED) {
            rc = nc_server_ssh_endpt_add_hostkey(endpt_name, ((struct lyd_node_leaf_list *)node->child)->value_str, -1);
        } else if (op == SR_OP_DELETED) {
            rc = nc_server_ssh_endpt_del_hostkey(endpt_name, ((struct lyd_node_leaf_list *)node->child)->value_str, -1);
        } else if (op == SR_OP_MOVED) {
            rc = nc_server_ssh_endpt_mov_hostkey(endpt_name, ((struct lyd_node_leaf_list *)node->child)->value_str, prev_val);
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

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/
 * supported-authentication-methods */
int
np2srv_endpt_ssh_auth_methods_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_notif_event_t UNUSED(event), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node, *tmp;
    struct lyd_node_leaf_list *leaf;
    const char *prev_val, *prev_list, *endpt_name = NULL;
    char *xpath2;
    bool prev_dflt;
    int rc, auth;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return -1;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        /* find endpoint name */
        for (tmp = node; tmp && strcmp(tmp->schema->name, "endpoint"); tmp = tmp->parent);
        assert(tmp);
        endpt_name = ((struct lyd_node_leaf_list *)tmp->child)->value_str;

        /* current methods */
        auth = nc_server_ssh_endpt_get_auth_methods(endpt_name);

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
            leaf = (struct lyd_node_leaf_list *)node;
            if (!strcmp(leaf->value_str, "interactive")) {
                if (op == SR_OP_CREATED) {
                    auth |= NC_SSH_AUTH_INTERACTIVE;
                } else if (op == SR_OP_DELETED) {
                    auth &= ~NC_SSH_AUTH_INTERACTIVE;
                }
            } else {
                WRN("SSH authentication \"%s\" not supported.", leaf->value_str);
            }
        }

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
    char name[6], *str;
    struct lyd_node *authkey;

    authkey = lyd_new(user, NULL, "authorized-key");
    if (!authkey) {
        return -1;
    }

    /* name */
    sprintf(name, "key%d", (*key_idx)++);
    if (!lyd_new_leaf(authkey, NULL, "name", name)) {
        return -1;
    }

    /* algorithm */
    str = strndup(alg, alg_len);
    if (!str) {
        EMEM;
        return -1;
    }
    lyd_new_leaf(authkey, NULL, "algorithm", str);
    free(str);

    /* key-data */
    str = strndup(key, key_len);
    if (!str) {
        EMEM;
        return -1;
    }
    lyd_new_leaf(authkey, NULL, "key-data", str);
    free(str);

    return 0;
}

/* /ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/users */
int
np2srv_endpt_ssh_auth_users_oper_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name),
        const char *UNUSED(path), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct passwd *pwd;
    struct lyd_node *users, *user;
    char *path, *line = NULL, *ptr, *alg, *data;
    size_t line_len = 0;
    FILE *f = NULL;
    int rc = SR_ERR_INTERNAL;
    uint8_t key_idx;

    users = lyd_new(*parent, NULL, "users");
    if (!users) {
        return SR_ERR_INTERNAL;
    }

    while ((pwd = getpwent())) {
        /* create user with name */
        user = lyd_new(users, NULL, "user");
        if (!user) {
            return SR_ERR_INTERNAL;
        }
        lyd_new_leaf(user, NULL, "name", pwd->pw_name);

        /* check any authorized keys */
        if (asprintf(&path, "%s/.ssh/authorized_keys", pwd->pw_dir) == -1) {
            EMEM;
            goto cleanup;
        }
        f = fopen(path, "r");
        free(path);
        if (!f) {
            if (errno != ENOENT) {
                ERR("Opening \"%s\" authorized key file failed (%s).", strerror(errno));
                goto cleanup;
            }
            continue;
        }

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
            if (!(ptr = strchr(ptr, ' ')) && !(ptr = strchr(ptr, '\n'))) {
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
