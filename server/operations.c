/**
 * @file operations.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Basic NETCONF operations
 *
 * Copyright (c) 2016-2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include <sysrepo.h>

#include "common.h"
#include "operations.h"

/* lock for accessing/reconnecting sysrepo connection and all sysrepo sessions */
pthread_rwlock_t sr_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct nc_server_reply *
op_build_err_sr(struct nc_server_reply *ereply, sr_session_ctx_t *session)
{
    const sr_error_info_t *err_info;
    size_t err_count, i;
    struct nc_server_error *e = NULL;

    /* get all sysrepo errors connected with the last sysrepo operation */
    sr_get_last_errors(session, &err_info, &err_count);
    for (i = 0; i < err_count; ++i) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, err_info[i].message, "en");
        if (err_info[i].xpath) {
            nc_err_set_path(e, err_info[i].xpath);
        }
        if (ereply) {
            nc_server_reply_add_err(ereply, e);
        } else {
            ereply = nc_server_reply_err(e);
        }
        e = NULL;
    }

    return ereply;
}

int
np2srv_sr_session_switch_ds(sr_session_ctx_t *srs, sr_datastore_t ds, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_session_switch_ds(srs, ds);
    }

    if (rc == SR_ERR_DISCONNECT) {
        /* elevate lock to write */
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        /* while we released the lock, someone else could have performed a full reconnect */
        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_session_switch_ds(srs, ds, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_set_item(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts,
                   struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_set_item(srs, xpath, value, opts);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_set_item(srs, xpath, value, opts, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            switch (rc) {
            case SR_ERR_UNAUTHORIZED:
                e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            case SR_ERR_DATA_EXISTS:
                e = nc_err(NC_ERR_DATA_EXISTS, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            case SR_ERR_DATA_MISSING:
                e = nc_err(NC_ERR_DATA_MISSING, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            default:
                *ereply = op_build_err_sr(*ereply, srs);
                break;
            }
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_delete_item(sr_session_ctx_t *srs, const char *xpath, const sr_edit_options_t opts, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_delete_item(srs, xpath, opts);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_delete_item(srs, xpath, opts, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            switch (rc) {
            case SR_ERR_UNAUTHORIZED:
                e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            case SR_ERR_DATA_EXISTS:
                e = nc_err(NC_ERR_DATA_EXISTS, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            case SR_ERR_DATA_MISSING:
                e = nc_err(NC_ERR_DATA_MISSING, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            default:
                *ereply = op_build_err_sr(*ereply, srs);
                break;
            }
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_get_item(sr_session_ctx_t *srs, const char *xpath, sr_val_t **value, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_item(srs, xpath, value);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_item(srs, xpath, value, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_get_items(sr_session_ctx_t *srs, const char *xpath, sr_val_t **values, size_t *value_cnt, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_items(srs, xpath, values, value_cnt);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_items(srs, xpath, values, value_cnt, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_get_changes_iter(sr_session_ctx_t *srs, const char *xpath, sr_change_iter_t **iter, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_changes_iter(srs, xpath, iter);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_changes_iter(srs, xpath, iter, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

/* NOT_FOUND returns 1, no error */
int
np2srv_sr_get_change_next(sr_session_ctx_t *srs, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_change_next(srs, iter, operation, old_value, new_value);
        if (rc == SR_ERR_NOT_FOUND) {
            pthread_rwlock_unlock(&sr_lock);
            return 1;
        }
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

       if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_change_next(srs, iter, operation, old_value, new_value, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

/* UNKNOWN_MODEL, NOT_FOUND, and UNAUTHORIZED return 1, no error */
int
np2srv_sr_get_items_iter(sr_session_ctx_t *srs, const char *xpath, sr_val_iter_t **iter, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_items_iter(srs, xpath, iter);
        if ((rc == SR_ERR_UNKNOWN_MODEL) || (rc == SR_ERR_NOT_FOUND) || (rc == SR_ERR_UNAUTHORIZED)) {
            pthread_rwlock_unlock(&sr_lock);
            return 1;
        }
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_items_iter(srs, xpath, iter, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

/* NOT_FOUND returns 1, no error */
int
np2srv_sr_get_item_next(sr_session_ctx_t *srs, sr_val_iter_t *iter, sr_val_t **value, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_item_next(srs, iter, value);
        if (rc == SR_ERR_NOT_FOUND) {
            /* thats fine */
            pthread_rwlock_unlock(&sr_lock);
            return 1;
        }
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_item_next(srs, iter, value, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_move_item(sr_session_ctx_t *srs, const char *xpath, const sr_move_position_t position,
        const char *relative_item, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_move_item(srs, xpath, position, relative_item);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_move_item(srs, xpath, position, relative_item, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_rpc_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_rpc_send(srs, xpath, input, input_cnt, output, output_cnt);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_rpc_send(srs, xpath, input, input_cnt, output, output_cnt, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            switch (rc) {
            case SR_ERR_UNKNOWN_MODEL:
            case SR_ERR_NOT_FOUND:
                e = nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            default:
                *ereply = op_build_err_sr(*ereply, srs);
                break;
            }
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_action_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_action_send(srs, xpath, input, input_cnt, output, output_cnt);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_action_send(srs, xpath, input, input_cnt, output, output_cnt, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            switch (rc) {
            case SR_ERR_UNKNOWN_MODEL:
            case SR_ERR_NOT_FOUND:
                e = nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT);
                nc_err_set_path(e, xpath);
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
                break;
            default:
                *ereply = op_build_err_sr(*ereply, srs);
                break;
            }
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_check_exec_permission(sr_session_ctx_t *srs, const char *xpath, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;
    bool permitted;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_check_exec_permission(srs, xpath, &permitted);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_check_exec_permission(srs, xpath, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    } else if (!permitted) {
        e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
        if (ereply) {
            if (*ereply) {
                nc_server_reply_add_err(*ereply, e);
            } else {
                *ereply = nc_server_reply_err(e);
            }
        } else {
            ERR("%s failed (sysrepo: access denied).", __func__);
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if ((rc != SR_ERR_OK) || !permitted) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_module_change_subscribe(sr_session_ctx_t *srs, const char *module_name, sr_module_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_module_change_subscribe(srs, module_name, callback, private_ctx, priority, opts, subscription);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_module_change_subscribe(srs, module_name, callback, private_ctx, priority, opts, subscription, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_subtree_change_subscribe(sr_session_ctx_t *srs, const char *xpath, sr_subtree_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_subtree_change_subscribe(srs, xpath, callback, private_ctx, priority, opts, subscription);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_subtree_change_subscribe(srs, xpath, callback, private_ctx, priority, opts, subscription, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_event_notif_subscribe(sr_session_ctx_t *srs, const char *xpath, sr_event_notif_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_event_notif_subscribe(srs, xpath, callback, private_ctx, opts, subscription);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_event_notif_subscribe(srs, xpath, callback, private_ctx, opts, subscription, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_event_notif_replay(sr_session_ctx_t *srs, sr_subscription_ctx_t *subscription, time_t start_time,
        time_t stop_time, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_event_notif_replay(srs, subscription, start_time, stop_time);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_event_notif_replay(srs, subscription, start_time, stop_time, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_event_notif_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, sr_ev_notif_flag_t opts, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_event_notif_send(srs, xpath, values, values_cnt, opts);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_event_notif_send(srs, xpath, values, values_cnt, opts, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_session_start_user(const char *user_name, const sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session, struct nc_server_reply **ereply)
{
    char *msg;
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_session_start_user(np2srv.sr_conn, user_name, datastore, opts, session);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(np2srv.sr_sess.srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_session_start_user(user_name, datastore, opts, session, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            asprintf(&msg, "%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, msg, "en");
            free(msg);

            if (*ereply) {
                nc_server_reply_add_err(*ereply, e);
            } else {
                *ereply = nc_server_reply_err(e);
            }
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_session_stop(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_session_stop(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_session_stop(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_session_set_options(sr_session_ctx_t *srs, const sr_sess_options_t opts, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_session_set_options(srs, opts);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_session_set_options(srs, opts, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_session_refresh(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_session_refresh(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_session_refresh(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_discard_changes(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_discard_changes(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_discard_changes(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_commit(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_commit(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_commit(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_validate(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_validate(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_validate(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_copy_config(sr_session_ctx_t *srs, const char *module_name, sr_datastore_t src_datastore,
        sr_datastore_t dst_datastore, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_copy_config(srs, module_name, src_datastore, dst_datastore);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_copy_config(srs, module_name, src_datastore, dst_datastore, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_lock_datastore(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_lock_datastore(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_lock_datastore(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_unlock_datastore(sr_session_ctx_t *srs, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_unlock_datastore(srs);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_unlock_datastore(srs, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_unsubscribe(sr_session_ctx_t *srs, sr_subscription_ctx_t *subscription, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_unsubscribe(srs, subscription);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_unsubscribe(srs, subscription, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_list_schemas(sr_session_ctx_t *srs, sr_schema_t **schemas, size_t *schema_cnt, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_list_schemas(srs, schemas, schema_cnt);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_list_schemas(srs, schemas, schema_cnt, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_get_submodule_schema(sr_session_ctx_t *srs, const char *submodule_name, const char *submodule_revision,
        sr_schema_format_t format, char **schema_content, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_submodule_schema(srs, submodule_name, submodule_revision, format, schema_content);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_submodule_schema(srs, submodule_name, submodule_revision, format, schema_content, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

int
np2srv_sr_get_schema(sr_session_ctx_t *srs, const char *module_name, const char *revision,
        const char *submodule_name, sr_schema_format_t format, char **schema_content, struct nc_server_reply **ereply)
{
    int rc = SR_ERR_DISCONNECT;
    struct nc_server_error *e;

    pthread_rwlock_rdlock(&sr_lock);

    if (!np2srv.disconnected) {
        rc = sr_get_schema(srs, module_name, revision, submodule_name, format, schema_content);
    }

    if (rc == SR_ERR_DISCONNECT) {
        pthread_rwlock_unlock(&sr_lock);
        pthread_rwlock_wrlock(&sr_lock);

        if ((np2srv.disconnected || (sr_session_check(srs) == SR_ERR_DISCONNECT)) && np2srv_sr_reconnect()) {
            pthread_rwlock_unlock(&sr_lock);

            if (ereply) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                if (*ereply) {
                    nc_server_reply_add_err(*ereply, e);
                } else {
                    *ereply = nc_server_reply_err(e);
                }
            }
            return -1;
        }

        pthread_rwlock_unlock(&sr_lock);
        return np2srv_sr_get_schema(srs, module_name, revision, submodule_name, format, schema_content, ereply);
    }

    if (rc != SR_ERR_OK) {
        if (ereply) {
            *ereply = op_build_err_sr(*ereply, srs);
        } else {
            ERR("%s failed (sysrepo: %s).", __func__, sr_strerror(rc));
        }
    }

    pthread_rwlock_unlock(&sr_lock);
    if (rc != SR_ERR_OK) {
        return -1;
    }
    return 0;
}

char *
op_get_srval(struct ly_ctx *ctx, const sr_val_t *value, char *buf)
{
    struct lys_node_leaf *sleaf;

    if (!value) {
        return NULL;
    }

    switch (value->type) {
    case SR_STRING_T:
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_ANYDATA_T:
    case SR_ANYXML_T:
        return (value->data.string_val);
    case SR_LEAF_EMPTY_T:
        return NULL;
    case SR_BOOL_T:
        return value->data.bool_val ? "true" : "false";
    case SR_DECIMAL64_T:
        /* get fraction-digits */
        sleaf = (struct lys_node_leaf *)ly_ctx_get_node(ctx, NULL, value->xpath, 0);
        if (!sleaf) {
            return NULL;
        }
        while (sleaf->type.base == LY_TYPE_LEAFREF) {
            sleaf = sleaf->type.info.lref.target;
        }
        sprintf(buf, "%.*f", sleaf->type.info.dec64.dig, value->data.decimal64_val);
        return buf;
    case SR_UINT8_T:
        sprintf(buf, "%u", value->data.uint8_val);
        return buf;
    case SR_UINT16_T:
        sprintf(buf, "%u", value->data.uint16_val);
        return buf;
    case SR_UINT32_T:
        sprintf(buf, "%u", value->data.uint32_val);
        return buf;
    case SR_UINT64_T:
        sprintf(buf, "%"PRIu64, value->data.uint64_val);
        return buf;
    case SR_INT8_T:
        sprintf(buf, "%d", value->data.int8_val);
        return buf;
    case SR_INT16_T:
        sprintf(buf, "%d", value->data.int16_val);
        return buf;
    case SR_INT32_T:
        sprintf(buf, "%d", value->data.int32_val);
        return buf;
    case SR_INT64_T:
        sprintf(buf, "%"PRId64, value->data.int64_val);
        return buf;
    default:
        return NULL;
    }

}

int
op_set_srval(struct lyd_node *node, char *path, int dup, sr_val_t *val, char **val_buf)
{
    uint32_t i;
    struct lyd_node_leaf_list *leaf;
    const char *str;
    LY_DATA_TYPE type;

    if (!dup) {
        assert(val_buf);
        (*val_buf) = NULL;
    }

    val->xpath = (dup && path) ? strdup(path) : path;
    val->dflt = 0;
    val->data.int64_val = 0;

    switch (node->schema->nodetype) {
    case LYS_CONTAINER:
        val->type = ((struct lys_node_container *)node->schema)->presence ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
        break;
    case LYS_LIST:
        val->type = SR_LIST_T;
        break;
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (struct lyd_node_leaf_list *)node;
settype:
        type = leaf->value_type;
        switch (type & LY_DATA_TYPE_MASK) {
        case LY_TYPE_BINARY:
            val->type = SR_BINARY_T;
            str = leaf->value.binary;
            val->data.binary_val = (dup && str) ? strdup(str) : (char *)str;
            if (NULL == val->data.binary_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_BITS:
            val->type = SR_BITS_T;
            str = leaf->value_str;
            val->data.bits_val = (dup && str) ? strdup(str) : (char *)str;
            break;
        case LY_TYPE_BOOL:
            val->type = SR_BOOL_T;
            val->data.bool_val = leaf->value.bln;
            break;
        case LY_TYPE_DEC64:
            val->type = SR_DECIMAL64_T;
            val->data.decimal64_val = (double)leaf->value.dec64;
            for (i = 0; i < ((struct lys_node_leaf *)leaf->schema)->type.info.dec64.dig; i++) {
                /* shift decimal point */
                val->data.decimal64_val *= 0.1;
            }
            break;
        case LY_TYPE_EMPTY:
            val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            val->type = SR_ENUM_T;
            str = leaf->value.enm->name;
            val->data.enum_val = (dup && str) ? strdup(str) : (char*)str;
            if (NULL == val->data.enum_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_IDENT:
            val->type = SR_IDENTITYREF_T;
            if (leaf->value.ident->module == leaf->schema->module) {
                str = leaf->value.ident->name;
                val->data.identityref_val = (dup && str) ? strdup(str) : (char*)str;
                if (NULL == val->data.identityref_val) {
                    EMEM;
                    return -1;
                }
            } else {
                str = malloc(strlen(lys_main_module(leaf->value.ident->module)->name) + 1 + strlen(leaf->value.ident->name) + 1);
                if (NULL == str) {
                    EMEM;
                    return -1;
                }
                sprintf((char *)str, "%s:%s", lys_main_module(leaf->value.ident->module)->name, leaf->value.ident->name);
                val->data.identityref_val = (char *)str;
                if (!dup) {
                    (*val_buf) = (char *)str;
                }
            }
            break;
        case LY_TYPE_INST:
            val->type = SR_INSTANCEID_T;
            val->data.instanceid_val = dup ? strdup(leaf->value_str) : (char*)leaf->value_str;
            break;
        case LY_TYPE_STRING:
            val->type = SR_STRING_T;
            str = leaf->value.string;
            val->data.string_val = (dup && str) ? strdup(str) : (char*)str;
            if (NULL == val->data.string_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_INT8:
            val->type = SR_INT8_T;
            val->data.int8_val = leaf->value.int8;
            break;
        case LY_TYPE_UINT8:
            val->type = SR_UINT8_T;
            val->data.uint8_val = leaf->value.uint8;
            break;
        case LY_TYPE_INT16:
            val->type = SR_INT16_T;
            val->data.int16_val = leaf->value.int16;
            break;
        case LY_TYPE_UINT16:
            val->type = SR_UINT16_T;
            val->data.uint16_val = leaf->value.uint16;
            break;
        case LY_TYPE_INT32:
            val->type = SR_INT32_T;
            val->data.int32_val = leaf->value.int32;
            break;
        case LY_TYPE_UINT32:
            val->type = SR_UINT32_T;
            val->data.uint32_val = leaf->value.uint32;
            break;
        case LY_TYPE_INT64:
            val->type = SR_INT64_T;
            val->data.int64_val = leaf->value.int64;
            break;
        case LY_TYPE_UINT64:
            val->type = SR_UINT64_T;
            val->data.uint64_val = leaf->value.uint64;
            break;
        case LY_TYPE_LEAFREF:
            leaf = (struct lyd_node_leaf_list *)leaf->value.leafref;
            goto settype;
        default:
            //LY_DERIVED, LY_UNION
            val->type = SR_UNKNOWN_T;
            break;
        }
        break;
    default:
        val->type = SR_UNKNOWN_T;
        break;
    }

    return 0;
}

int
op_filter_get_tree_from_data(struct lyd_node **root, struct lyd_node *data, const char *subtree_path)
{
    struct ly_set *nodeset;
    struct lyd_node *node, *node2, *key, *key2, *child, *tmp_root;
    struct lys_node_list *slist;
    uint16_t i, j;

    nodeset = lyd_find_path(data, subtree_path);
    for (i = 0; i < nodeset->number; ++i) {
        node = nodeset->set.d[i];
        tmp_root = lyd_dup(node, 1);
        if (!tmp_root) {
            EMEM;
            return -1;
        }
        for (node = node->parent; node; node = node->parent) {
            node2 = lyd_dup(node, 0);
            if (!node2) {
                EMEM;
                return -1;
            }
            if (lyd_insert(node2, tmp_root)) {
                EINT;
                lyd_free(node2);
                return -1;
            }
            tmp_root = node2;

            /* we want to include all list keys in the result */
            if (node2->schema->nodetype == LYS_LIST) {
                slist = (struct lys_node_list *)node2->schema;
                for (j = 0, key = node->child; j < slist->keys_size; ++j, key = key->next) {
                    assert((struct lys_node *)slist->keys[j] == key->schema);

                    /* was the key already duplicated? */
                    LY_TREE_FOR(node2->child, child) {
                        if (child->schema == (struct lys_node *)slist->keys[j]) {
                            break;
                        }
                    }

                    /* it wasn't */
                    if (!child) {
                        key2 = lyd_dup(key, 0);
                        if (!key2) {
                            EMEM;
                            return -1;
                        }
                        if (lyd_insert(node2, key2)) {
                            EINT;
                            lyd_free(key2);
                            return -1;
                        }
                    }
                }

                /* we added those keys at the end, if some existed before the order is wrong */
                if (lyd_schema_sort(node2->child, 0)) {
                    EINT;
                    return -1;
                }
            }
        }

        if (*root) {
            if (lyd_merge(*root, tmp_root, LYD_OPT_DESTRUCT)) {
                EINT;
                return -1;
            }
        } else {
            *root = tmp_root;
        }
    }
    ly_set_free(nodeset);

    return 0;
}

static int
strws(const char *str)
{
    while (*str) {
        if (!isspace(*str)) {
            return 0;
        }
        ++str;
    }

    return 1;
}

int
op_filter_xpath_add_filter(char *new_filter, char ***filters, int *filter_count)
{
    char **filters_new;

    filters_new = realloc(*filters, (*filter_count + 1) * sizeof **filters);
    if (!filters_new) {
        EMEM;
        return -1;
    }
    ++(*filter_count);
    *filters = filters_new;
    (*filters)[*filter_count - 1] = new_filter;

    return 0;
}

static int
filter_xpath_buf_add_attrs(struct ly_ctx *ctx, struct lyxml_attr *attr, char **buf, int size)
{
    const struct lys_module *module;
    struct lyxml_attr *next;
    int new_size;
    char *buf_new;

    LY_TREE_FOR(attr, next) {
        if (next->type == LYXML_ATTR_STD) {
            module = NULL;
            if (next->ns) {
                module = ly_ctx_get_module_by_ns(ctx, next->ns->value, NULL, 1);
            }
            if (!module) {
                /* attribute without namespace or with unknown one will not match anything anyway */
                continue;
            }

            new_size = size + 2 + strlen(module->name) + 1 + strlen(next->name) + 2 + strlen(next->value) + 2;
            buf_new = realloc(*buf, new_size * sizeof(char));
            if (!buf_new) {
                EMEM;
                return -1;
            }
            *buf = buf_new;
            sprintf((*buf) + (size - 1), "[@%s:%s='%s']", module->name, next->name, next->value);
            size = new_size;
        }
    }

    return size;
}

/* top-level content node with optional namespace and attributes */
static int
filter_xpath_buf_add_top_content(struct ly_ctx *ctx, struct lyxml_elem *elem, const char *elem_module_name,
                                char ***filters, int *filter_count)
{
    int size, len;
    const char *start;
    char *buf;

    /* skip leading and trailing whitespaces */
    for (start = elem->content; isspace(*start); ++start);
    for (len = strlen(start); isspace(start[len - 1]); --len);

    size = 1 + strlen(elem_module_name) + 1 + strlen(elem->name) + 9 + len + 3;
    buf = malloc(size * sizeof(char));
    if (!buf) {
        EMEM;
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%.*s']", elem_module_name, elem->name, len, start);

    size = filter_xpath_buf_add_attrs(ctx, elem->attr, &buf, size);
    if (!size) {
        free(buf);
        return 0;
    } else if (size < 1) {
        free(buf);
        return -1;
    }

    if (op_filter_xpath_add_filter(buf, filters, filter_count)) {
        free(buf);
        return -1;
    }

    return 0;
}

/* content node with optional namespace and attributes */
static int
filter_xpath_buf_add_content(struct ly_ctx *ctx, struct lyxml_elem *elem, const char *elem_module_name,
                            const char **last_ns, char **buf, int size)
{
    const struct lys_module *module;
    int new_size, len;
    const char *start;
    char *buf_new;

    if (!elem_module_name && elem->ns && (elem->ns->value != *last_ns)
            && strcmp(elem->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL, 1);
        if (!module) {
            /* not really an error */
            return 0;
        }

        *last_ns = elem->ns->value;
        elem_module_name = module->name;
    }

    new_size = size + 1 + (elem_module_name ? strlen(elem_module_name) + 1 : 0) + strlen(elem->name);
    buf_new = realloc(*buf, new_size * sizeof(char));
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "[%s%s%s", (elem_module_name ? elem_module_name : ""), (elem_module_name ? ":" : ""),
            elem->name);
    size = new_size;

    size = filter_xpath_buf_add_attrs(ctx, elem->attr, buf, size);
    if (!size) {
        return 0;
    } else if (size < 1) {
        return -1;
    }

    /* skip leading and trailing whitespaces */
    for (start = elem->content; isspace(*start); ++start);
    for (len = strlen(start); isspace(start[len - 1]); --len);

    new_size = size + 2 + len + 2;
    buf_new = realloc(*buf, new_size * sizeof(char));
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "='%.*s']", len, start);

    return new_size;
}

/* containment/selection node with optional namespace and attributes */
static int
filter_xpath_buf_add_node(struct ly_ctx *ctx, struct lyxml_elem *elem, const char *elem_module_name,
                         const char **last_ns, char **buf, int size)
{
    const struct lys_module *module;
    int new_size;
    char *buf_new;

    if (!elem_module_name && elem->ns && (elem->ns->value != *last_ns)
            && strcmp(elem->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL, 1);
        if (!module) {
            /* not really an error */
            return 0;
        }

        *last_ns = elem->ns->value;
        elem_module_name = module->name;
    }

    new_size = size + 1 + (elem_module_name ? strlen(elem_module_name) + 1 : 0) + strlen(elem->name);
    buf_new = realloc(*buf, new_size * sizeof(char));
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "/%s%s%s", (elem_module_name ? elem_module_name : ""), (elem_module_name ? ":" : ""),
            elem->name);
    size = new_size;

    size = filter_xpath_buf_add_attrs(ctx, elem->attr, buf, size);

    return size;
}

/* buf is spent in the function, removes content match nodes from elem->child list! */
static int
filter_xpath_buf_add(struct ly_ctx *ctx, struct lyxml_elem *elem, const char *elem_module_name, const char *last_ns,
                    char **buf, int size, char ***filters, int *filter_count)
{
    struct lyxml_elem *temp, *child;
    int new_size;
    char *buf_new;
    int only_content_match_node = 1;

    /* containment node, selection node */
    size = filter_xpath_buf_add_node(ctx, elem, elem_module_name, &last_ns, buf, size);
    if (!size) {
        free(*buf);
        *buf = NULL;
        return 0;
    } else if (size < 1) {
        goto error;
    }

    /* content match node */
    LY_TREE_FOR_SAFE(elem->child, temp, child) {
        if (!child->child && child->content && !strws(child->content)) {
            size = filter_xpath_buf_add_content(ctx, child, elem_module_name, &last_ns, buf, size);
            if (!size) {
                free(*buf);
                *buf = NULL;
                return 0;
            } else if (size < 1) {
                goto error;
            }
        } else {
            only_content_match_node = 0;
        }
    }

    /* that is it, it seems */
    if (only_content_match_node) {
        if (op_filter_xpath_add_filter(*buf, filters, filter_count)) {
            goto error;
        }
        *buf = NULL;
        return 0;
    }

    /* that is it for this filter depth, now we branch with every new node except last */
    LY_TREE_FOR(elem->child, child) {
        if (!child->next) {
            buf_new = *buf;
            *buf = NULL;
        } else {
            buf_new = malloc(size * sizeof(char));
            if (!buf_new) {
                EMEM;
                goto error;
            }
            memcpy(buf_new, *buf, size * sizeof(char));
        }
        new_size = size;

        /* child containment node */
        if (child->child) {
            filter_xpath_buf_add(ctx, child, NULL, last_ns, &buf_new, new_size, filters, filter_count);

        /* child selection node or content match node */
        } else {
            new_size = filter_xpath_buf_add_node(ctx, child, NULL, &last_ns, &buf_new, new_size);
            if (!new_size) {
                free(buf_new);
                continue;
            } else if (new_size < 1) {
                free(buf_new);
                goto error;
            }

            if (op_filter_xpath_add_filter(buf_new, filters, filter_count)) {
                goto error;
            }
        }
    }

    return 0;

error:
    free(*buf);
    return -1;
}

/* modifies elem XML tree! */
static int
op_filter_build_xpath_from_subtree(struct ly_ctx *ctx, struct lyxml_elem *elem, char ***filters, int *filter_count)
{
    const struct lys_module *module, **modules, **modules_new;
    const struct lys_node *node;
    struct lyxml_elem *next;
    char *buf;
    uint32_t i, module_count;

    LY_TREE_FOR(elem, next) {
        /* first filter node, it must always have a namespace */
        modules = NULL;
        module_count = 0;
        if (next->ns && strcmp(next->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
            modules = malloc(sizeof *modules);
            if (!modules) {
                EMEM;
                goto error;
            }
            module_count = 1;
            modules[0] = ly_ctx_get_module_by_ns(ctx, next->ns->value, NULL, 1);
            if (!modules[0]) {
                /* not really an error */
                free(modules);
                continue;
            }
        } else {
            i = 0;
            while ((module = ly_ctx_get_module_iter(ctx, &i))) {
                node = NULL;
                while ((node = lys_getnext(node, NULL, module, 0))) {
                    if (!strcmp(node->name, next->name)) {
                        modules_new = realloc(modules, (module_count + 1) * sizeof *modules);
                        if (!modules_new) {
                            EMEM;
                            goto error;
                        }
                        ++module_count;
                        modules = modules_new;
                        modules[module_count - 1] = module;
                        break;
                    }
                }
            }
        }

        buf = NULL;
        for (i = 0; i < module_count; ++i) {
            if (!next->child && next->content && !strws(next->content)) {
                /* special case of top-level content match node */
                if (filter_xpath_buf_add_top_content(ctx, next, modules[i]->name, filters, filter_count)) {
                    goto error;
                }
            } else {
                /* containment or selection node */
                if (filter_xpath_buf_add(ctx, next, modules[i]->name, modules[i]->ns, &buf, 1, filters, filter_count)) {
                    goto error;
                }
            }
        }
        free(modules);
    }

    return 0;

error:
    free(modules);
    for (i = 0; (signed)i < *filter_count; ++i) {
        free((*filters)[i]);
    }
    free(*filters);
    return -1;
}

int
op_filter_create(struct lyd_node *filter_node, char ***filters, int *filter_count)
{
    struct lyd_attr *attr;
    struct lyxml_elem *subtree_filter;
    int free_filter, ret;
    char *path;

    LY_TREE_FOR(filter_node->attr, attr) {
        if (!strcmp(attr->name, "type")) {
            if (!strcmp(attr->value_str, "xpath")) {
                LY_TREE_FOR(filter_node->attr, attr) {
                    if (!strcmp(attr->name, "select")) {
                        break;
                    }
                }
                if (!attr) {
                    ERR("RPC with an XPath filter without the \"select\" attribute.");
                    return -1;
                }
                break;
            } else if (!strcmp(attr->value_str, "subtree")) {
                attr = NULL;
                break;
            }
        }
    }

    if (!attr) {
        /* subtree */
        if (!((struct lyd_node_anydata *)filter_node)->value.str
                || (((struct lyd_node_anydata *)filter_node)->value_type <= LYD_ANYDATA_STRING &&
                    !((struct lyd_node_anydata *)filter_node)->value.str[0])) {
            /* empty filter, fair enough */
            return 0;
        }

        switch (((struct lyd_node_anydata *)filter_node)->value_type) {
        case LYD_ANYDATA_CONSTSTRING:
        case LYD_ANYDATA_STRING:
            subtree_filter = lyxml_parse_mem(np2srv.ly_ctx, ((struct lyd_node_anydata *)filter_node)->value.str, LYXML_PARSE_MULTIROOT);
            free_filter = 1;
            break;
        case LYD_ANYDATA_XML:
            subtree_filter = ((struct lyd_node_anydata *)filter_node)->value.xml;
            free_filter = 0;
            break;
        default:
            /* filter cannot be parsed as lyd_node tree */
            return -1;
        }
        if (!subtree_filter) {
            return -1;
        }

        ret = op_filter_build_xpath_from_subtree(np2srv.ly_ctx, subtree_filter, filters, filter_count);
        if (free_filter) {
            lyxml_free(np2srv.ly_ctx, subtree_filter);
        }
        if (ret) {
            return -1;
        }
    } else {
        /* xpath */
        if (!attr->value_str || !attr->value_str[0]) {
            /* empty select, okay, I guess... */
            return 0;
        }
        path = strdup(attr->value_str);
        if (!path) {
            EMEM;
            return -1;
        }
        if (op_filter_xpath_add_filter(path, filters, filter_count)) {
            free(path);
            return -1;
        }
    }

    return 0;
}

int
op_sr_val_to_lyd_node(struct lyd_node *root, const sr_val_t *sr_val, struct lyd_node **new_node)
{
    char numstr[22];
    char *str;

    str = op_get_srval(np2srv.ly_ctx, sr_val, numstr);
    if (!str) {
        str = "";
    }

    ly_errno = LY_SUCCESS;

    *new_node = lyd_new_path(root, np2srv.ly_ctx, sr_val->xpath, str,
            (sr_val->type == SR_ANYXML_T || sr_val->type == SR_ANYDATA_T) ? LYD_ANYDATA_SXML : 0,
            LYD_PATH_OPT_UPDATE | (sr_val->dflt ? LYD_PATH_OPT_DFLT : 0));
    if (ly_errno) {
        return -1;
    }

    return 0;
}
