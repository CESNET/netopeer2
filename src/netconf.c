/**
 * @file netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "netconf.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/netconf_acm.h>
#include <sysrepo/subscribed_notifications.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "netconf_confirmed_commit.h"
#include "netconf_monitoring.h"

/**
 * @brief Get data for a get RPC.
 *
 * @param[in] session User SR session.
 * @param[in] xp_filter XPath filter to use.
 * @param[out] data Retrieved data.
 * @return Error reply on error, NULL on success.
 */
static struct nc_server_reply *
np_get_rpc_data(sr_session_ctx_t *session, const char *xp_filter, struct lyd_node **data)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node *node, *base_data = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    *data = NULL;

    if (!xp_filter) {
        /* empty filter matches no data */
        goto cleanup;
    }

    /* get base data from running */
    sr_session_switch_ds(session, SR_DS_RUNNING);
    if ((reply = np_op_filter_data_get(session, 0, SR_GET_NO_FILTER, xp_filter, &base_data))) {
        goto cleanup;
    }

    /* then append base operational data */
    sr_session_switch_ds(session, SR_DS_OPERATIONAL);
    if ((reply = np_op_filter_data_get(session, 0, SR_OPER_NO_CONFIG | SR_GET_NO_FILTER, xp_filter, &base_data))) {
        goto cleanup;
    }

    if (!strcmp(xp_filter, "/*") || !base_data) {
        /* no filter, use all the data, or no data at all */
        *data = base_data;
        base_data = NULL;
        goto cleanup;
    }

    /* now filter only the requested data from the created running data + state data */
    if (lyd_find_xpath3(NULL, base_data, xp_filter, LY_VALUE_JSON, NULL, NULL, &set)) {
        reply = np_reply_err_op_failed(session, NULL, ly_last_logmsg());
        goto cleanup;
    }

    for (i = 0; i < set->count; ++i) {
        if (lyd_dup_single(set->dnodes[i], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &node)) {
            reply = np_reply_err_op_failed(session, NULL, ly_last_logmsg());
            goto cleanup;
        }

        /* always find parent */
        while (node->parent) {
            node = lyd_parent(node);
        }

        /* merge */
        if (lyd_merge_tree(data, node, LYD_MERGE_DESTRUCT)) {
            lyd_free_tree(node);
            reply = np_reply_err_op_failed(session, NULL, ly_last_logmsg());
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(base_data);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_get_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node *node, *data_get = NULL, *output = NULL;
    struct lyd_meta *meta;
    struct ly_set *nodeset = NULL;
    sr_datastore_t ds = 0;
    char *xp_filter = NULL;

    /* learn which datastore is being affected for get-config */
    if (!strcmp(LYD_NAME(rpc), "get-config")) {
        lyd_find_xpath(rpc, "source/*", &nodeset);
        if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
            ds = SR_DS_CANDIDATE;
        }

        ly_set_free(nodeset, NULL);
    }

    /* create filters */
    if (!lyd_find_path(rpc, "filter", 0, &node)) {
        /* learn filter type */
        meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:type");
        if (meta && !strcmp(lyd_get_meta_value(meta), "xpath")) {
            meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:select");
            if (!meta) {
                node = nc_err(LYD_CTX(rpc), NC_ERR_MISSING_ATTR, NC_ERR_TYPE_PROT, "select", "filter");
                reply = nc_server_reply_err(node);
                goto cleanup;
            }
        } else {
            meta = NULL;
        }

        if (!meta) {
            /* subtree */
            if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
                if (((struct lyd_node_any *)node)->value.tree) {
                    if (srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter)) {
                        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                        goto cleanup;
                    }
                }
            } else {
                ERR("Invalid subtree filter:\n  %s", ((struct lyd_node_any *)node)->value.str);
                goto cleanup;
            }
        } else {
            /* xpath */
            xp_filter = strdup(lyd_get_meta_value(meta));
        }
    } else {
        xp_filter = strdup("/*");
    }

    /* we do not care here about with-defaults mode, it does not change anything */

    /* get filtered data */
    if (!strcmp(LYD_NAME(rpc), "get-config")) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* create the data tree for the data reply */
        if ((reply = np_op_filter_data_get(user_sess->sess, 0, 0, xp_filter, &data_get))) {
            goto cleanup;
        }
    } else {
        /* get properly merged data */
        if ((reply = np_get_rpc_data(user_sess->sess, xp_filter, &data_get))) {
            goto cleanup;
        }
    }

    /* generate output */
    if (lyd_dup_single(rpc, NULL, LYD_DUP_WITH_PARENTS, &output)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    if (lyd_new_any(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, NULL)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    data_get = NULL;
    reply = np_reply_success(rpc, output);
    output = NULL;

cleanup:
    free(xp_filter);
    lyd_free_siblings(data_get);
    lyd_free_siblings(output);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_editconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct lyd_node *node, *config = NULL;
    const char *defop = "merge", *testop = "test-then-set";

    /* get know which datastore is being affected */
    lyd_find_xpath(rpc, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    /* default-operation */
    if (!lyd_find_path(rpc, "default-operation", 0, &node)) {
        defop = lyd_get_value(node);
    }

    /* test-option */
    if (!lyd_find_path(rpc, "test-option", 0, &node)) {
        testop = lyd_get_value(node);
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }

    /* error-option */
    if (!lyd_find_path(rpc, "error-option", 0, &node)) {
        if (strcmp(lyd_get_value(node), "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", lyd_get_value(node));
        }
    }

    /* config */
    lyd_find_xpath(rpc, "config | url", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        reply = np_op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_ONLY | LYD_PARSE_OPAQ |
                LYD_PARSE_NO_STATE, &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        reply = np_op_parse_url(LYD_CTX(rpc), lyd_get_value(nodeset->dnodes[0]), 0, &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (config && sr_edit_batch(user_sess->sess, config, defop)) {
        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
        goto cleanup;
    }

    if (!strcmp(testop, "test-then-set")) {
        if (sr_apply_changes(user_sess->sess, np2srv.sr_timeout)) {
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    } else {
        assert(!strcmp(testop, "test-only"));
        if (sr_validate(user_sess->sess, NULL, 0)) {
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    /* discard any changes that possibly failed to be applied */
    sr_discard_changes(user_sess->sess);

    lyd_free_siblings(config);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_copyconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds = SR_DS_OPERATIONAL, sds = SR_DS_OPERATIONAL;
    struct ly_set *nodeset = NULL;
    struct lyd_node *config = NULL;
    sr_data_t *sr_data;
    int run_to_start = 0, source_is_config = 0;

#ifdef NP2SRV_URL_CAPAB
    const char *trg_url = NULL;
    int lyp_wd_flag;
    uint8_t url = 0;
#endif

    /* get know which datastores are affected */
    lyd_find_xpath(rpc, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = lyd_get_value(nodeset->dnodes[0]);
        url++;
#else
        ly_set_free(nodeset, NULL);
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    lyd_find_xpath(rpc, "source/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        sds = SR_DS_RUNNING;
        if (ds == SR_DS_STARTUP) {
            /* special copy-config from running to startup that bypasses NACM */
            run_to_start = 1;
        }
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        sds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        sds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        reply = np_op_parse_config((struct lyd_node_any *)nodeset->dnodes[0],
                LYD_PARSE_STRICT | LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
        source_is_config = 1;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        url++;
        if (trg_url && !strcmp(trg_url, lyd_get_value(nodeset->dnodes[0]))) {
            reply = np_reply_err_invalid_val(LYD_CTX(rpc), "Source and target URLs are the same.", NULL);
            goto cleanup;
        }

        reply = np_op_parse_url(LYD_CTX(rpc), lyd_get_value(nodeset->dnodes[0]), 0, &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
        source_is_config = 1;
#else
        ly_set_free(nodeset, NULL);
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* if both are url it is a valid call */
#ifdef NP2SRV_URL_CAPAB
    if ((ds == sds) && (url != 2))
#else
    if (ds == sds)
#endif
    {
        reply = np_reply_err_invalid_val(LYD_CTX(rpc), "Source and target datastores are the same.", NULL);
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        struct lyd_node *node;

        if (!source_is_config) {
            /* get source datastore data */
            sr_session_switch_ds(user_sess->sess, sds);
            if (sr_get_data(user_sess->sess, "/*", 0, np2srv.sr_timeout, 0, &sr_data)) {
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                goto cleanup;
            }
            config = sr_data->tree;
            sr_data->tree = NULL;
            sr_release_data(sr_data);
        }

        /* we need with-defaults flag in this case */
        lyp_wd_flag = 0;
        if (!lyd_find_path(rpc, "ietf-netconf-with-defaults:with-defaults", 0, &node)) {
            if (!strcmp(lyd_get_value(node), "report-all")) {
                lyp_wd_flag = LYD_PRINT_WD_ALL;
            } else if (!strcmp(lyd_get_value(node), "report-all-tagged")) {
                lyp_wd_flag = LYD_PRINT_WD_ALL_TAG;
            } else if (!strcmp(lyd_get_value(node), "trim")) {
                lyp_wd_flag = LYD_PRINT_WD_TRIM;
            } else {
                assert(!strcmp(lyd_get_value(node), "explicit"));
                lyp_wd_flag = LYD_PRINT_WD_EXPLICIT;
            }
        }

        if ((reply = np_op_export_url(LYD_CTX(rpc), trg_url, config, LYD_PRINT_SIBLINGS | lyp_wd_flag))) {
            goto cleanup;
        }
    } else
#endif
    {
        if (source_is_config) {
            /* config is spent */
            if (sr_replace_config(user_sess->sess, NULL, config, np2srv.sr_timeout)) {
                config = NULL;
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                goto cleanup;
            }
            config = NULL;
        } else {
            if (run_to_start) {
                /* skip NACM check */
                sr_nacm_set_user(user_sess->sess, NULL);
            }

            if (sr_copy_config(user_sess->sess, NULL, sds, np2srv.sr_timeout)) {
                /* prevent the error info being overwritten */
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            }

            /* set NACM username back */
            sr_nacm_set_user(user_sess->sess, nc_session_get_username(user_sess->ntf_arg.nc_sess));

            if (reply) {
                goto cleanup;
            }
        }
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    lyd_free_siblings(config);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_deleteconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;

#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    /* get know which datastore is affected */
    lyd_find_xpath(rpc, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = lyd_get_value(nodeset->dnodes[0]);
#else
        ly_set_free(nodeset, NULL);
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        reply = np_op_parse_url(LYD_CTX(rpc), trg_url, 0, &config);
        if (reply) {
            goto cleanup;
        }
        lyd_free_siblings(config);

        /* upload empty config */
        reply = np_op_export_url(LYD_CTX(rpc), trg_url, NULL, 0);
        if (reply) {
            goto cleanup;
        }
    } else
#endif
    {
        if (sr_replace_config(user_sess->sess, NULL, NULL, np2srv.sr_timeout)) {
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_un_lock_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct nc_session *nc_sess, *ncc_sess;
    int r;

    /* get know which datastore is being affected */
    lyd_find_xpath(rpc, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    nc_sess = user_sess->ntf_arg.nc_sess;
    if ((ds == SR_DS_RUNNING) && !strcmp(rpc->schema->name, "lock") && ncc_ongoing_confirmed_commit(&ncc_sess) &&
            (!ncc_sess || (ncc_sess != nc_sess))) {
        /* RFC 6241 sec. 7.5. */
        if (nc_sess) {
            reply = np_reply_err_lock_denied(LYD_CTX(rpc), "There is an ongoing confirmed commit.",
                    nc_session_get_id(nc_sess));
        } else {
            reply = np_reply_err_lock_denied(LYD_CTX(rpc), "There is an ongoing persistent confirmed commit.", 0);
        }
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (!strcmp(rpc->schema->name, "lock")) {
        r = sr_lock(user_sess->sess, NULL, NP2SRV_DS_LOCK_TIMEOUT);
    } else {
        assert(!strcmp(rpc->schema->name, "unlock"));
        r = sr_unlock(user_sess->sess, NULL);
    }
    if (r) {
        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_kill_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    struct nc_session *kill_sess;
    struct lyd_node *node;
    uint32_t kill_sid, nc_sid, i;

    lyd_find_path(rpc, "session-id", 0, &node);
    kill_sid = ((struct lyd_node_term *)node)->value.uint32;

    nc_sid = nc_session_get_id(user_sess->ntf_arg.nc_sess);
    if (kill_sid == nc_sid) {
        reply = np_reply_err_invalid_val(LYD_CTX(rpc), "It is forbidden to kill own session.", NULL);
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        reply = np_reply_err_invalid_val(LYD_CTX(rpc), "Session with the specified \"session-id\" not found.", NULL);
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, kill_sid);

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_discard_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, SR_DS_CANDIDATE);

    /* sysrepo API */
    if (sr_copy_config(user_sess->sess, NULL, SR_DS_RUNNING, np2srv.sr_timeout)) {
        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_validate_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds = 0;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset = NULL;

    /* learn which datastore is affected */
    lyd_find_xpath(rpc, "source/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        reply = np_op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_STRICT | LYD_PARSE_NO_STATE,
                &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        reply = np_op_parse_url(LYD_CTX(rpc), lyd_get_value(nodeset->dnodes[0]), 1, &config);
        if (reply) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    if (!config) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* sysrepo API */
        if (sr_validate(user_sess->sess, NULL, 0)) {
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    } /* else already validated */

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    lyd_free_siblings(config);
    return reply;
}

/**
 * @brief New notification callback used for notifications received on subscription made by \<create-subscription\> RPC.
 */
static void
np2srv_rpc_subscribe_ntf_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const sr_ev_notif_type_t notif_type,
        const struct lyd_node *notif, struct timespec *timestamp, void *private_data)
{
    struct np_ntf_arg *arg = private_data;
    struct lyd_node *ly_ntf;
    const struct ly_ctx *ly_ctx;
    uint32_t i;

    if (notif) {
        /* find the top-level node */
        while (notif->parent) {
            notif = lyd_parent(notif);
        }
    }

    switch (notif_type) {
    case SR_EV_NOTIF_REPLAY_COMPLETE:
        if (ATOMIC_INC_RELAXED(arg->sr_ntf_replay_complete_count) + 1 < arg->sr_sub_count) {
            /* ignore, wait for the last SR subscription */
            break;
        }

        /* context lock is held while the callback is executing */
        ly_ctx = sr_acquire_context(np2srv.sr_conn);
        sr_release_context(np2srv.sr_conn);

        if (lyd_new_path(NULL, ly_ctx, "/nc-notifications:replayComplete", NULL, 0, &ly_ntf)) {
            return;
        }
        np_ntf_send(arg->nc_sess, timestamp, &ly_ntf, 1);

        /* now send all the buffered notifications */
        for (i = 0; i < arg->rt_notif_count; ++i) {
            np_ntf_send(arg->nc_sess, &arg->rt_notifs[i].timestamp, &arg->rt_notifs[i].notif, 1);
        }
        break;
    case SR_EV_NOTIF_STOP_TIME:
        if (ATOMIC_INC_RELAXED(arg->sr_ntf_stop_count) + 1 < arg->sr_sub_count) {
            /* ignore, wait for the last SR subscription */
            break;
        }

        /* context lock is held while the callback is executing */
        ly_ctx = sr_acquire_context(np2srv.sr_conn);
        sr_release_context(np2srv.sr_conn);

        if (lyd_new_path(NULL, ly_ctx, "/nc-notifications:notificationComplete", NULL, 0, &ly_ntf)) {
            return;
        }
        np_ntf_send(arg->nc_sess, timestamp, &ly_ntf, 1);

        /* subscription finished */
        nc_session_dec_notif_status(arg->nc_sess);
        break;
    case SR_EV_NOTIF_REALTIME:
        if (ATOMIC_LOAD_RELAXED(arg->sr_ntf_replay_complete_count) < arg->sr_sub_count) {
            /* realtime notification received before replay has been completed, store in buffer */
            np_ntf_add_dup(notif, timestamp, &arg->rt_notifs, &arg->rt_notif_count);
        } else {
            /* send the realtime notification */
            np_ntf_send(arg->nc_sess, timestamp, (struct lyd_node **)&notif, 0);
        }
        break;
    case SR_EV_NOTIF_REPLAY:
        /* send the replayed notification */
        np_ntf_send(arg->nc_sess, timestamp, (struct lyd_node **)&notif, 0);
        break;
    case SR_EV_NOTIF_MODIFIED:
    case SR_EV_NOTIF_SUSPENDED:
    case SR_EV_NOTIF_RESUMED:
    case SR_EV_NOTIF_TERMINATED:
        /* ignore */
        break;
    }
}

struct nc_server_reply *
np2srv_rpc_subscribe_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *node;
    struct lyd_meta *meta;
    struct nc_session *ncs;
    const char *stream;
    char *xp_filter = NULL;
    struct timespec start = {0}, stop = {0}, cur_ts;
    uint32_t idx;
    struct ly_set *mod_set = NULL;

    ncs = user_sess->ntf_arg.nc_sess;

    /* RFC 5277 section 6.5 */
    if (nc_session_get_notif_status(ncs)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Session already subscribed.");
        goto cleanup;
    }

    /* learn stream */
    lyd_find_path(rpc, "stream", 0, &node);
    stream = lyd_get_value(node);

    /* filter */
    if (!lyd_find_path(rpc, "filter", 0, &node)) {
        /* learn filter type */
        meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:type");
        if (meta && !strcmp(lyd_get_meta_value(meta), "xpath")) {
            meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:select");
            if (!meta) {
                reply = np_reply_err_missing_attr(LYD_CTX(rpc), "An expected attribute is missing.", "select", "filter");
                goto cleanup;
            }
        } else {
            meta = NULL;
        }

        if (!meta) {
            /* subtree */
            if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
                if (srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter)) {
                    reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                    goto cleanup;
                }
            }
        } else {
            /* xpath */
            if (strlen(lyd_get_meta_value(meta))) {
                xp_filter = strdup(lyd_get_meta_value(meta));
                if (!xp_filter) {
                    EMEM;
                    reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Memory allocation failed.");
                    goto cleanup;
                }
            }
        }
    }

    /* start time */
    if (!lyd_find_path(rpc, "startTime", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &start);
    }

    /* stop time */
    if (!lyd_find_path(rpc, "stopTime", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* check parameters */
    cur_ts = np_gettimespec(1);
    if (start.tv_sec && (np_difftimespec(&start, &cur_ts) < 0)) {
        reply = np_reply_err_bad_elem(LYD_CTX(rpc), "Specified \"startTime\" is in future.", "startTime");
        goto cleanup;
    } else if (stop.tv_sec && !start.tv_sec) {
        reply = np_reply_err_missing_elem(LYD_CTX(rpc), "An expected element is missing.", "startTime");
        goto cleanup;
    } else if (start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &start) > 0)) {
        reply = np_reply_err_bad_elem(LYD_CTX(rpc), "Specified \"stopTime\" is earlier than \"startTime\".",
                "stopTime");
        goto cleanup;
    }

    /* collect modules */
    if (srsn_stream_collect_mods(stream, xp_filter, LYD_CTX(rpc), &mod_set)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to collect modules to subscribe to.");
        goto cleanup;
    }

    /* set ongoing notifications flag */
    nc_session_inc_notif_status(ncs);

    /* subscribe to the modules */
    user_sess->ntf_arg.sr_sub_count = mod_set->count;
    user_sess->ntf_arg.sr_ntf_replay_complete_count = start.tv_sec ? 0 : user_sess->ntf_arg.sr_sub_count;
    for (idx = 0; idx < mod_set->count; ++idx) {
        ly_mod = mod_set->objs[idx];
        if (sr_notif_subscribe_tree(user_sess->sess, ly_mod->name, xp_filter, start.tv_sec ? &start : NULL,
                stop.tv_sec ? &stop : NULL, np2srv_rpc_subscribe_ntf_cb, &user_sess->ntf_arg, 0, &np2srv.sr_notif_sub)) {
            nc_session_dec_notif_status(ncs);
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    ly_set_free(mod_set, NULL);
    free(xp_filter);
    return reply;
}

int
np2srv_nc_ntf_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    char *buf;
    uint32_t idx = 0;
    int enabled;
    struct timespec earliest_notif;

    /* context is locked by the callback anyway */
    ly_ctx = sr_session_acquire_context(session);
    sr_session_release_context(session);

    if (lyd_new_path(NULL, ly_ctx, "/nc-notifications:netconf/streams", NULL, 0, &root)) {
        goto error;
    }

    /* generic stream */
    if (lyd_new_path(root, NULL, "/nc-notifications:netconf/streams/stream[name='NETCONF']", NULL, 0, &stream)) {
        goto error;
    }
    if (lyd_new_term(stream, stream->schema->module, "description",
            "Default NETCONF stream containing notifications from all the modules."
            " Replays only notifications for modules (streams) that support replay.", 0, NULL)) {
        goto error;
    }
    if (lyd_new_term(stream, stream->schema->module, "replaySupport", "true", 0, NULL)) {
        goto error;
    }

    /* go through all the modules */
    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!ly_mod->implemented || !np_ly_mod_has_notif(ly_mod)) {
            /* not implemented or no notifications in the module so do not consider it a stream */
            continue;
        }

        /* generate information about the stream/module */
        if (lyd_new_list(lyd_child(root), NULL, "stream", 0, &stream, ly_mod->name)) {
            goto error;
        }
        if (lyd_new_term(stream, NULL, "description", "Stream with all the notifications of a module.", 0, NULL)) {
            goto error;
        }

        /* learn whether replay is supported */
        if (sr_get_module_replay_support(sr_session_get_connection(session), ly_mod->name, &earliest_notif, &enabled)) {
            goto error;
        }
        if (lyd_new_term(stream, NULL, "replaySupport", enabled ? "true" : "false", 0, NULL)) {
            goto error;
        }
        if (enabled) {
            ly_time_ts2str(&earliest_notif, &buf);
            if (lyd_new_term(stream, NULL, "replayLogCreationTime", buf, 0, NULL)) {
                free(buf);
                goto error;
            }
            free(buf);
        }
    }

    *parent = root;
    return SR_ERR_OK;

error:
    lyd_free_tree(root);
    return SR_ERR_INTERNAL;
}
