/**
 * @file netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
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
#include "err_netconf.h"
#include "log.h"
#include "netconf_confirmed_commit.h"
#include "netconf_monitoring.h"

/**
 * @brief Get data for a get RPC.
 *
 * @param[in] session User SR session.
 * @param[in] xp_filter XPath filter to use.
 * @param[in,out] ev_sess Event SR session to use for errors.
 * @param[out] data Retrieved data.
 * @return SR error value.
 */
static int
np2srv_get_rpc_data(sr_session_ctx_t *session, const char *xp_filter, sr_session_ctx_t *ev_sess,
        struct lyd_node **data)
{
    int rc = SR_ERR_OK;
    struct lyd_node *node, *base_data = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    *data = NULL;

    /* get base data from running */
    sr_session_switch_ds(session, SR_DS_RUNNING);
    if ((rc = op_filter_data_get(session, 0, SR_GET_NO_FILTER, xp_filter, ev_sess, &base_data))) {
        goto cleanup;
    }

    /* then append base operational data */
    sr_session_switch_ds(session, SR_DS_OPERATIONAL);
    if ((rc = op_filter_data_get(session, 0, SR_OPER_NO_CONFIG | SR_GET_NO_FILTER, xp_filter, ev_sess, &base_data))) {
        goto cleanup;
    }

    if (!strcmp(xp_filter, "/*")) {
        /* no filter, use all the data */
        *data = base_data;
        base_data = NULL;
        goto cleanup;
    }

    /* now filter only the requested data from the created running data + state data */
    if (lyd_find_xpath3(NULL, base_data, xp_filter, LY_VALUE_JSON, NULL, NULL, &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    for (i = 0; i < set->count; ++i) {
        if (lyd_dup_single(set->dnodes[i], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &node)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* always find parent */
        while (node->parent) {
            node = lyd_parent(node);
        }

        /* merge */
        if (lyd_merge_tree(data, node, LYD_MERGE_DESTRUCT)) {
            lyd_free_tree(node);
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(base_data);
    return rc;
}

int
np2srv_rpc_get_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct lyd_node *node, *data_get = NULL;
    struct lyd_meta *meta;
    struct np2_user_sess *user_sess = NULL;
    struct ly_set *nodeset = NULL;
    sr_datastore_t ds = 0;
    char *xp_filter = NULL;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* get know which datastore is being affected for get-config */
    if (!strcmp(op_path, "/ietf-netconf:get-config")) {
        lyd_find_xpath(input, "source/*", &nodeset);
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
    if (!lyd_find_path(input, "filter", 0, &node)) {
        /* learn filter type */
        meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:type");
        if (meta && !strcmp(lyd_get_meta_value(meta), "xpath")) {
            meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:select");
            if (!meta) {
                ERR("RPC with an XPath filter without the \"select\" attribute.");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        } else {
            meta = NULL;
        }

        if (!meta) {
            /* subtree */
            if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
                if ((rc = srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter))) {
                    sr_session_dup_error(user_sess->sess, session);
                    goto cleanup;
                }
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
    if (!strcmp(op_path, "/ietf-netconf:get-config")) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* create the data tree for the data reply */
        if ((rc = op_filter_data_get(user_sess->sess, 0, 0, xp_filter, session, &data_get))) {
            goto cleanup;
        }
    } else {
        /* get properly merged data */
        if ((rc = np2srv_get_rpc_data(user_sess->sess, xp_filter, session, &data_get))) {
            goto cleanup;
        }
    }

    /* add output */
    if (lyd_new_any(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, &node)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    data_get = NULL;

cleanup:
    free(xp_filter);
    lyd_free_siblings(data_get);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_editconfig_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct lyd_node *node, *config = NULL;
    struct np2_user_sess *user_sess = NULL;
    const char *defop = "merge", *testop = "test-then-set";
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastore is being affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    /* default-operation */
    if (!lyd_find_path(input, "default-operation", 0, &node)) {
        defop = lyd_get_value(node);
    }

    /* test-option */
    if (!lyd_find_path(input, "test-option", 0, &node)) {
        testop = lyd_get_value(node);
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }

    /* error-option */
    if (!lyd_find_path(input, "error-option", 0, &node)) {
        if (strcmp(lyd_get_value(node), "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", lyd_get_value(node));
        }
    }

    /* config */
    lyd_find_xpath(input, "config | url", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_ONLY | LYD_PARSE_OPAQ |
                LYD_PARSE_NO_STATE, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), 0, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (config) {
        rc = sr_edit_batch(user_sess->sess, config, defop);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    if (!strcmp(testop, "test-then-set")) {
        if ((rc = sr_apply_changes(user_sess->sess, np2srv.sr_timeout))) {
            /* specific edit-config error */
            np_err_sr2nc_edit(session, user_sess->sess);
            goto cleanup;
        }
    } else {
        assert(!strcmp(testop, "test-only"));
        if ((rc = sr_validate(user_sess->sess, NULL, 0))) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    }

cleanup:
    if (user_sess) {
        /* discard any changes that possibly failed to be applied */
        sr_discard_changes(user_sess->sess);
    }
    lyd_free_siblings(config);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_copyconfig_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = SR_DS_OPERATIONAL, sds = SR_DS_OPERATIONAL;
    struct ly_set *nodeset = NULL;
    struct lyd_node *config = NULL;
    sr_data_t *sr_data;
    int rc = SR_ERR_OK, run_to_start = 0, source_is_config = 0;
    struct np2_user_sess *user_sess = NULL;
    struct nc_session *nc_sess;

#ifdef NP2SRV_URL_CAPAB
    const char *trg_url = NULL;
    int lyp_wd_flag;
    uint8_t url = 0;
#endif

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastores are affected */
    lyd_find_xpath(input, "target/*", &nodeset);
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
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    lyd_find_xpath(input, "source/*", &nodeset);
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
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0],
                LYD_PARSE_STRICT | LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
        source_is_config = 1;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        url++;
        if (trg_url && !strcmp(trg_url, lyd_get_value(nodeset->dnodes[0]))) {
            rc = SR_ERR_INVAL_ARG;
            np_err_sr2nc_same_ds(session, "Source and target URLs are the same.");
            goto cleanup;
        }

        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), 0, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
        source_is_config = 1;
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
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
        rc = SR_ERR_INVAL_ARG;
        np_err_sr2nc_same_ds(session, "Source and target datastores are the same.");
        goto cleanup;
    }

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, &nc_sess, &user_sess))) {
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
            if ((rc = sr_get_data(user_sess->sess, "/*", 0, np2srv.sr_timeout, 0, &sr_data))) {
                sr_session_dup_error(user_sess->sess, session);
                goto cleanup;
            }
            config = sr_data->tree;
            sr_data->tree = NULL;
            sr_release_data(sr_data);
        }

        /* we need with-defaults flag in this case */
        lyp_wd_flag = 0;
        if (!lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults", 0, &node)) {
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

        if (op_export_url(trg_url, config, LYD_PRINT_WITHSIBLINGS | lyp_wd_flag, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        if (source_is_config) {
            /* config is spent */
            rc = sr_replace_config(user_sess->sess, NULL, config, np2srv.sr_timeout);
            config = NULL;
            if (rc) {
                sr_session_dup_error(user_sess->sess, session);
                goto cleanup;
            }
        } else {
            if (run_to_start) {
                /* skip NACM check */
                sr_nacm_set_user(user_sess->sess, NULL);
            }

            if ((rc = sr_copy_config(user_sess->sess, NULL, sds, np2srv.sr_timeout))) {
                /* prevent the error info being overwritten */
                sr_session_dup_error(user_sess->sess, session);
            }

            /* set NACM username back */
            sr_nacm_set_user(user_sess->sess, nc_session_get_username(nc_sess));

            if (rc) {
                goto cleanup;
            }
        }
    }

cleanup:
    lyd_free_siblings(config);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_deleteconfig_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess = NULL;

#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastore is affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = lyd_get_value(nodeset->dnodes[0]);
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        config = op_parse_url(trg_url, 0, &rc, session);
        if (rc) {
            goto cleanup;
        }
        lyd_free_siblings(config);

        /* upload empty config */
        if (op_export_url(trg_url, NULL, 0, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        rc = sr_replace_config(user_sess->sess, NULL, NULL, np2srv.sr_timeout);
        if (rc) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_un_lock_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    struct np2_user_sess *user_sess = NULL;
    struct nc_session *nc_sess, *ncc_sess;
    const sr_error_info_t *err_info;
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastore is being affected */
    lyd_find_xpath(input, "target/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, &nc_sess, &user_sess))) {
        goto cleanup;
    }

    if ((ds == SR_DS_RUNNING) && !strcmp(input->schema->name, "lock") && ncc_ongoing_confirmed_commit(&ncc_sess) &&
            (!ncc_sess || (ncc_sess != nc_sess))) {
        /* RFC 6241 sec. 7.5. */
        if (nc_sess) {
            np_err_lock_denied(session, "There is an ongoing confirmed commit.", nc_session_get_id(nc_sess));
        } else {
            np_err_lock_denied(session, "There is an ongoing persistent confirmed commit.", 0);
        }
        rc = SR_ERR_LOCKED;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (!strcmp(input->schema->name, "lock")) {
        rc = sr_lock(user_sess->sess, NULL, 0);
    } else if (!strcmp(input->schema->name, "unlock")) {
        rc = sr_unlock(user_sess->sess, NULL);
    }
    if (rc == SR_ERR_LOCKED) {
        /* NETCONF error */
        sr_session_get_error(user_sess->sess, &err_info);
        np_err_sr2nc_lock_denied(session, err_info);
        goto cleanup;
    } else if (rc) {
        /* generic error */
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

cleanup:
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_kill_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct nc_session *kill_sess;
    struct lyd_node *node;
    uint32_t kill_sid, *nc_sid, i;
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    lyd_find_path(input, "session-id", 0, &node);
    kill_sid = ((struct lyd_node_term *)node)->value.uint32;

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_sid);
    if (kill_sid == *nc_sid) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error(session, NULL, rc, "It is forbidden to kill own session.");
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error(session, NULL, rc, "Session with the specified \"session-id\" not found.");
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, kill_sid);

cleanup:
    return rc;
}

int
np2srv_rpc_discard_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *UNUSED(input), sr_event_t event, uint32_t UNUSED(request_id),
        struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess = NULL;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, SR_DS_CANDIDATE);

    /* sysrepo API */
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_RUNNING, np2srv.sr_timeout);
    if (rc != SR_ERR_OK) {
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

cleanup:
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_validate_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset = NULL;
    struct np2_user_sess *user_sess = NULL;
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastore is affected */
    lyd_find_xpath(input, "source/*", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_STRICT | LYD_PARSE_NO_STATE,
                &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), 1, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error(session, NULL, rc, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    if (!config) {
        /* get the user session */
        if ((rc = np_find_user_sess(session, __func__, NULL, &user_sess))) {
            goto cleanup;
        }

        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess->sess, ds);

        /* sysrepo API */
        rc = sr_validate(user_sess->sess, NULL, 0);
        if (rc != SR_ERR_OK) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    } /* else already validated */

cleanup:
    lyd_free_siblings(config);
    np_release_user_sess(user_sess);
    return rc;
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

        lyd_new_path(NULL, ly_ctx, "/nc-notifications:replayComplete", NULL, 0, &ly_ntf);
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

        lyd_new_path(NULL, ly_ctx, "/nc-notifications:notificationComplete", NULL, 0, &ly_ntf);
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

int
np2srv_rpc_subscribe_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    const struct lys_module *ly_mod;
    struct lyd_node *node;
    struct lyd_meta *meta;
    struct nc_session *ncs;
    struct np2_user_sess *user_sess = NULL;
    const char *stream;
    char *xp_filter = NULL;
    struct timespec start = {0}, stop = {0}, cur_ts;
    int rc = SR_ERR_OK, has_nc_ntf_status = 0;
    uint32_t idx;
    struct ly_set mod_set = {0};
    struct np_ntf_arg *ntf_arg;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get the NETCONF session and user session */
    if ((rc = np_find_user_sess(session, __func__, &ncs, &user_sess))) {
        goto cleanup;
    }

    /* RFC 5277 section 6.5 */
    if (nc_session_get_notif_status(ncs)) {
        rc = SR_ERR_EXISTS;
        sr_session_set_error(session, NULL, rc, "Session already subscribed.");
        goto cleanup;
    }

    /* learn stream */
    lyd_find_path(input, "stream", 0, &node);
    stream = lyd_get_value(node);

    /* filter */
    if (!lyd_find_path(input, "filter", 0, &node)) {
        /* learn filter type */
        meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:type");
        if (meta && !strcmp(lyd_get_meta_value(meta), "xpath")) {
            meta = lyd_find_meta(node->meta, NULL, "ietf-netconf:select");
            if (!meta) {
                ERR("RPC with an XPath filter without the \"select\" attribute.");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        } else {
            meta = NULL;
        }

        if (!meta) {
            /* subtree */
            if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
                if ((rc = srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter))) {
                    sr_session_dup_error(user_sess->sess, session);
                    goto cleanup;
                }
            }
        } else {
            /* xpath */
            if (strlen(lyd_get_meta_value(meta))) {
                xp_filter = strdup(lyd_get_meta_value(meta));
                if (!xp_filter) {
                    EMEM;
                    rc = SR_ERR_NO_MEMORY;
                    goto cleanup;
                }
            }
        }
    }

    /* start time */
    if (!lyd_find_path(input, "startTime", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &start);
    }

    /* stop time */
    if (!lyd_find_path(input, "stopTime", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* check parameters */
    cur_ts = np_gettimespec(1);
    if (start.tv_sec && (np_difftimespec(&start, &cur_ts) < 0)) {
        np_err_bad_element(session, "startTime", "Specified \"startTime\" is in future.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (stop.tv_sec && !start.tv_sec) {
        np_err_missing_element(session, "startTime");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &start) > 0)) {
        np_err_bad_element(session, "stopTime", "Specified \"stopTime\" is earlier than \"startTime\".");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* init notif CB data */
    ntf_arg = &user_sess->ntf_arg;
    ntf_arg->nc_sess = ncs;

    /* set ongoing notifications flag */
    nc_session_inc_notif_status(ncs);
    has_nc_ntf_status = 1;

    /* sysrepo API */
    if (!strcmp(stream, "NETCONF")) {
        /* find all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(LYD_CTX(input), &idx))) {
            if (!ly_mod->implemented) {
                continue;
            }

            if (np_ly_mod_has_notif(ly_mod)) {
                /* a notification was found */
                if (ly_set_add(&mod_set, (void *)ly_mod, 1, NULL)) {
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
            }
        }

        /* subscribe to all the modules */
        ntf_arg->sr_sub_count = mod_set.count;
        ntf_arg->sr_ntf_replay_complete_count = start.tv_sec ? 0 : ntf_arg->sr_sub_count;
        for (idx = 0; idx < mod_set.count; ++idx) {
            ly_mod = mod_set.objs[idx];
            rc = sr_notif_subscribe_tree(user_sess->sess, ly_mod->name, xp_filter, start.tv_sec ? &start : NULL,
                    stop.tv_sec ? &stop : NULL, np2srv_rpc_subscribe_ntf_cb, ntf_arg, 0, &np2srv.sr_notif_sub);
            if (rc != SR_ERR_OK) {
                sr_session_dup_error(user_sess->sess, session);
                goto cleanup;
            }
        }
    } else {
        /* subscribe to the specific module (stream) */
        ntf_arg->sr_sub_count = 1;
        ntf_arg->sr_ntf_replay_complete_count = start.tv_sec ? 0 : 1;
        rc = sr_notif_subscribe_tree(user_sess->sess, stream, xp_filter, start.tv_sec ? &start : NULL, stop.tv_sec ? &stop : NULL,
                np2srv_rpc_subscribe_ntf_cb, ntf_arg, 0, &np2srv.sr_notif_sub);
        if (rc != SR_ERR_OK) {
            sr_session_dup_error(user_sess->sess, session);
            goto cleanup;
        }
    }

cleanup:
    if (rc && has_nc_ntf_status) {
        nc_session_dec_notif_status(ncs);
    }
    ly_set_erase(&mod_set, NULL);
    free(xp_filter);
    np_release_user_sess(user_sess);
    return rc;
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
