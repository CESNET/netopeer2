/**
 * @file netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf callbacks
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_SOURCE

#include "netconf.h"

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "common.h"
#include "log.h"
#include "netconf_acm.h"
#include "netconf_monitoring.h"
#include "err_netconf.h"

static int
np2srv_get_first_ns(const char *expr, const char **start, int *len)
{
    int i;

    if (expr[0] != '/') {
        return -1;
    }
    if (expr[1] == '/') {
        expr += 2;
    } else {
        ++expr;
    }

    if (!isalpha(expr[0]) && (expr[0] != '_')) {
        return -1;
    }
    for (i = 1; expr[i] && (isalnum(expr[i]) || (expr[i] == '_') || (expr[i] == '-') || (expr[i] == '.')); ++i);
    if (expr[i] != ':') {
        return -1;
    }

    *start = expr;
    *len = i;
    return 0;
}

/**
 * @brief Get generic filters in the form of "/module:*" from exact xpath filters.
 */
static int
np2srv_get_rpc_module_filters(const struct np2_filter *filter, struct np2_filter *mod_filter)
{
    int len, selection;
    uint32_t i, j;
    const char *start;
    char *str;

    for (i = 0; i < filter->count; ++i) {
        if (np2srv_get_first_ns(filter->filters[i].str, &start, &len)) {
            /* not the simple format, use it as it is */
            str = strdup(filter->filters[i].str);
            selection = filter->filters[i].selection;
        } else {
            /* get all the data of a module */
            if (asprintf(&str, "/%.*s:*", len, start) == -1) {
                str = NULL;
            }
            selection = 1;
        }

        if (!str) {
            EMEM;
            return SR_ERR_NO_MEMORY;
        }

        /* check for a duplicity */
        for (j = 0; j < mod_filter->count; ++j) {
            if (!strcmp(str, mod_filter->filters[j].str)) {
                break;
            }
        }
        if (j < mod_filter->count) {
            free(str);
            continue;
        }

        /* add a new module filter */
        mod_filter->filters = realloc(mod_filter->filters, (mod_filter->count + 1) * sizeof *mod_filter->filters);
        mod_filter->filters[mod_filter->count].str = str;
        mod_filter->filters[mod_filter->count].selection = selection;
        ++mod_filter->count;
    }

    return SR_ERR_OK;
}

/**
 * @brief Get data for a get RPC.
 */
static int
np2srv_get_rpc_data(sr_session_ctx_t *session, const struct np2_filter *filter, sr_session_ctx_t *ev_sess,
        struct lyd_node **data)
{
    struct lyd_node *all_data = NULL;
    sr_datastore_t ds;
    sr_get_oper_options_t get_opts = 0;
    struct np2_filter mod_filter = {0};
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;

    /* get generic filters to allow retrieving all possibly needed data first, which are then filtered again
     * (once we have merged config and state data) */
    rc = np2srv_get_rpc_module_filters(filter, &mod_filter);
    if (rc) {
        goto cleanup;
    }

    /* get data from running first */
    ds = SR_DS_RUNNING;

get_sr_data:
    sr_session_switch_ds(session, ds);

    if ((rc = op_filter_data_get(session, 0, get_opts, &mod_filter, ev_sess, &all_data))) {
        goto cleanup;
    }

    if (ds == SR_DS_RUNNING) {
        /* we have running data, now append state data */
        ds = SR_DS_OPERATIONAL;
        get_opts = SR_OPER_NO_CONFIG;
        goto get_sr_data;
    }

    /* now filter only the requested data from the created running data + state data */
    if ((rc = op_filter_data_filter(&all_data, filter, 1, data))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set, NULL);
    lyd_free_siblings(all_data);
    op_filter_erase(&mod_filter);
    return rc;
}

/**
 * @brief get data for a get-config RPC.
 */
static int
np2srv_getconfig_rpc_data(sr_session_ctx_t *session, const struct np2_filter *filter, sr_datastore_t ds,
        sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    struct lyd_node *select_data = NULL;
    int rc = SR_ERR_OK;

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /*
     * create the data tree for the data reply
     */
    if ((rc = op_filter_data_get(session, 0, 0, filter, ev_sess, &select_data))) {
        goto cleanup;
    }

    if ((rc = op_filter_data_filter(&select_data, filter, 0, data))) {
        goto cleanup;
    }

cleanup:
    lyd_free_siblings(select_data);
    return rc;
}

int
np2srv_rpc_get_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    struct lyd_node *node, *data_get = NULL;
    struct lyd_meta *meta;
    struct np2_filter filter = {0};
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    struct ly_set *nodeset = NULL;
    sr_datastore_t ds = 0;
    const char *single_filter, *username;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
    lyd_find_path(input, "filter", 0, &node);
    if (node) {
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
                if (op_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, &filter)) {
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
            }
            single_filter = NULL;
        } else {
            /* xpath */
            single_filter = lyd_get_meta_value(meta);
        }
    } else {
        single_filter = "/*";
    }

    if (single_filter) {
        /* create a single filter */
        filter.filters = malloc(sizeof *filter.filters);
        if (!filter.filters) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        filter.count = 1;
        filter.filters[0].str = strdup(single_filter);
        filter.filters[0].selection = 1;
        if (!filter.filters[0].str) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
    }

    /* we do not care here about with-defaults mode, it does not change anything */

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* get filtered data */
    if (!strcmp(op_path, "/ietf-netconf:get-config")) {
        rc = np2srv_getconfig_rpc_data(user_sess, &filter, ds, session, &data_get);
    } else {
        rc = np2srv_get_rpc_data(user_sess, &filter, session, &data_get);
    }
    if (rc) {
        goto cleanup;
    }

    /* perform correct NACM filtering */
    sr_session_get_orig_data(session, 1, NULL, (const void **)&username);
    ncac_check_data_read_filter(&data_get, username);

    /* add output */
    if (lyd_new_any(output, NULL, "data", data_get, 1, LYD_ANYDATA_DATATREE, 1, &node)) {
        goto cleanup;
    }
    data_get = NULL;

    /* success */

cleanup:
    op_filter_erase(&filter);
    lyd_free_siblings(data_get);
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
    const sr_error_info_t *err_info;
    sr_session_ctx_t *user_sess = NULL;
    const char *defop = "merge", *testop = "test-then-set";
    int rc = SR_ERR_OK;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
    lyd_find_path(input, "default-operation", 0, &node);
    if (node) {
        defop = lyd_get_value(node);
    }

    /* test-option */
    lyd_find_path(input, "test-option", 0, &node);
    if (node) {
        testop = lyd_get_value(node);
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }

    /* error-option */
    lyd_find_path(input, "error-option", 0, &node);
    if (node) {
        if (strcmp(lyd_get_value(node), "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", lyd_get_value(node));
        }
    }

    /* config */
    lyd_find_xpath(input, "config | url", &nodeset);
    if (!strcmp(nodeset->dnodes[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_OPAQ | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), LYD_PARSE_OPAQ | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(session, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API */
    if (config) {
        rc = sr_edit_batch(user_sess, config, defop);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    if (!strcmp(testop, "test-then-set")) {
        rc = sr_apply_changes(user_sess, np2srv.sr_timeout);
    } else {
        assert(!strcmp(testop, "test-only"));
        rc = sr_validate(user_sess, NULL, 0);
    }
    if (rc != SR_ERR_OK) {
        sr_session_get_error(user_sess, &err_info);
        sr_session_set_error_message(session, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    if (user_sess) {
        /* discard any changes that possibly failed to be applied */
        sr_discard_changes(user_sess);
    }
    lyd_free_siblings(config);
    return rc;
}

int
np2srv_rpc_copyconfig_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = SR_DS_OPERATIONAL, sds = SR_DS_OPERATIONAL;
    struct ly_set *nodeset = NULL;
    const sr_error_info_t *err_info;
    struct lyd_node *node, *config = NULL;
    int rc = SR_ERR_OK, run_to_start = 0;
    sr_session_ctx_t *user_sess;
    const char *username;
    uint32_t *nc_sid;
#ifdef NP2SRV_URL_CAPAB
    const char *trg_url = NULL;
    int lyp_wd_flag;
#endif

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(session, "URL not supported.");
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
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        if (trg_url && !strcmp(trg_url, lyd_get_value(nodeset->dnodes[0]))) {
            rc = SR_ERR_INVAL_ARG;
            sr_session_set_error_message(session, "Source and target URLs are the same.");
            goto cleanup;
        }

        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), LYD_PARSE_STRICT | LYD_PARSE_NO_STATE |
                LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(session, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    if (ds == sds) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "Source and target datastores are the same.");
        goto cleanup;
    }

    /* NACM checks */
    if (!config && !run_to_start) {
        /* get source datastore data and filter them */
        sr_session_switch_ds(session, sds);
        rc = sr_get_data(session, "/*", 0, np2srv.sr_timeout, 0, &config);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }

        sr_session_get_orig_data(session, 1, NULL, (const void **)&username);
        ncac_check_data_read_filter(&config, username);
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* we need with-defaults flag in this case */
        lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults", 0, &node);
        lyp_wd_flag = 0;
        if (node) {
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
        if (config) {
            /* config is spent */
            rc = sr_replace_config(user_sess, NULL, config, np2srv.sr_timeout);
            config = NULL;
        } else {
            assert(run_to_start);

            /* set SID to skip NACM check, only one copy-config can be executed at once */
            sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_sid);
            ATOMIC_STORE_RELAXED(skip_nacm_nc_sid, *nc_sid);
            rc = sr_copy_config(user_sess, NULL, sds, np2srv.sr_timeout);
            ATOMIC_STORE_RELAXED(skip_nacm_nc_sid, 0);
        }
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(session, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_siblings(config);
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
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
        sr_session_set_error_message(session, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        config = op_parse_url(trg_url, LYD_PARSE_STRICT | LYD_PARSE_NO_STATE | LYD_PARSE_ONLY, &rc, session);
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
        rc = sr_replace_config(user_sess, NULL, NULL, np2srv.sr_timeout);
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(session, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_un_lock_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset = NULL;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;
    int rc = SR_ERR_OK;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API */
    if (!strcmp(input->schema->name, "lock")) {
        rc = sr_lock(user_sess, NULL);
    } else if (!strcmp(input->schema->name, "unlock")) {
        rc = sr_unlock(user_sess, NULL);
    }
    if ((rc == SR_ERR_LOCKED) && sr_session_get_orig_name(session) && !strcmp(sr_session_get_orig_name(session), "netopeer2")) {
        /* NETCONF error */
        sr_session_get_error(user_sess, &err_info);
        np_err_sr2nc_lock_denied(session, err_info);
        goto cleanup;
    } else if (rc) {
        /* generic error */
        sr_session_get_error(user_sess, &err_info);
        sr_session_set_error_message(session, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
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

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    lyd_find_path(input, "session-id", 0, &node);
    kill_sid = ((struct lyd_node_term *)node)->value.uint32;

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_sid);
    if (kill_sid == *nc_sid) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "It is forbidden to kill own session.");
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "Session with the specified \"session-id\" not found.");
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, kill_sid);

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_commit_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *UNUSED(input), sr_event_t event, uint32_t UNUSED(request_id),
        struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, SR_DS_RUNNING);

    /* sysrepo API */
    rc = sr_copy_config(user_sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout);
    if (rc != SR_ERR_OK) {
        sr_session_get_error(user_sess, &err_info);
        sr_session_set_error_message(session, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_discard_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *UNUSED(input), sr_event_t event, uint32_t UNUSED(request_id),
        struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, SR_DS_CANDIDATE);

    /* sysrepo API */
    rc = sr_copy_config(user_sess, NULL, SR_DS_RUNNING, np2srv.sr_timeout);
    if (rc != SR_ERR_OK) {
        sr_session_get_error(user_sess, &err_info);
        sr_session_set_error_message(session, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_validate_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset = NULL;
    sr_session_ctx_t *user_sess;
    int rc = SR_ERR_OK;
    const sr_error_info_t *err_info;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
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
        /* config is also validated now */
        config = op_parse_config((struct lyd_node_any *)nodeset->dnodes[0], LYD_PARSE_STRICT | LYD_PARSE_NO_STATE,
                &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->dnodes[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(lyd_get_value(nodeset->dnodes[0]), LYD_PARSE_STRICT | LYD_PARSE_NO_STATE |
                LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            ly_set_free(nodeset, NULL);
            goto cleanup;
        }
#else
        ly_set_free(nodeset, NULL);
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(session, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset, NULL);

    if (!config) {
        /* get the user session */
        user_sess = np_get_user_sess(session);
        if (!user_sess) {
            EINT;
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess, ds);

        /* sysrepo API */
        rc = sr_validate(user_sess, NULL, 0);
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(session, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_siblings(config);
    return rc;
}

static LY_ERR
np2srv_lysc_has_notif_clb(struct lysc_node *node, void *UNUSED(data), ly_bool *UNUSED(dfs_continue))
{
    if (node->nodetype == LYS_NOTIF) {
        return LY_EEXIST;
    }

    return LY_SUCCESS;
}

/**
 * @brief New notification callback used for notifications received on subscription made by \<create-subscription\> RPC.
 */
static void
np2srv_rpc_subscribe_ntf_cb(sr_session_ctx_t *UNUSED(session), uint32_t sub_id, const sr_ev_notif_type_t notif_type,
        const struct lyd_node *notif, struct timespec *timestamp, void *private_data)
{
    struct nc_server_notif *nc_ntf = NULL;
    struct nc_session *ncs = (struct nc_session *)private_data;
    struct lyd_node *ly_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char *datetime;
    time_t stop;

    /* create these notifications, sysrepo only emulates them */
    if (notif_type == SR_EV_NOTIF_REPLAY_COMPLETE) {
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:replayComplete", NULL, 0, &ly_ntf);
        notif = ly_ntf;
    } else if (notif_type == SR_EV_NOTIF_TERMINATED) {
        sr_event_notif_sub_get_info(np2srv.sr_notif_sub, sub_id, NULL, NULL, NULL, &stop, NULL);
        if (!stop || (stop > time(NULL))) {
            /* no stop-time or it was not reached so no notification should be generated */
            goto cleanup;
        }

        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:notificationComplete", NULL, 0, &ly_ntf);
        notif = ly_ntf;
    } else if ((notif_type == SR_EV_NOTIF_MODIFIED) || (notif_type == SR_EV_NOTIF_RESUMED) ||
            (notif_type == SR_EV_NOTIF_SUSPENDED)) {
        /* these subscriptions do not support these events, ignore */
        goto cleanup;
    }

    /* find the top-level node */
    while (notif->parent) {
        notif = lyd_parent(notif);
    }

    /* check NACM */
    if (ncac_check_operation(notif, nc_session_get_username(ncs))) {
        goto cleanup;
    }

    /* create the notification object */
    ly_time_ts2str(timestamp, &datetime);
    nc_ntf = nc_server_notif_new((struct lyd_node *)notif, datetime, NC_PARAMTYPE_CONST);
    free(datetime);

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        goto cleanup;
    }
    ncm_session_notification(ncs);

cleanup:
    if (notif_type == SR_EV_NOTIF_TERMINATED) {
        /* subscription finished */
        nc_session_dec_notif_status(ncs);
    }

    nc_server_notif_free(nc_ntf);
    lyd_free_all(ly_ntf);
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
    sr_session_ctx_t *user_sess;
    const char *stream;
    struct np2_filter filter = {0};
    char *xp = NULL;
    struct timespec start = {0}, stop = {0};
    int rc = SR_ERR_OK;
    const sr_error_info_t *err_info;
    uint32_t idx;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* find this NETCONF session and sysrepo user session */
    ncs = np_get_nc_sess(session);
    if (!ncs) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    user_sess = nc_session_get_data(ncs);

    /* RFC 5277 section 6.5 */
    if (nc_session_get_notif_status(ncs)) {
        sr_session_set_error_message(session, "Session already subscribed.");
        return SR_ERR_EXISTS;
    }

    /* learn stream */
    lyd_find_path(input, "stream", 0, &node);
    stream = lyd_get_value(node);

    /* filter */
    lyd_find_path(input, "filter", 0, &node);
    if (node) {
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
                if (op_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, &filter)) {
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                if ((rc = op_filter_filter2xpath(&filter, &xp))) {
                    goto cleanup;
                }
            }
        } else {
            /* xpath */
            if (strlen(lyd_get_meta_value(meta))) {
                xp = strdup(lyd_get_meta_value(meta));
                if (xp) {
                    EMEM;
                    rc = SR_ERR_NO_MEMORY;
                    goto cleanup;
                }
            }
        }
    }

    /* start time */
    lyd_find_path(input, "startTime", 0, &node);
    if (node) {
        ly_time_str2ts(lyd_get_value(node), &start);
    }

    /* stop time */
    lyd_find_path(input, "stopTime", 0, &node);
    if (node) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* set ongoing notifications flag */
    nc_session_inc_notif_status(ncs);

    /* sysrepo API */
    if (!strcmp(stream, "NETCONF")) {
        /* subscribe to all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(LYD_CTX(input), &idx))) {
            if (!ly_mod->implemented) {
                continue;
            }

            if (lysc_module_dfs_full(ly_mod, np2srv_lysc_has_notif_clb, NULL) == LY_EEXIST) {
                /* a notification was found, subscribe to the module */
                rc = sr_event_notif_subscribe_tree(user_sess, ly_mod->name, xp, start.tv_sec, stop.tv_sec,
                        np2srv_rpc_subscribe_ntf_cb, ncs, SR_SUBSCR_CTX_REUSE, &np2srv.sr_notif_sub);
                if (rc != SR_ERR_OK) {
                    sr_session_get_error(user_sess, &err_info);
                    sr_session_set_error_message(session, err_info->err[0].message);
                    break;
                }
            }
        }
    } else {
        /* subscribe to the specific module (stream) */
        rc = sr_event_notif_subscribe_tree(user_sess, stream, xp, start.tv_sec, stop.tv_sec, np2srv_rpc_subscribe_ntf_cb,
                ncs, SR_SUBSCR_CTX_REUSE, &np2srv.sr_notif_sub);
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(session, err_info->err[0].message);
        }
    }

    if (rc) {
        /* fail */
        nc_session_dec_notif_status(ncs);
        goto cleanup;
    }

    /* success */

cleanup:
    op_filter_erase(&filter);
    free(xp);
    return rc;
}

int
np2srv_nc_ntf_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream, *sr_data = NULL, *sr_mod, *rep_sup;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    const char *mod_name;
    char *buf;
    int rc;

    conn = sr_session_get_connection(session);
    ly_ctx = sr_get_context(conn);

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

    /* go through all the sysrepo modules */
    rc = sr_get_module_info(conn, &sr_data);
    if (rc != SR_ERR_OK) {
        ERR("Failed to get sysrepo module info data (%s).", sr_strerror(rc));
        goto error;
    }
    LY_LIST_FOR(lyd_child(sr_data), sr_mod) {
        if (strcmp(sr_mod->schema->name, "module")) {
            continue;
        }

        mod_name = lyd_get_value(lyd_child(sr_mod));

        /* get the module */
        mod = ly_ctx_get_module_implemented(ly_ctx, mod_name);
        assert(mod);

        if (!np_ly_mod_has_notif(mod)) {
            /* no notifications in the module so do not consider it a stream */
            continue;
        }

        /* generate information about the stream/module */
        if (lyd_new_list(lyd_child(root), NULL, "stream", 0, &stream, mod_name)) {
            goto error;
        }
        if (lyd_new_term(stream, NULL, "description", "Stream with all the notifications of a module.", 0, NULL)) {
            goto error;
        }

        lyd_find_path(sr_mod, "replay-support", 0, &rep_sup);
        if (lyd_new_term(stream, NULL, "replaySupport", rep_sup ? "true" : "false", 0, NULL)) {
            goto error;
        }
        if (rep_sup) {
            ly_time_time2str(((struct lyd_node_term *)rep_sup)->value.uint64, NULL, &buf);
            if (lyd_new_term(stream, NULL, "replayLogCreationTime", buf, 0, NULL)) {
                free(buf);
                goto error;
            }
            free(buf);
        }
    }

    lyd_free_siblings(sr_data);
    *parent = root;
    return SR_ERR_OK;

error:
    lyd_free_tree(root);
    lyd_free_siblings(sr_data);
    return SR_ERR_INTERNAL;
}
