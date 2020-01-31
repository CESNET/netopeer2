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

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "common.h"
#include "log.h"
#include "netconf_acm.h"

int
np2srv_rpc_get_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t UNUSED(event),
        uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *node, *data_get = NULL;
    char **filters = NULL;
    int filter_count = 0, i, rc = SR_ERR_OK;
    struct ly_set *nodeset;
    sr_datastore_t ds = 0;
    sr_get_oper_options_t get_opts = 0;
    NC_WD_MODE nc_wd;

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    if (!strcmp(op_path, "/ietf-netconf:get")) {
        /* get running data first */
        ds = SR_DS_RUNNING;
    } else { /* get-config */
        nodeset = lyd_find_path(input, "source/*");
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
            ds = SR_DS_CANDIDATE;
        }

        ly_set_free(nodeset);
    }

    /* create filters */
    nodeset = lyd_find_path(input, "filter");
    if (nodeset->number) {
        node = nodeset->set.d[0];
        ly_set_free(nodeset);
        if (op_filter_create(node, &filters, &filter_count)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        ly_set_free(nodeset);

        filters = malloc(sizeof *filters);
        if (!filters) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        filter_count = 1;
        filters[0] = strdup("/*");
        if (!filters[0]) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* get with-defaults mode */
    nodeset = lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults");
    if (nodeset->number) {
        leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
        if (!strcmp(leaf->value_str, "report-all")) {
            nc_wd = NC_WD_ALL;
        } else if (!strcmp(leaf->value_str, "report-all-tagged")) {
            nc_wd = NC_WD_ALL_TAG;
        } else if (!strcmp(leaf->value_str, "trim")) {
            nc_wd = NC_WD_TRIM;
        } else {
            assert(!strcmp(leaf->value_str, "explicit"));
            nc_wd = NC_WD_EXPLICIT;
        }
    }
    ly_set_free(nodeset);

get_sr_data:
    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /*
     * create the data tree for the data reply
     */
    for (i = 0; i < filter_count; i++) {
        rc = sr_get_data(session, filters[i], 0, 0, get_opts, &node);
        if (rc != SR_ERR_OK) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filters[i], sr_strerror(rc));
            goto cleanup;
        }

        if (!data_get) {
            data_get = node;
        } else if (node && lyd_merge(data_get, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
            lyd_free_withsiblings(node);
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    if (!strcmp(op_path, "/ietf-netconf:get") && (ds == SR_DS_RUNNING)) {
        /* we have running data, now append state data */
        ds = SR_DS_OPERATIONAL;
        get_opts = SR_OPER_NO_CONFIG;
        goto get_sr_data;
    }

    /* perform correct NACM filtering */
    ncac_check_data_read_filter(&data_get, np_get_nc_sess_user(session));

    /* add output */
    node = lyd_new_output_anydata(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE);
    if (!node) {
        goto cleanup;
    }
    data_get = NULL;

    /* success */

cleanup:
    for (i = 0; i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);
    lyd_free_withsiblings(data_get);
    return rc;
}

int
np2srv_rpc_editconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    struct lyd_node *config = NULL;
    const sr_error_info_t *err_info;
    const char *str, *defop = "merge", *testop = "test-then-set";
    int rc = SR_ERR_OK;

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset);

    /* default-operation */
    nodeset = lyd_find_path(input, "default-operation");
    if (nodeset->number) {
        defop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
    }
    ly_set_free(nodeset);

    /* test-option */
    nodeset = lyd_find_path(input, "test-option");
    if (nodeset->number) {
        testop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }
    ly_set_free(nodeset);

    /* error-option */
    nodeset = lyd_find_path(input, "error-option");
    if (nodeset->number) {
        str = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (strcmp(str, "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", str);
        }
    }
    ly_set_free(nodeset);

    /* config */
    nodeset = lyd_find_path(input, "config | url");
    if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_EDIT | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                LYD_OPT_EDIT | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /* sysrepo API */
    rc = sr_edit_batch(session, config, defop);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (!strcmp(testop, "test-then-set")) {
        rc = sr_apply_changes(session, NP2SRV_EDIT_CONFIG_TIMEOUT);
    } else {
        assert(!strcmp(testop, "test-only"));
        rc = sr_validate(session, 0);
    }
    if (rc != SR_ERR_OK) {
        sr_get_error(session, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    return rc;
}

int
np2srv_rpc_copyconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0, sds;
    struct ly_set *nodeset;
    struct lyd_node *config = NULL;
    int rc = SR_ERR_OK;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node_leaf_list *leaf;
    const char *trg_url = NULL;
    int lyp_wd_flag;
#endif

    /* get know which datastores are affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    nodeset = lyd_find_path(input, "source/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        sds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        sds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
        sds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* NACM checks */
    if (!config && (ds != SR_DS_STARTUP) && (sds != SR_DS_RUNNING)) {
        /* get source datastore data and filter them */
        sr_session_switch_ds(session, sds);
        rc = sr_get_data(session, "/*", 0, 0, 0, &config);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
        ncac_check_data_read_filter(&config, np_get_nc_sess_user(session));
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* we need with-defaults flag in this case */
        nodeset = lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults");
        lyp_wd_flag = 0;
        if (nodeset->number) {
            leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
            if (!strcmp(leaf->value_str, "report-all")) {
                lyp_wd_flag = LYP_WD_ALL;
            } else if (!strcmp(leaf->value_str, "report-all-tagged")) {
                lyp_wd_flag = LYP_WD_ALL_TAG;
            } else if (!strcmp(leaf->value_str, "trim")) {
                lyp_wd_flag = LYP_WD_TRIM;
            } else {
                assert(!strcmp(leaf->value_str, "explicit"));
                lyp_wd_flag = LYP_WD_EXPLICIT;
            }
        }
        ly_set_free(nodeset);

        if (op_export_url(trg_url, config, LYP_FORMAT | LYP_WITHSIBLINGS | lyp_wd_flag, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        /* config is spent */
        rc = sr_replace_config(session, NULL, config, 0);
        config = NULL;
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    return rc;
}

int
np2srv_rpc_deleteconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    /* get know which datastore is affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        config = op_parse_url(trg_url, LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            goto cleanup;
        }
        lyd_free_withsiblings(config);

        /* upload empty config */
        if (op_export_url(trg_url, NULL, 0, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        rc = sr_replace_config(session, NULL, NULL, 0);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_un_lock_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset);

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /* sysrepo API */
    if (!strcmp(input->schema->name, "lock")) {
        rc = sr_lock(session, NULL);
    } else if (!strcmp(input->schema->name, "unlock")) {
        rc = sr_unlock(session, NULL);
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_kill_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct nc_session *kill_sess;
    struct ly_set *nodeset;
    uint32_t kill_sid, i;
    int rc = SR_ERR_OK;

    nodeset = lyd_find_path(input, "session-id");
    kill_sid = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value.uint32;
    ly_set_free(nodeset);

    if (kill_sid == sr_session_get_nc_id(session)) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "It is forbidden to kill own session.");
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Session with the specified \"session-id\" not found.");
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, sr_session_get_nc_id(session));

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_commit_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *UNUSED(input),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;;

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, SR_DS_RUNNING);

    /* sysrepo API */
    rc = sr_copy_config(session, NULL, SR_DS_CANDIDATE, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_discard_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *UNUSED(input),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, SR_DS_CANDIDATE);

    /* sysrepo API */
    rc = sr_copy_config(session, NULL, SR_DS_RUNNING, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_validate_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;

    /* get know which datastore is affected */
    nodeset = lyd_find_path(input, "source/*");
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            ds = SR_DS_CANDIDATE;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
            /* config is also validated now */
            config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
            if (rc) {
                ly_set_free(nodeset);
                goto cleanup;
            }
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            /* config is also validated now */
            config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                    LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
            if (rc) {
                ly_set_free(nodeset);
                goto cleanup;
            }
#else
            ly_set_free(nodeset);
            rc = SR_ERR_UNSUPPORTED;
            sr_set_error(session, NULL, "URL not supported.");
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    if (!config) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(session, ds);

        rc = sr_validate(session, 0);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    return rc;
}

int
np2srv_rpc_subscribe_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct ly_set *nodeset;
    const struct lys_module *ly_mod;
    struct lys_node *root, *next, *elem, *parent;
    struct nc_session *ncs;
    const char *stream;
    char **filters = NULL, *xp = NULL, *mem;
    time_t start = 0, stop = 0;
    int rc = SR_ERR_OK, i, len, filter_count = 0;
    uint32_t idx;

    /* find this NETCONF session */
    for (i = 0; (ncs = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(ncs) == sr_session_get_nc_id(session)) {
            break;
        }
    }
    if (!ncs) {
        ERR("Failed to find NETCONF session SID %u.", sr_session_get_nc_id(session));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* learn stream */
    nodeset = lyd_find_path(input, "stream");
    stream = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
    ly_set_free(nodeset);

    /* filter */
    nodeset = lyd_find_path(input, "filter");
    if (nodeset->number) {
        if (op_filter_create(nodeset->set.d[0], &filters, &filter_count)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* join all filters into one xpath */
        for (i = 0; i < filter_count; ++i) {
            if (!xp) {
                xp = strdup(filters[0]);
                if (!xp) {
                    EMEM;
                    rc = SR_ERR_NOMEM;
                    goto cleanup;
                }
            } else {
                len = strlen(xp);
                mem = realloc(xp, len + 5 + strlen(filters[i]) + 1);
                if (!mem) {
                    EMEM;
                    rc = SR_ERR_NOMEM;
                    goto cleanup;
                }
                xp = mem;
                sprintf(xp + len, " and %s", filters[i]);
            }
        }
    }
    ly_set_free(nodeset);

    /* start time */
    nodeset = lyd_find_path(input, "startTime");
    if (nodeset->number) {
        start = nc_datetime2time(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str);
    }
    ly_set_free(nodeset);

    /* stop time */
    nodeset = lyd_find_path(input, "stopTime");
    if (nodeset->number) {
        stop = nc_datetime2time(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str);
    }
    ly_set_free(nodeset);

    /* sysrepo API */
    if (!strcmp(stream, "NETCONF")) {
        /* subscribe to all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(lyd_node_module(input)->ctx, &idx))) {
            rc = SR_ERR_OK;
            LY_TREE_FOR(ly_mod->data, root) {
                LY_TREE_DFS_BEGIN(root, next, elem) {
                    if (elem->nodetype == LYS_NOTIF) {
                        /* check that we are not in a grouping */
                        parent = lys_parent(elem);
                        while (parent && (parent->nodetype != LYS_GROUPING)) {
                            parent = lys_parent(parent);
                        }
                        if (!parent) {
                            rc = sr_event_notif_subscribe_tree(nc_session_get_data(ncs), ly_mod->name, xp, start, stop,
                                    np2srv_ntf_new_cb, ncs, np2srv.sr_notif_sub ? SR_SUBSCR_CTX_REUSE : 0, &np2srv.sr_notif_sub);
                            break;
                        }
                    }
                    LY_TREE_DFS_END(root, next, elem);
                }
                if (elem && (elem->nodetype == LYS_NOTIF)) {
                   break;
                }
            }
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    } else {
        rc = sr_event_notif_subscribe_tree(nc_session_get_data(ncs), stream, xp, start, stop, np2srv_ntf_new_cb, ncs,
                np2srv.sr_notif_sub ? SR_SUBSCR_CTX_REUSE : 0, &np2srv.sr_notif_sub);
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* set ongoing notifications flag */
    nc_session_set_notif_status(ncs, 1);

    /* success */

cleanup:
    for (i = 0; i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);
    free(xp);
    return rc;
}
