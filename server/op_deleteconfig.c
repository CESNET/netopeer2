/**
 * @file op_deleteconfig.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF <delete-config> operation implementation
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <string.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

struct nc_server_reply *
op_deleteconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    sr_datastore_t target = 0;
    const char *dsname;
    uint32_t index;
    int rc;
    const struct lys_module *mod;
    struct lys_node *iter;
    char path[1024];
    struct ly_set *nodeset;
    struct nc_server_reply *ereply = NULL;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* get know which datastore is being affected */
    nodeset = lyd_find_xpath(rpc, "/ietf-netconf:delete-config/target/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(dsname, "startup")) {
        target = SR_DS_STARTUP;
    }
    /* TODO URL capability */

    if (sessions->ds != target) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, target);
        sessions->ds = target;
    }

    /* update data from sysrepo */
    if (sr_session_refresh(sessions->srs) != SR_ERR_OK) {
        goto error;
    }

    /* perform operation
     * - iterate over all schemas and remove all top-level data nodes.
     * sysrepo does not accept '/\asterisk' since it splits data */
    index = 0;
    while ((mod = ly_ctx_get_module_iter(np2srv.ly_ctx, &index))) {
        LY_TREE_FOR(mod->data, iter) {
            if (!(iter->nodetype & (LYS_CONTAINER | LYS_LIST | LYS_LEAFLIST | LYS_LEAF | LYS_ANYXML)) ||
                    (iter->flags & LYS_CONFIG_R)) {
                /* skip bothering sysrepo with schemas with no configuration data */
                continue;
            }

            snprintf(path, 1024, "/%s:*", mod->name);
            rc = sr_delete_item(sessions->srs, path, 0);
            if (rc != SR_ERR_OK &&
                    rc != SR_ERR_UNKNOWN_MODEL) { /* TODO: hack to skip internal ietf-netconf-acm */
                goto error;
            }

            /* sysrepo was asked for remove all configuration data
             * from this schema so we can continue with another schema */
            break;
        }
    }

    /* commit the result */
    rc = sr_commit(sessions->srs);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    return nc_server_reply_ok();

error:
    /* get the error */
    ereply = op_build_err_sr(ereply, sessions->srs);

    /* rollback changes */
    sr_discard_changes(sessions->srs);

    return ereply;
}
