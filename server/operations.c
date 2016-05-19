/**
 * @file operations.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Basic NETCONF operations
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
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

char *
op_get_srval_value(struct ly_ctx *ctx, sr_val_t *value, char *buf)
{
    const struct lys_node *snode;

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
    case SR_LEAFREF_T:
        return (value->data.string_val);
    case SR_LEAF_EMPTY_T:
        return NULL;
    case SR_BOOL_T:
        return value->data.bool_val ? "true" : "false";
    case SR_DECIMAL64_T:
        /* get fraction-digits */
        snode = ly_ctx_get_node(ctx, NULL, value->xpath);
        if (!snode) {
            return NULL;
        }
        sprintf(buf, "%.*f", ((struct lys_node_leaf *)snode)->type.info.dec64.dig, value->data.decimal64_val);
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
        sprintf(buf, "%lu", value->data.uint64_val);
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
        sprintf(buf, "%ld", value->data.int64_val);
        return buf;
    default:
        return NULL;
    }

}

/* return: -1 = discard, 0 = keep, 1 = keep and add the attribute */
int
op_dflt_data_inspect(struct ly_ctx *ctx, sr_val_t *value, NC_WD_MODE wd)
{
    const struct lys_node_leaf *sleaf;
    struct lys_tpdf *tpdf;
    const char *dflt_val = NULL;
    char buf[256], *val;

    /* NC_WD_ALL HANDLED */
    if (wd == NC_WD_ALL) {
        /* we keep it all */
        return 0;
    }

    if ((wd == NC_WD_EXPLICIT) && !value->dflt) {
        return 0;
    }

    /*
     * we need the schema node now
     */

    sleaf = (const struct lys_node_leaf *)ly_ctx_get_node2(ctx, NULL, value->xpath, 0);
    if (!sleaf) {
        EINT;
        return -1;
    }

    if (sleaf->nodetype != LYS_LEAF) {
        return 0;
    }

    /* NC_WD_EXPLICIT HANDLED */
    if (wd == NC_WD_EXPLICIT) {
        if (sleaf->flags & LYS_CONFIG_W) {
            return -1;
        }
        return 0;
    }

    if (value->dflt) {
        switch (wd) {
        case NC_WD_TRIM:
            return -1;
        case NC_WD_ALL_TAG:
            return 1;
        default:
            EINT;
            return -1;
        }
    }

    /*
     * we need to actually examine the value now
     */

    /* leaf's default value */
    dflt_val = sleaf->dflt;

    /* typedef's default value */
    if (!dflt_val) {
        tpdf = sleaf->type.der;
        while (tpdf && !tpdf->dflt) {
            tpdf = tpdf->type.der;
        }
        if (tpdf) {
            dflt_val = tpdf->dflt;
        }
    }

    /* value itself */
    val = op_get_srval_value(ctx, value, buf);

    switch (wd) {
    case NC_WD_TRIM:
        if (dflt_val && !strcmp(dflt_val, val)) {
            return -1;
        }
        break;
    case NC_WD_ALL_TAG:
        if (dflt_val && !strcmp(dflt_val, val)) {
            return 1;
        }
        break;
    default:
        EINT;
        return -1;
    }

    return 0;
}
