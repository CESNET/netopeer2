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

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

static bool
sr_has_parent(const struct lys_node *node, LYS_NODE type)
{
    for (node = node->parent; node; node = node->parent) {
        if (node->nodetype == type) {
            return true;
        }
    }

    return false;
}

static bool
sr_find_schema_node_valid_identifier(const char *identifier, size_t id_len)
{
    size_t i;

    if (0 == id_len) {
        id_len = strlen(identifier);
    }

    if (0 == id_len) {
        return false;
    } else if (!isalpha(identifier[0]) && (identifier[0] != '_')) {
        return false;
    }

    --id_len;

    for (i = 1; i < id_len; ++i) {
        if (!isalnum(identifier[0]) && (identifier[0] != '_') && (identifier[0] != '-') && (identifier[0] != '.')) {
            return false;
        }
    }

    return true;
}

static int
sr_find_schema_node_predicate(const struct lys_node *node, char *predicate)
{
    char *pred_end = NULL, *identifier = NULL;
    size_t id_len = 0;
    uint16_t i = 0;
    struct lys_node_leaf *key = NULL;

    if (!(node->nodetype & (LYS_LIST | LYS_LEAFLIST))) {
        return -1;
    }

    for (; !pred_end || (pred_end[1] == '['); predicate = pred_end + 2) {
        pred_end = strchr(predicate, ']');
        if (NULL == pred_end) {
            return SR_ERR_INVAL_ARG;
        }

        identifier = predicate;
        while (isspace(identifier[0])) {
            ++identifier;
        }

        id_len = 0;
        while (!isspace(identifier[id_len]) && (identifier[id_len] != '=') && (identifier[id_len] != ']')) {
            ++id_len;
        }

        /* check the identifier */
        if (node->nodetype == LYS_LEAFLIST) {
            if ((identifier[0] != '.') || (id_len != 1)) {
                return SR_ERR_INVAL_ARG;
            }
            break;
        } else {
            if (isdigit(identifier[0])) {
                /* position */
                for (i = 1; i < id_len; ++i) {
                    if (!isdigit(identifier[i])) {
                        return SR_ERR_INVAL_ARG;
                    }
                }
            } else {
                if (!sr_find_schema_node_valid_identifier(identifier, id_len)) {
                    return SR_ERR_INVAL_ARG;
                }

                for (i = 0; i < ((struct lys_node_list *)node)->keys_size; ++i) {
                    key = ((struct lys_node_list *)node)->keys[i];
                    if (0 == strncmp(key->name, identifier, id_len) && !key->name[id_len]) {
                        break;
                    }
                }
                if (i == ((struct lys_node_list *)node)->keys_size) {
                    return -1;
                }
            }
        }
    }

    return SR_ERR_OK;
}

int
sr_find_schema_node(const struct lys_module *module, const struct lys_node *start, const char *data_path, int output,
                    struct ly_set **ret)
{
    int rc = 0, tmp_rc = SR_ERR_OK;
    const struct lys_node *node = NULL, *next = NULL, *elem = NULL;
    char *path = NULL, *name = NULL, *mod_name = NULL, *path_end = NULL, *predicate = NULL;
    const struct lys_module *prev_mod = NULL;
    bool all_desc = false, last_iter = false;

    assert(module || start);
    if (ret) {
        *ret = NULL;
    }

    path = strdup(data_path);

    path_end = path + strlen(path);
    /* replace every '/' with 0 (but be careful with "//") and prepare for parsing */
    for (name = strchr(path, '/'); name; name = strchr(name + 2, '/')) {
        name[0] = '\0';
        if (name[1] == '\0') {
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }
    }
    if (path[0] == '\0') {
        /* absolute path */
        if (NULL == module) {
            module = lys_node_module(start);
        }
        start = NULL;

        name = path + 1;
    } else {
        /* relative path */
        if (NULL == start) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        module = NULL;

        name = path;
        prev_mod = lys_node_module(start);
    }

    /* main loop */
    while (1) {
        mod_name = strchr(name, ':');
        if (mod_name) {
            mod_name[0] = '\0';
            mod_name = name;
            name = mod_name + strlen(mod_name) + 1;

            if (mod_name[0] == '/') {
                all_desc = 1;
                ++mod_name;
            }
        } else if (name[0] == '/') {
            all_desc = 1;
            ++name;
        }
        if ((predicate = strchr(name, '['))) {
            predicate[0] = '\0';
            ++predicate;
        }
        if (all_desc && (0 != strcmp(name, ".")) && (0 != strcmp(name, "*"))) {
            /* we do not support "node//node" */
            rc = SR_ERR_UNSUPPORTED;
            goto error;
        } else if (!all_desc && (0 == strcmp(name, "."))) {
            /* we do not support "node/." */
            rc = SR_ERR_UNSUPPORTED;
            goto error;
        }
        if ((0 != strcmp(name, ".") && 0 != strcmp(name, "*") && !sr_find_schema_node_valid_identifier(name, 0))
                || (mod_name && !sr_find_schema_node_valid_identifier(mod_name, 0))) {
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }

        /* last iteration, we are getting results */
        if ((predicate ? predicate : name) + strlen(predicate ? predicate : name) == path_end && ret) {
            last_iter = true;
            *ret = ly_set_new();
            if (0 == strcmp(name, ".")) {
                /* handle "." */
                ly_set_add(*ret, (void *)start, LY_SET_OPT_USEASLIST);
                name[0] = '*';
            }
        }

        node = NULL;
        while ((node = lys_getnext(node, start, module, 0))) {
            /* check input/output */
            if (output && sr_has_parent(node, LYS_INPUT)) {
                continue;
            } else if (!output && sr_has_parent(node, LYS_OUTPUT)) {
                continue;
            }

            /* check module */
            if (mod_name) {
                if (strcmp(mod_name, lys_node_module(node)->name)) {
                    continue;
                }
            } else if (lys_node_module(node) != prev_mod && name[0] != '*') {
                continue;
            }

            /* check name */
            if (name[0] != '*') {
                if (0 == strcmp(node->name, name)) {
                    if (predicate) {
                        tmp_rc = sr_find_schema_node_predicate(node, predicate);
                        if (tmp_rc == -1) {
                            continue;
                        } else if (tmp_rc != SR_ERR_OK) {
                            rc = tmp_rc;
                            goto error;
                        }
                    }
                    if (last_iter && ret) {
                        if (all_desc) {
                            LY_TREE_DFS_BEGIN(node, next, elem) {
                                ly_set_add(*ret, (void *)elem, LY_SET_OPT_USEASLIST);
                                LY_TREE_DFS_END(node, next, elem);
                            }
                        } else {
                            ly_set_add(*ret, (void *)node, LY_SET_OPT_USEASLIST);
                        }
                    }
                    break;
                }
            } else {
                if (last_iter && ret) {
                    if (all_desc) {
                        LY_TREE_DFS_BEGIN(node, next, elem) {
                            ly_set_add(*ret, (void *)elem, LY_SET_OPT_USEASLIST);
                            LY_TREE_DFS_END(node, next, elem);
                        }
                    } else {
                        ly_set_add(*ret, (void *)node, LY_SET_OPT_USEASLIST);
                    }
                }
            }
        }
        if (NULL == node && name[0] != '*') {
            rc = SR_ERR_BAD_ELEMENT;
            goto error;
        }

        if (last_iter) {
            /* finished */
            break;
        }

        /* next iteration */
        start = node;
        prev_mod = lys_node_module(start);
        if (predicate) {
            name = predicate + strlen(predicate) + 1;
        } else {
            name += strlen(name) + 1;
        }
    }

    free(path);
    return rc;

error:
    if (ret) {
        ly_set_free(*ret);
    }
    free(path);
    return rc;
}

char *
op_get_srval(struct ly_ctx *ctx, const sr_val_t *value, char *buf)
{
    struct lys_node_leaf *sleaf;
    const struct lys_module *module;
    char *mod_name;
    struct ly_set *set;
    int rc;

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
        mod_name = strndup(value->xpath + 1, strchr(value->xpath + 1, ':') - (value->xpath + 1));
        module = ly_ctx_get_module(ctx, mod_name, NULL);
        free(mod_name);
        if (!module) {
            return NULL;
        }
        rc = sr_find_schema_node(module, NULL, value->xpath, 0, &set);
        if (rc) {
            return NULL;
        }
        sleaf = (struct lys_node_leaf *)set->set.s[0];
        ly_set_free(set);
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

struct nc_server_reply *
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
                module = ly_ctx_get_module_by_ns(ctx, next->ns->value, NULL);
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
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL);
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
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL);
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

            /* this content match node must be present in the final output, so add it as a selection node as well */
            /* TODO optimization: needed only if child is not key and we have a sibling containment/selection node */
            buf_new = malloc(size * sizeof(char));
            if (!buf_new) {
                EMEM;
                goto error;
            }
            memcpy(buf_new, *buf, size * sizeof(char));
            new_size = size;

            new_size = filter_xpath_buf_add_node(ctx, child, elem_module_name, &last_ns, &buf_new, new_size);
            if (!new_size) {
                free(*buf);
                *buf = NULL;
                free(buf_new);
                return 0;
            } else if (new_size < 1) {
                goto error;
            }
            if (op_filter_xpath_add_filter(buf_new, filters, filter_count)) {
                goto error;
            }

            lyxml_free(ctx, child);
        }
    }

    /* that is it, it seems */
    if (!elem->child) {
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

        /* child selection node */
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
            modules[0] = ly_ctx_get_module_by_ns(ctx, next->ns->value, NULL);
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
op_filter_create(struct lyd_node *filter_node, char ***filters, int *filter_count) {
    struct lyd_attr *attr;
    struct lyxml_elem *subtree_filter;
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
            break;
        case LYD_ANYDATA_XML:
            subtree_filter = ((struct lyd_node_anydata *)filter_node)->value.xml;
            break;
        default:
            /* filter cannot be parsed as lyd_node tree */
            return -1;
        }
        if (!subtree_filter) {
            return -1;
        }

        if (op_filter_build_xpath_from_subtree(np2srv.ly_ctx, subtree_filter, filters, filter_count)) {
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
    struct ly_set *set;
    struct lyd_node *iter;
    unsigned int u = 0;
    char *str;

    str = op_get_srval(np2srv.ly_ctx, sr_val, numstr);
    if (!str) {
        str = "";
    }

    ly_errno = LY_SUCCESS;
    *new_node = lyd_new_path(root, np2srv.ly_ctx, sr_val->xpath, str, 0, LYD_PATH_OPT_UPDATE);
    if (ly_errno) {
        return -1;
    }

    if (*new_node) {
        if (!root) {
            root = *new_node;
        }

        /* propagate default flag */
        if (sr_val->dflt) {
            /* find the actual node supposed to be created */
            set = lyd_find_path(root, sr_val->xpath);
            if (!set) {
                EINT;
                return -1;
            } else if (set->number > 1) {
                /* leaf-list - find the corresponding node for the sr_val according to its value */
                for (u = 0; u < set->number; u++) {
                    if (!strcmp(str, ((struct lyd_node_leaf_list *)set->set.d[u])->value_str)) {
                        break;
                    }
                }
                if (u == set->number) {
                    EINT;
                    return -1;
                }
            } else {
                u = 0;
            }

            if (set->set.d[u] == *new_node) {
                (*new_node)->dflt = 1;
            } else {
                /* go up, back to the top-most created node */
                for (iter = set->set.d[u]; iter != *new_node; iter = iter->parent) {
                    if (iter->schema->nodetype == LYS_CONTAINER && ((struct lys_node_container *)iter->schema)->presence) {
                        /* presence container */
                        break;
                    } else if (iter->schema->nodetype == LYS_LIST && ((struct lys_node_list *)iter->schema)->keys_size) {
                        /* list with keys */
                        break;
                    }
                    iter->dflt = 1;
                }
            }

            ly_set_free(set);
        } else { /* non default node, propagate it to the parents */
            for (iter = (*new_node)->parent; iter && iter->dflt; iter = iter->parent) {
                iter->dflt = 0;
            }
        }
    }

    return 0;
}
