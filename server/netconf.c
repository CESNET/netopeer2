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
#include <ctype.h>
#include <pthread.h>
#include <errno.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "common.h"

#ifdef NP2SRV_URL_CAPAB
# include <curl/curl.h>

# ifdef CURL_GLOBAL_ACK_EINTR
#  define URL_INIT_FLAGS CURL_GLOBAL_SSL | CURL_GLOBAL_ACK_EINTR
# else
#  define URL_INIT_FLAGS CURL_GLOBAL_SSL
# endif

#endif

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

static int
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

static char *
filter_xpath_buf_get_content(struct ly_ctx *ctx, struct lyxml_elem *elem)
{
    const char *start;
    size_t len;
    char *ret;

    /* skip leading and trailing whitespaces */
    for (start = elem->content; isspace(*start); ++start);
    for (len = strlen(start); isspace(start[len - 1]); --len);

    start = lydict_insert(ctx, start, len);

    ly_log_options(0);
    ret = ly_path_xml2json(ctx, start, elem);
    ly_log_options(LY_LOLOG | LY_LOSTORE_LAST);

    if (!ret) {
        ret = strdup(start);
    }
    lydict_remove(ctx, start);

    return ret;
}

/* top-level content node with optional namespace and attributes */
static int
filter_xpath_buf_add_top_content(struct ly_ctx *ctx, struct lyxml_elem *elem, const char *elem_module_name,
                                char ***filters, int *filter_count)
{
    int size;
    char *buf, *content;

    content = filter_xpath_buf_get_content(ctx, elem);

    size = 1 + strlen(elem_module_name) + 1 + strlen(elem->name) + 9 + strlen(content) + 3;
    buf = malloc(size * sizeof(char));
    if (!buf) {
        EMEM;
        free(content);
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%s']", elem_module_name, elem->name, content);
    free(content);

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
    int new_size;
    char *buf_new, *content, quot;

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

    content = filter_xpath_buf_get_content(ctx, elem);

    new_size = size + 2 + strlen(content) + 2;
    buf_new = realloc(*buf, new_size * sizeof(char));
    if (!buf_new) {
        EMEM;
        free(content);
        return -1;
    }
    *buf = buf_new;

    if (strchr(content, '\'')) {
        quot = '\"';
    } else {
        quot = '\'';
    }
    sprintf((*buf) + (size - 1), "=%c%s%c]", quot, content, quot);

    free(content);
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

static int
op_filter_create(struct lyd_node *filter_node, char ***filters, int *filter_count)
{
    struct lyd_attr *attr;
    struct lyxml_elem *subtree_filter;
    struct ly_ctx *ly_ctx;
    int free_filter, ret;
    char *path;

    ly_ctx = lyd_node_module(filter_node)->ctx;

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
            subtree_filter = lyxml_parse_mem(ly_ctx, ((struct lyd_node_anydata *)filter_node)->value.str, LYXML_PARSE_MULTIROOT);
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

        ret = op_filter_build_xpath_from_subtree(ly_ctx, subtree_filter, filters, filter_count);
        if (free_filter) {
            lyxml_free(ly_ctx, subtree_filter);
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

static struct lyd_node *
op_parse_config(struct lyd_node_anydata *config, int options, int *rc, sr_session_ctx_t *sr_sess)
{
    struct ly_ctx *ly_ctx;
    struct lyd_node *root = NULL;

    ly_ctx = lyd_node_module((struct lyd_node *)config)->ctx;

    switch (config->value_type) {
    case LYD_ANYDATA_CONSTSTRING:
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_SXML:
        root = lyd_parse_mem(ly_ctx, config->value.str, LYD_XML, options);
        break;
    case LYD_ANYDATA_DATATREE:
        root = lyd_dup_withsiblings(config->value.tree, LYD_DUP_OPT_RECURSIVE);
        break;
    case LYD_ANYDATA_XML:
        root = lyd_parse_xml(ly_ctx, &config->value.xml, options);
        break;
    case LYD_ANYDATA_LYB:
        root = lyd_parse_mem(ly_ctx, config->value.mem, LYD_LYB, options);
        break;
    case LYD_ANYDATA_JSON:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_LYBD:
        EINT;
        *rc = SR_ERR_INTERNAL;
        return NULL;
    }
    if (ly_errno != LY_SUCCESS) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errmsg(ly_ctx), ly_errpath(ly_ctx));
    }

    return root;
}

#ifdef NP2SRV_URL_CAPAB

struct np2srv_url_mem {
    char *memory;
    size_t size;
};

static size_t
url_writedata(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int *fd = (int *)userdata;
    return write(*fd, ptr, size * nmemb);
}

static size_t
url_readdata(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t copied = 0, aux_size = size * nmemb;
    struct np2srv_url_mem *data = (struct np2srv_url_mem *)userdata;

    if (aux_size < 1 || data->size == 0) {
        /* no space or nothing left */
        return 0;
    }

    copied = (data->size > aux_size) ? aux_size : data->size;
    memcpy(ptr, data->memory, copied);
    data->memory = data->memory + copied; /* move pointer */
    data->size = data->size - copied; /* decrease amount of data left */
    return copied;
}

static int
url_open(const char *url)
{
    CURL *curl;
    CURLcode res;
    char curl_buffer[CURL_ERROR_SIZE];
    char url_tmp_name[(sizeof P_tmpdir / sizeof(char)) + 15] = P_tmpdir "/np2srv-XXXXXX";
    int url_tmpfile;

    /* prepare temporary file ... */
    if ((url_tmpfile = mkstemp(url_tmp_name)) < 0) {
        ERR("Failed to create a temporary file (%s).", strerror(errno));
        return -1;
    }

    /* and hide it from the file system */
    unlink(url_tmp_name);

    DBG("Getting file from URL: %s (via curl)", url);

    /* set up libcurl */
    curl_global_init(URL_INIT_FLAGS);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, url_writedata);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &url_tmpfile);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_buffer);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        ERR("Failed to download data (curl: %s).", curl_buffer);
        close(url_tmpfile);
        url_tmpfile = -1;
    } else {
        /* move back to the beginning of the output file */
        lseek(url_tmpfile, 0, SEEK_SET);
    }

    /* cleanup */
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return url_tmpfile;
}

static struct lyd_node *
op_parse_url(const char *url, int options, int *rc, sr_session_ctx_t *sr_sess)
{
    struct lyd_node *config, *data;
    struct ly_ctx *ly_ctx;
    int fd;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    fd = url_open(url);
    if (fd == -1) {
        *rc = SR_ERR_INVAL_ARG;
        sr_set_error(sr_sess, "Could not open URL.", NULL);
        return NULL;
    }

    config = lyd_parse_fd(ly_ctx, fd, LYD_XML, options);
    if (ly_errno) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errmsg(ly_ctx), ly_errpath(ly_ctx));
        return NULL;
    }

    data = op_parse_config((struct lyd_node_anydata *)config, options, rc, sr_sess);
    lyd_free_withsiblings(config);
    return data;
}

static int
op_export_url(const char *url, struct lyd_node *data, int options, int *rc, sr_session_ctx_t *sr_sess)
{
    CURL *curl;
    CURLcode res;
    struct np2srv_url_mem mem_data;
    char curl_buffer[CURL_ERROR_SIZE], *str_data;
    struct lyd_node *config;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    config = lyd_new_path(NULL, ly_ctx, "/ietf-netconf:config", data, data ? LYD_ANYDATA_DATATREE : 0, 0);
    if (!config) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errmsg(ly_ctx), ly_errpath(ly_ctx));
        return -1;
    }

    lyd_print_mem(&str_data, config, LYD_XML, options);
    /* do not free data */
    ((struct lyd_node_anydata *)config)->value.tree = NULL;
    lyd_free_withsiblings(config);

    DBG("Uploading file to URL: %s (via curl)", url);

    /* fill the structure for libcurl's READFUNCTION */
    mem_data.memory = str_data;
    mem_data.size = strlen(str_data);

    /* set up libcurl */
    curl_global_init(URL_INIT_FLAGS);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, &mem_data);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, url_readdata);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, (long)mem_data.size);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_buffer);
    res = curl_easy_perform(curl);
    free(str_data);

    if (res != CURLE_OK) {
        ERR("Failed to upload data (curl: %s).", curl_buffer);
        *rc = SR_ERR_SYS;
        sr_set_error(sr_sess, curl_buffer, NULL);
        return -1;
    }

    /* cleanup */
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}

#endif

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
        rc = sr_get_data(session, filters[i], &node);
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
        ds = SR_DS_STATE;
        goto get_sr_data;
    }

    /* perform correct NACM filtering */
    ncac_check_data_read_filter(&data_get, sr_session_get_user(session));

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
        sr_set_error(session, "URL not supported.", NULL);
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
        rc = sr_apply_changes(session);
    } else {
        assert(!strcmp(testop, "test-only"));
        rc = sr_validate(session);
    }
    if (rc != SR_ERR_OK) {
        sr_get_error(session, &err_info);
        sr_set_error(session, err_info->err[0].message, err_info->err[0].xpath);
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
    sr_datastore_t tds, sds;
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
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            tds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            tds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            tds = SR_DS_CANDIDATE;
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
            ly_set_free(nodeset);
            rc = SR_ERR_UNSUPPORTED;
            sr_set_error(session, "URL not supported.", NULL);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    nodeset = lyd_find_path(input, "source/*");
    if (nodeset->number) {
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
            sr_set_error(session, "URL not supported.", NULL);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    /* NACM checks */
    if (!config && (tds != SR_DS_STARTUP) && (sds != SR_DS_RUNNING)) {
        /* get source datastore data and filter them */
        sr_session_switch_ds(session, sds);
        rc = sr_get_data(session, "/*", &config);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
        ncac_check_data_read_filter(&config, sr_session_get_user(session));
    }

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
        rc = sr_replace_config(session, NULL, config, tds);
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
    sr_datastore_t ds;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    /* get know which datastore is affected */
    nodeset = lyd_find_path(input, "target/*");
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
            ly_set_free(nodeset);
            rc = SR_ERR_UNSUPPORTED;
            sr_set_error(session, "URL not supported.", NULL);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

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
        rc = sr_replace_config(session, NULL, NULL, ds);
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
        sr_set_error(session, "It is forbidden to kill own session.", NULL);
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, "Session with the specified \"session-id\" not found.", NULL);
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

    /* sysrepo API */
    rc = sr_copy_config(session, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING);
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

    /* sysrepo API */
    rc = sr_copy_config(session, NULL, SR_DS_RUNNING, SR_DS_CANDIDATE);
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
            sr_set_error(session, "URL not supported.", NULL);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    if (!config) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(session, ds);

        rc = sr_validate(session);
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
    struct lys_node *root, *next, *elem;
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
                        rc = sr_event_notif_subscribe_tree(session, ly_mod->name, xp, start, stop, np2srv_ntf_new_cb,
                                ncs, np2srv.sr_notif_sub ? SR_SUBSCR_CTX_REUSE : 0, &np2srv.sr_notif_sub);
                        break;
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
        rc = sr_event_notif_subscribe_tree(session, stream, xp, start, stop, np2srv_ntf_new_cb, ncs,
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
