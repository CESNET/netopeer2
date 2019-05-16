/**
 * @file operations.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Basic NETCONF operations
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
op_parse_config(struct lyd_node_anydata *config, int options, struct nc_server_reply **ereply)
{
    struct nc_server_error *e;
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
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        *ereply = nc_server_reply_err(e);
        return NULL;
    }
    if (ly_errno != LY_SUCCESS) {
        *ereply = nc_server_reply_err(nc_err_libyang(ly_ctx));
    }

    return root;
}

static struct nc_server_reply *
op_sr_err_reply(struct nc_server_reply *reply, sr_session_ctx_t *session)
{
    const sr_error_info_t *err_info;
    struct nc_server_error *e = NULL;
    const char *ptr;
    size_t i;

    /* get all sysrepo errors connected with the last sysrepo operation */
    sr_get_error(session, &err_info);
    for (i = 0; i < err_info->err_count; ++i) {
        switch (err_info->err_code) {
        case SR_ERR_LOCKED:
            ptr = strstr(err_info->err[i].message, "NC SID ");
            assert(ptr);
            ptr += 7;
            e = nc_err(NC_ERR_LOCK_DENIED, atoi(ptr));
            nc_err_set_msg(e, err_info->err[i].message, "en");
            break;
        case SR_ERR_UNAUTHORIZED:
            e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
            nc_err_set_msg(e, err_info->err[i].message, "en");
            if (err_info->err[i].xpath) {
                nc_err_set_path(e, err_info->err[i].xpath);
            }
            break;
        case SR_ERR_VALIDATION_FAILED:
            if (!strncmp(err_info->err[i].message, "When condition", 14)) {
                assert(err_info->err[i].xpath);
                e = nc_err(NC_ERR_UNKNOWN_ELEM, NC_ERR_TYPE_APP, err_info->err[i].xpath);
                nc_err_set_msg(e, err_info->err[i].message, "en");
                break;
            }
            /* fallthrough */
        default:
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, err_info->err[i].message, "en");
            if (err_info->err[i].xpath) {
                nc_err_set_path(e, err_info->err[i].xpath);
            }
            break;
        }

        if (reply) {
            nc_server_reply_add_err(reply, e);
        } else {
            reply = nc_server_reply_err(e);
        }
        e = NULL;
    }

    return reply;
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
op_parse_url(const char *url, int options, struct nc_server_reply **ereply)
{
    struct lyd_node *config, *data;
    struct nc_server_error *e;
    struct ly_ctx *ly_ctx;
    int fd;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    fd = url_open(url);
    if (fd == -1) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, "Could not open URL.", "en");
        *ereply = nc_server_reply_err(e);
        return NULL;
    }

    config = lyd_parse_fd(ly_ctx, fd, LYD_XML, options);
    if (ly_errno) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, ly_errmsg(ly_ctx), "en");
        *ereply = nc_server_reply_err(e);
        return NULL;
    }

    data = op_parse_config((struct lyd_node_anydata *)config, options, ereply);
    lyd_free_withsiblings(config);
    return data;
}

static int
op_export_url(const char *url, struct lyd_node *data, int options, struct nc_server_reply **ereply)
{
    CURL *curl;
    CURLcode res;
    struct np2srv_url_mem mem_data;
    char curl_buffer[CURL_ERROR_SIZE], *str_data;
    struct nc_server_error *e;
    struct lyd_node *config;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    config = lyd_new_path(NULL, ly_ctx, "/ietf-netconf:config", data, data ? LYD_ANYDATA_DATATREE : 0, 0);
    if (!config) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, ly_errmsg(ly_ctx), "en");
        *ereply = nc_server_reply_err(e);
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
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, curl_buffer, "en");
        *ereply = nc_server_reply_err(e);
        return -1;
    }

    /* cleanup */
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}

#endif

struct nc_server_reply *
op_get(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *root = NULL, *node, *rpl_rpc = NULL;
    char **filters = NULL;
    int filter_count = 0, i, rc;
    sr_session_ctx_t *sr_sess;
    struct ly_set *nodeset;
    sr_datastore_t ds = 0;
    struct nc_server_error *e;
    struct nc_server_reply *reply = NULL;
    NC_WD_MODE nc_wd;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    if (!strcmp(rpc->schema->name, "get")) {
        /* get running data first */
        ds = SR_DS_RUNNING;
    } else { /* get-config */
        nodeset = lyd_find_path(rpc, "source/*");
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
    nodeset = lyd_find_path(rpc, "filter");
    if (nodeset->number) {
        node = nodeset->set.d[0];
        ly_set_free(nodeset);
        if (op_filter_create(node, &filters, &filter_count)) {
            goto cleanup;
        }
    } else {
        ly_set_free(nodeset);

        filters = malloc(sizeof *filters);
        if (!filters) {
            EMEM;
            goto cleanup;
        }
        filter_count = 1;
        filters[0] = strdup("/*");
        if (!filters[0]) {
            EMEM;
            goto cleanup;
        }
    }

    /* get with-defaults mode */
    nodeset = lyd_find_path(rpc, "ietf-netconf-with-defaults:with-defaults");
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
    sr_session_switch_ds(sr_sess, ds);

    /*
     * create the data tree for the data reply
     */
    for (i = 0; i < filter_count; i++) {
        rc = sr_get_data(sr_sess, filters[i], &node);
        if (rc != SR_ERR_OK) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filters[i], sr_strerror(rc));
            goto cleanup;
        }

        if (!root) {
            root = node;
        } else {
            if (lyd_merge(root, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                goto cleanup;
            }
        }
    }

    if (!strcmp(rpc->schema->name, "get")) {
        assert(ds == SR_DS_RUNNING);

        /* we have running data, now append state data */
        ds = SR_DS_STATE;
        goto get_sr_data;
    }

    /* build RPC Reply */
    rpl_rpc = lyd_dup(rpc, 0);
    if (!rpl_rpc) {
        goto cleanup;
    }
    if (!lyd_new_output_anydata(rpl_rpc, NULL, "data", root, LYD_ANYDATA_DATATREE)) {
        goto cleanup;
    }
    root = NULL;
    if (lyd_validate(&rpl_rpc, LYD_OPT_RPCREPLY, NULL)) {
        EINT;
        goto cleanup;
    }

    /* success */
    reply = nc_server_reply_data(rpl_rpc, nc_wd, NC_PARAMTYPE_FREE);
    rpl_rpc = NULL;

cleanup:
    if (!reply) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        reply = nc_server_reply_err(e);
    }

    for (i = 0; i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);

    lyd_free_withsiblings(rpl_rpc);
    lyd_free_withsiblings(root);
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_un_lock(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    struct nc_server_reply *reply = NULL;
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(rpc, "target/*");
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
    sr_session_switch_ds(sr_sess, ds);

    /* sysrepo API */
    if (!strcmp(rpc->schema->name, "lock")) {
        rc = sr_lock(sr_sess, NULL);
    } else if (!strcmp(rpc->schema->name, "unlock")) {
        rc = sr_unlock(sr_sess, NULL);
    }
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_editconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    struct lyd_node *config = NULL;
    struct nc_server_reply *reply = NULL;
    const char *str, *defop = "merge", *testop = "test-then-set";
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(rpc, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset);

    /* default-operation */
    nodeset = lyd_find_path(rpc, "default-operation");
    if (nodeset->number) {
        defop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
    }
    ly_set_free(nodeset);

    /* test-option */
    nodeset = lyd_find_path(rpc, "test-option");
    if (nodeset->number) {
        testop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }
    ly_set_free(nodeset);

    /* error-option */
    nodeset = lyd_find_path(rpc, "error-option");
    if (nodeset->number) {
        str = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (strcmp(str, "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", str);
        }
    }
    ly_set_free(nodeset);

    /* config */
    nodeset = lyd_find_path(rpc, "config | url");
    if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_EDIT | LYD_OPT_STRICT, &reply);
        if (reply) {
            ly_set_free(nodeset);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                LYD_OPT_EDIT | LYD_OPT_STRICT, &reply);
        if (reply) {
            ly_set_free(nodeset);
            goto cleanup;
        }
#else
        ly_set_free(nodeset);
        struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, "URL not supported.", "en");
        reply = nc_server_reply_err(e);
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* update sysrepo session datastore */
    sr_session_switch_ds(sr_sess, ds);

    /* sysrepo API */
    rc = sr_edit_batch(sr_sess, config, defop);
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    if (!strcmp(testop, "test-then-set")) {
        rc = sr_apply_changes(sr_sess);
    } else {
        assert(!strcmp(testop, "test-only"));
        rc = sr_validate(sr_sess);
    }
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    lyd_free_withsiblings(config);
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_copyconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    sr_datastore_t tds, sds;
    struct ly_set *nodeset;
    struct lyd_node *config = NULL;
    struct nc_server_reply *reply = NULL;
    int rc;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node_leaf_list *leaf;
    const char *trg_url = NULL;
    int lyp_wd_flag;
#endif

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get know which datastores are affected */
    nodeset = lyd_find_path(rpc, "target/*");
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
            struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "URL not supported.", "en");
            reply = nc_server_reply_err(e);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    nodeset = lyd_find_path(rpc, "source/*");
    /* invalid DS */
    sds = SR_DS_OPERATIONAL;
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            sds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            sds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            sds = SR_DS_CANDIDATE;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
            config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &reply);
            if (reply) {
                ly_set_free(nodeset);
                goto cleanup;
            }
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                    LYD_OPT_CONFIG | LYD_OPT_STRICT, &reply);
            if (reply) {
                ly_set_free(nodeset);
                goto cleanup;
            }
#else
            ly_set_free(nodeset);
            struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "URL not supported.", "en");
            reply = nc_server_reply_err(e);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* we need with-defaults flag in this case */
        nodeset = lyd_find_path(rpc, "ietf-netconf-with-defaults:with-defaults");
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

        if (sds != SR_DS_OPERATIONAL) {
            /* get this datastore content from sysrepo */
            sr_session_switch_ds(sr_sess, sds);
            rc = sr_get_data(sr_sess, "/*", &config);
            if (rc != SR_ERR_OK) {
                reply = op_sr_err_reply(reply, sr_sess);
                goto cleanup;
            }
        }
        if (op_export_url(trg_url, config, LYP_FORMAT | LYP_WITHSIBLINGS | lyp_wd_flag, &reply)) {
            goto cleanup;
        }
    } else
#endif
    {
        if (sds == SR_DS_OPERATIONAL) {
            rc = sr_replace_config(sr_sess, NULL, config, tds);
        } else {
            rc = sr_copy_config(sr_sess, NULL, sds, tds);
        }
        if (rc != SR_ERR_OK) {
            reply = op_sr_err_reply(reply, sr_sess);
            goto cleanup;
        }
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    lyd_free_withsiblings(config);
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_deleteconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    sr_datastore_t ds;
    struct ly_set *nodeset;
    struct nc_server_reply *reply = NULL;
    int rc;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get know which datastore is affected */
    nodeset = lyd_find_path(rpc, "target/*");
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
            ly_set_free(nodeset);
            struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "URL not supported.", "en");
            reply = nc_server_reply_err(e);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        config = op_parse_url(trg_url, LYD_OPT_CONFIG | LYD_OPT_STRICT, &reply);
        if (reply) {
            struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "URL does not appear to contain a valid config.", "en");
            nc_server_reply_add_err(reply, e);
            goto cleanup;
        }
        lyd_free_withsiblings(config);

        /* upload empty config */
        if (op_export_url(trg_url, NULL, 0, &reply)) {
            goto cleanup;
        }
    } else
#endif
    {
        rc = sr_replace_config(sr_sess, NULL, NULL, ds);
        if (rc != SR_ERR_OK) {
            reply = op_sr_err_reply(reply, sr_sess);
            goto cleanup;
        }
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_validate(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    sr_datastore_t ds;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset;
    struct nc_server_reply *reply = NULL;
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* get know which datastore is affected */
    nodeset = lyd_find_path(rpc, "source/*");
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            ds = SR_DS_CANDIDATE;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
            /* config is also validated now */
            config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &reply);
            if (reply) {
                ly_set_free(nodeset);
                goto cleanup;
            }
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            /* config is also validated now */
            config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                    LYD_OPT_CONFIG | LYD_OPT_STRICT, &reply);
            if (reply) {
                ly_set_free(nodeset);
                goto cleanup;
            }
#else
            ly_set_free(nodeset);
            struct nc_server_error *e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "URL not supported.", "en");
            reply = nc_server_reply_err(e);
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    if (!config) {
        /* update sysrepo session datastore */
        sr_session_switch_ds(sr_sess, ds);

        /* does not do anything, it is always valid, but whatever */
        rc = sr_validate(sr_sess);
        if (rc != SR_ERR_OK) {
            reply = op_sr_err_reply(reply, sr_sess);
            goto cleanup;
        }
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    lyd_free_withsiblings(config);
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_kill(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct nc_session *kill_sess;
    struct ly_set *nodeset;
    struct nc_server_error *e;
    struct nc_server_reply *reply = NULL;
    uint32_t kill_sid, i;

    nodeset = lyd_find_path(rpc, "session-id");
    kill_sid = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value.uint32;
    ly_set_free(nodeset);

    if (kill_sid == nc_session_get_id(ncs)) {
        e = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, "It is forbidden to kill own session.", "en");
        reply = nc_server_reply_err(e);
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        e = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, "Session with the specified \"session-id\" not found.", "en");
        reply = nc_server_reply_err(e);
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, nc_session_get_id(ncs));

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    return reply;
}

struct nc_server_reply *
op_commit(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    struct nc_server_reply *reply = NULL;
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* sysrepo API */
    rc = sr_copy_config(sr_sess, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING);
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    sr_session_stop(sr_sess);
    return reply;
}

struct nc_server_reply *
op_discardchanges(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    struct nc_server_reply *reply = NULL;
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* sysrepo API */
    rc = sr_copy_config(sr_sess, NULL, SR_DS_RUNNING, SR_DS_CANDIDATE);
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    /* build positive RPC Reply */
    reply = nc_server_reply_ok();

cleanup:
    sr_session_stop(sr_sess);
    return reply;
}


struct nc_server_reply *
op_generic(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess;
    struct nc_server_reply *reply = NULL;
    struct lyd_node *output, *child = NULL;
    NC_WD_MODE nc_wd;
    int rc;

    /* create temporary session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    rc = sr_session_set_user(sr_sess, nc_session_get_username(ncs));
    if (rc != SR_ERR_OK) {
        ERR("Failed to set user of a SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* sysrepo API */
    rc = sr_rpc_send_tree(sr_sess, rpc, &output);
    if (rc != SR_ERR_OK) {
        reply = op_sr_err_reply(reply, sr_sess);
        goto cleanup;
    }

    /* build RPC Reply */
    if (output) {
        LY_TREE_FOR(output->child, child) {
            if (!child->dflt) {
                break;
            }
        }
    }
    if (child) {
        nc_server_get_capab_withdefaults(&nc_wd, NULL);
        reply = nc_server_reply_data(output, nc_wd, NC_PARAMTYPE_FREE);
    } else {
        lyd_free_withsiblings(output);
        reply = nc_server_reply_ok();
    }

cleanup:
    sr_session_stop(sr_sess);
    return reply;
}
