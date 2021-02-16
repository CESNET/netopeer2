/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common routines
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#ifdef NP2SRV_URL_CAPAB
# include <curl/curl.h>

# ifdef CURL_GLOBAL_ACK_EINTR
#  define URL_INIT_FLAGS CURL_GLOBAL_SSL | CURL_GLOBAL_ACK_EINTR
# else
#  define URL_INIT_FLAGS CURL_GLOBAL_SSL
# endif

#endif

#include <libyang/libyang.h>
#include <nc_server.h>

#include "common.h"
#include "log.h"
#include "netconf_acm.h"
#include "netconf_monitoring.h"

struct np2srv np2srv = {.unix_mode = -1, .unix_uid = -1, .unix_gid = -1};

int
np_sleep(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    return nanosleep(&ts, NULL);
}

const char *
np_get_nc_sess_user(sr_session_ctx_t *session)
{
    struct nc_session *nc_sess = NULL;
    uint32_t nc_sid, i;

    nc_sid = sr_session_get_nc_id(session);
    for (i = 0; (nc_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(nc_sess) == nc_sid) {
            break;
        }
    }
    if (!nc_sess) {
        return NULL;
    }

    return nc_session_get_username(nc_sess);
}

void
np2srv_ntf_new_cb(sr_session_ctx_t *UNUSED(session), const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct nc_server_notif *nc_ntf = NULL;
    struct nc_session *ncs = (struct nc_session *)private_data;
    struct lyd_node *ly_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char buf[26], *datetime;

    /* create these notifications, sysrepo only emulates them */
    if (notif_type == SR_EV_NOTIF_REPLAY_COMPLETE) {
        ly_ntf = lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:replayComplete", NULL, 0, 0);
        notif = ly_ntf;
    } else if (notif_type == SR_EV_NOTIF_STOP) {
        ly_ntf = lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:notificationComplete", NULL, 0, 0);
        notif = ly_ntf;
    }

    /* find the top-level node */
    while (notif->parent) {
        notif = notif->parent;
    }

    /* check NACM */
    if (ncac_check_operation(notif, nc_session_get_username(ncs))) {
        goto cleanup;
    }

    /* create the notification object */
    datetime = nc_time2datetime(timestamp, NULL, buf);
    nc_ntf = nc_server_notif_new((struct lyd_node *)notif, datetime, NC_PARAMTYPE_CONST);

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        goto cleanup;
    }
    ncm_session_notification(ncs);

    if (notif_type == SR_EV_NOTIF_STOP) {
        /* subscription finished */
        nc_session_set_notif_status(ncs, 0);
    }

cleanup:
    nc_server_notif_free(nc_ntf);
    lyd_free_withsiblings(ly_ntf);
}

void
np2srv_new_session_cb(const char *UNUSED(client_name), struct nc_session *new_session)
{
    int c;
    sr_val_t *event_data;
    sr_session_ctx_t *sr_sess = NULL;
    const struct lys_module *mod;
    char *host = NULL;

    /* start sysrepo session for every NETCONF session (so that it can be used for notification subscriptions) */
    c = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (c != SR_ERR_OK) {
        ERR("Failed to start a sysrepo session (%s).", sr_strerror(c));
        nc_session_free(new_session, NULL);
        return;
    }
    nc_session_set_data(new_session, sr_sess);
    sr_session_set_nc_id(sr_sess, nc_session_get_id(new_session));
    ncm_session_add(new_session);

    c = 0;
    while ((c < 3) && nc_ps_add_session(np2srv.nc_ps, new_session)) {
        /* presumably timeout, give it a shot 2 times */
        np_sleep(NP2SRV_PS_BACKOFF_SLEEP);
        ++c;
    }

    if (c == 3) {
        /* there is some serious problem in synchronization/system planner */
        EINT;
        goto error;
    }

    if ((mod = ly_ctx_get_module(sr_get_context(np2srv.sr_conn), "ietf-netconf-notifications", NULL, 1))) {
        /* generate ietf-netconf-notification's netconf-session-start event for sysrepo */
        if (nc_session_get_ti(new_session) != NC_TI_UNIX) {
            host = (char *)nc_session_get_host(new_session);
        }
        event_data = calloc(3, sizeof *event_data);
        event_data[0].xpath = "/ietf-netconf-notifications:netconf-session-start/username";
        event_data[0].type = SR_STRING_T;
        event_data[0].data.string_val = (char *)nc_session_get_username(new_session);
        event_data[1].xpath = "/ietf-netconf-notifications:netconf-session-start/session-id";
        event_data[1].type = SR_UINT32_T;
        event_data[1].data.uint32_val = nc_session_get_id(new_session);
        if (host) {
            event_data[2].xpath = "/ietf-netconf-notifications:netconf-session-start/source-host";
            event_data[2].type = SR_STRING_T;
            event_data[2].data.string_val = host;
        }
        c = sr_event_notif_send(np2srv.sr_sess, "/ietf-netconf-notifications:netconf-session-start", event_data, host ? 3 : 2);
        if (c != SR_ERR_OK) {
            WRN("Failed to send a notification (%s).", sr_strerror(c));
        } else {
            VRB("Generated new event (netconf-session-start).");
        }
        free(event_data);
    }

    return;

error:
    ncm_session_del(new_session);
    sr_session_stop(sr_sess);
    nc_session_free(new_session, NULL);
}

#ifdef NP2SRV_URL_CAPAB

int
np2srv_url_setcap(void)
{
    uint32_t i, j;
    char *cpblt;
    int first = 1, cur_prot, sup_prot = 0;
    curl_version_info_data *curl_data;
    const char *url_protocol_str[] = {"scp", "http", "https", "ftp", "sftp", "ftps", "file", NULL};
    const char *main_cpblt = "urn:ietf:params:netconf:capability:url:1.0?scheme=";

    curl_data = curl_version_info(CURLVERSION_NOW);
    for (i = 0; curl_data->protocols[i]; ++i) {
        for (j = 0; url_protocol_str[j]; ++j) {
            if (!strcmp(curl_data->protocols[i], url_protocol_str[j])) {
                sup_prot |= (1 << j);
                break;
            }
        }
    }
    if (!sup_prot) {
        /* no protocols supported */
        return EXIT_SUCCESS;
    }

    /* get max capab string size and allocate it */
    j = strlen(main_cpblt) + 1;
    for (i = 0; url_protocol_str[i]; ++i) {
        j += strlen(url_protocol_str[i]) + 1;
    }
    cpblt = malloc(j);
    if (!cpblt) {
        EMEM;
        return EXIT_FAILURE;
    }

    /* main capability */
    strcpy(cpblt, main_cpblt);

    /* supported protocols */
    for (i = 0, cur_prot = 1; i < (sizeof url_protocol_str / sizeof *url_protocol_str); ++i, cur_prot <<= 1) {
        if (cur_prot & sup_prot) {
            sprintf(cpblt + strlen(cpblt), "%s%s", first ? "" : ",", url_protocol_str[i]);
            first = 0;
        }
    }

    nc_server_set_capability(cpblt);
    free(cpblt);
    return EXIT_SUCCESS;
}

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

struct lyd_node *
op_parse_url(const char *url, int options, int *rc, sr_session_ctx_t *sr_sess)
{
    struct lyd_node *config, *data;
    struct ly_ctx *ly_ctx;
    int fd;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    fd = url_open(url);
    if (fd == -1) {
        *rc = SR_ERR_INVAL_ARG;
        sr_set_error(sr_sess, NULL, "Could not open URL.");
        return NULL;
    }

    /* do not validate the whole context, we just want to load the config anyxml */
    config = lyd_parse_fd(ly_ctx, fd, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_TRUSTED);
    if (ly_errno) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errpath(ly_ctx), ly_errmsg(ly_ctx));
        return NULL;
    }

    data = op_parse_config((struct lyd_node_anydata *)config, options, rc, sr_sess);
    lyd_free_withsiblings(config);
    return data;
}

int
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
        sr_set_error(sr_sess, ly_errpath(ly_ctx), ly_errmsg(ly_ctx));
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
        sr_set_error(sr_sess, NULL, curl_buffer);
        return -1;
    }

    /* cleanup */
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}

#else

int
np2srv_url_setcap(void)
{
    return EXIT_SUCCESS;
}

#endif

struct lyd_node *
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
        sr_set_error(sr_sess, ly_errpath(ly_ctx), ly_errmsg(ly_ctx));
    }

    return root;
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

static int
op_filter_xpath_add_filter(const char *new_filter, int selection, struct np2_filter *filter)
{
    void *mem;

    mem = realloc(filter->filters, (filter->count + 1) * sizeof *filter->filters);
    if (!mem) {
        EMEM;
        return -1;
    }
    filter->filters = mem;
    filter->filters[filter->count].str = strdup(new_filter);
    filter->filters[filter->count].selection = selection;
    ++filter->count;

    return 0;
}

static int
filter_xpath_buf_append_attrs(struct ly_ctx *ctx, const struct lyxml_attr *attr, char **buf, int size)
{
    const struct lys_module *module;
    const struct lyxml_attr *next;
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
filter_xpath_buf_get_content(struct ly_ctx *ctx, const struct lyxml_elem *elem)
{
    const char *start;
    size_t len;
    char *ret;

    /* skip leading and trailing whitespaces */
    for (start = elem->content; isspace(*start); ++start);
    for (len = strlen(start); isspace(start[len - 1]); --len);

    start = lydict_insert(ctx, start, len);

    ly_log_options(0);
    ret = ly_path_xml2json(ctx, start, (struct lyxml_elem *)elem);
    ly_log_options(LY_LOLOG | LY_LOSTORE_LAST);

    if (!ret) {
        ret = strdup(start);
    }
    lydict_remove(ctx, start);

    return ret;
}

/* top-level content node with optional namespace and attributes */
static int
filter_xpath_buf_add_top_content(struct ly_ctx *ctx, const struct lyxml_elem *elem, const char *elem_module_name,
                                 struct np2_filter *filter)
{
    int size;
    char *buf, *content;

    content = filter_xpath_buf_get_content(ctx, elem);

    size = 1 + strlen(elem_module_name) + 1 + strlen(elem->name) + 9 + strlen(content) + 3;
    buf = malloc(size);
    if (!buf) {
        EMEM;
        free(content);
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%s']", elem_module_name, elem->name, content);
    free(content);

    size = filter_xpath_buf_append_attrs(ctx, elem->attr, &buf, size);
    if (!size) {
        free(buf);
        return 0;
    } else if (size < 1) {
        free(buf);
        return -1;
    }

    if (op_filter_xpath_add_filter(buf, 0, filter)) {
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}

/* content node with optional namespace and attributes */
static int
filter_xpath_buf_append_content(struct ly_ctx *ctx, const struct lyxml_elem *elem, const char *elem_module_name,
                                const char *last_ns, char **buf, int size)
{
    const struct lys_module *module;
    int new_size;
    char *buf_new, *content, quot;

    if (!elem_module_name && elem->ns && (elem->ns->value != last_ns)
            && strcmp(elem->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL, 1);
        if (!module) {
            /* not really an error */
            return 0;
        }

        elem_module_name = module->name;
    }

    new_size = size + 1 + (elem_module_name ? strlen(elem_module_name) + 1 : 0) + strlen(elem->name);
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "[%s%s%s", (elem_module_name ? elem_module_name : ""), (elem_module_name ? ":" : ""),
            elem->name);
    size = new_size;

    size = filter_xpath_buf_append_attrs(ctx, elem->attr, buf, size);
    if (size < 1) {
        return size;
    }

    content = filter_xpath_buf_get_content(ctx, elem);

    new_size = size + 2 + strlen(content) + 2;
    buf_new = realloc(*buf, new_size);
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
filter_xpath_buf_append_node(struct ly_ctx *ctx, const struct lyxml_elem *elem, const char *elem_module_name,
                             const char *last_ns, char **buf, int size)
{
    const struct lys_module *module;
    int new_size;
    char *buf_new;

    if (!elem_module_name && elem->ns && (elem->ns->value != last_ns)
            && strcmp(elem->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        module = ly_ctx_get_module_by_ns(ctx, elem->ns->value, NULL, 1);
        if (!module) {
            /* not really an error */
            return 0;
        }

        elem_module_name = module->name;
    }

    new_size = size + 1 + (elem_module_name ? strlen(elem_module_name) + 1 : 0) + strlen(elem->name);
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "/%s%s%s", (elem_module_name ? elem_module_name : ""), (elem_module_name ? ":" : ""),
            elem->name);
    size = new_size;

    size = filter_xpath_buf_append_attrs(ctx, elem->attr, buf, size);
    return size;
}

static int
filter_xpath_buf_add_r(struct ly_ctx *ctx, const struct lyxml_elem *elem, const char *elem_module_name,
                     const char *last_ns, char **buf, int size, struct np2_filter *filter)
{
    struct lyxml_elem *child;
    int s, only_content_match;

    /* containment node or selection node */
    size = filter_xpath_buf_append_node(ctx, elem, elem_module_name, last_ns, buf, size);
    if (size < 1) {
        return size;
    }

    if (!elem->child) {
        /* just a selection node */
        if (op_filter_xpath_add_filter(*buf, 1, filter)) {
            return -1;
        }
        return 0;
    }

    /* append child content match nodes */
    only_content_match = 1;
    LY_TREE_FOR(elem->child, child) {
        if (!child->child && child->content && !strws(child->content)) {
            /* there is a content filter, append all of them */
            size = filter_xpath_buf_append_content(ctx, child, elem_module_name, last_ns, buf, size);
            if (size < 1) {
                return size;
            }
        } else {
            only_content_match = 0;
        }
    }

    if (only_content_match) {
        /* there are only content match nodes so we retrieve this filter as a subtree */
        if (op_filter_xpath_add_filter(*buf, 0, filter)) {
            return -1;
        }

        return 0;
    }
    /* else there are some other filters so the current filter just restricts all the nested ones, is not retrieved
     * as a standalone subtree */

    /* that is it for this filter depth, now we branch with every new node */
    LY_TREE_FOR(elem->child, child) {
        if (child->child) {
            /* child containment node */
            filter_xpath_buf_add_r(ctx, child, NULL, last_ns, buf, size, filter);
        } else if (!child->content || strws(child->content)) {
            /* child selection node */
            s = filter_xpath_buf_append_node(ctx, child, NULL, last_ns, buf, size);
            if (!s) {
                continue;
            } else if (s < 0) {
                return s;
            }

            if (op_filter_xpath_add_filter(*buf, 1, filter)) {
                return -1;
            }
        } /* else child content node, already handled */
    }

    return 0;
}

static int
op_filter_build_xpath_from_subtree(struct ly_ctx *ctx, const struct lyxml_elem *elem, struct np2_filter *filter)
{
    const struct lys_module *module, **modules, **modules_new;
    const struct lys_node *node;
    const struct lyxml_elem *iter;
    char *buf = NULL;
    uint32_t i, module_count;

    LY_TREE_FOR(elem, iter) {
        /* first filter node, it must always have a namespace */
        modules = NULL;
        module_count = 0;
        if (iter->ns && strcmp(iter->ns->value, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
            modules = malloc(sizeof *modules);
            if (!modules) {
                EMEM;
                goto error;
            }
            module_count = 1;
            modules[0] = ly_ctx_get_module_by_ns(ctx, iter->ns->value, NULL, 1);
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
                    if (!strcmp(node->name, iter->name)) {
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

        for (i = 0; i < module_count; ++i) {
            if (!iter->child && iter->content && !strws(iter->content)) {
                /* special case of top-level content match node */
                if (filter_xpath_buf_add_top_content(ctx, iter, modules[i]->name, filter)) {
                    goto error;
                }
            } else {
                /* containment or selection node */
                if (filter_xpath_buf_add_r(ctx, iter, modules[i]->name, modules[i]->ns, &buf, 1, filter)) {
                    goto error;
                }
            }
        }
        free(modules);
    }

    free(buf);
    return 0;

error:
    free(buf);
    free(modules);
    op_filter_erase(filter);
    return -1;
}

void
op_filter_erase(struct np2_filter *filter)
{
    int i;

    for (i = 0; i < filter->count; ++i) {
        free(filter->filters[i].str);
    }
    free(filter->filters);
    filter->filters = NULL;
    filter->count = 0;
}

int
op_filter_create(struct lyd_node *filter_node, struct np2_filter *filter)
{
    struct lyd_attr *attr;
    struct lyxml_elem *subtree_filter;
    struct ly_ctx *ly_ctx;
    int free_filter, ret;

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

        ret = op_filter_build_xpath_from_subtree(ly_ctx, subtree_filter, filter);
        if (free_filter) {
            lyxml_free_withsiblings(ly_ctx, subtree_filter);
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
        if (op_filter_xpath_add_filter(attr->value_str, 1, filter)) {
            return -1;
        }
    }

    return 0;
}

int
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_oper_options_t get_opts,
        const struct np2_filter *filter, struct lyd_node **data)
{
    const sr_error_info_t *err_info;
    struct lyd_node *node;
    int i, rc;

    for (i = 0; i < filter->count; ++i) {
        /* get the selected data */
        rc = sr_get_data(session, filter->filters[i].str, max_depth, np2srv.sr_timeout, get_opts, &node);
        if (rc) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filter->filters[i].str, sr_strerror(rc));
            sr_get_error(session, &err_info);
            sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
            return rc;
        }

        /* merge */
        if (!*data) {
            *data = node;
        } else if (node && lyd_merge(*data, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
            lyd_free_withsiblings(node);
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

int
op_filter_data_filter(struct lyd_node **data, const struct np2_filter *filter, int with_selection,
        struct lyd_node **filtered_data)
{
    struct lyd_node *node;
    int i, has_filter = 0, rc = SR_ERR_OK;
    struct ly_set *set = NULL;
    uint32_t j;

    if (!*data) {
        /* nothing to filter */
        return SR_ERR_OK;
    }

    for (i = 0; i < filter->count; i++) {
        if (!with_selection && filter->filters[i].selection) {
            continue;
        }
        has_filter = 1;

        /* apply content (or even selection) filter */
        set = lyd_find_path(*data, filter->filters[i].str);
        if (!set) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        for (j = 0; j < set->number; ++j) {
            node = lyd_dup(set->set.d[j], LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_WITH_KEYS |
                    LYD_DUP_OPT_WITH_WHEN);
            if (!node) {
                rc = SR_ERR_LY;
                goto cleanup;
            }

            /* always find parent */
            while (node->parent) {
                node = node->parent;
            }

            /* merge */
            if (!*filtered_data) {
                *filtered_data = node;
            } else if (node && lyd_merge(*filtered_data, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                lyd_free_withsiblings(node);
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        ly_set_free(set);
        set = NULL;
    }

    if (!has_filter) {
        /* no filter, just use all the data */
        *filtered_data = *data;
        *data = NULL;
    }

cleanup:
    ly_set_free(set);
    return rc;
}
