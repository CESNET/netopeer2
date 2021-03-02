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

#include <assert.h>
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

    nc_sid = sr_session_get_event_nc_id(session);
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

sr_session_ctx_t *
np_get_user_sess(sr_session_ctx_t *ev_sess)
{
    struct nc_session *nc_sess = NULL;
    uint32_t nc_sid, i;

    nc_sid = sr_session_get_event_nc_id(ev_sess);
    for (i = 0; (nc_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(nc_sess) == nc_sid) {
            break;
        }
    }
    if (!nc_sess) {
        return NULL;
    }

    return nc_session_get_data(nc_sess);
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
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:replayComplete", NULL, 0, &ly_ntf);
        notif = ly_ntf;
    } else if (notif_type == SR_EV_NOTIF_STOP) {
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/nc-notifications:notificationComplete", NULL, 0, &ly_ntf);
        notif = ly_ntf;
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
    lyd_free_all(ly_ntf);
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

    if ((mod = ly_ctx_get_module_implemented(sr_get_context(np2srv.sr_conn), "ietf-netconf-notifications"))) {
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
op_parse_url(const char *url, uint32_t parse_options, int *rc, sr_session_ctx_t *sr_sess)
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
    if (lyd_parse_data_fd(ly_ctx, fd, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ | LYD_PARSE_NO_STATE, 0, &config)) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errpath(ly_ctx), ly_errmsg(ly_ctx));
        return NULL;
    }

    data = op_parse_config((struct lyd_node_any *)config, parse_options, rc, sr_sess);
    lyd_free_siblings(config);
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

    /* print the config as expected by the other end */
    if (lyd_new_path2(NULL, ly_ctx, "/ietf-netconf:config", data, data ? LYD_ANYDATA_DATATREE : 0, 0, NULL, &config)) {
        *rc = SR_ERR_LY;
        sr_set_error(sr_sess, ly_errpath(ly_ctx), ly_errmsg(ly_ctx));
        return -1;
    }
    lyd_print_mem(&str_data, config, LYD_XML, options);

    /* do not free data */
    ((struct lyd_node_any *)config)->value.tree = NULL;
    lyd_free_tree(config);

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
op_parse_config(struct lyd_node_any *config, uint32_t parse_options, int *rc, sr_session_ctx_t *sr_sess)
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *root = NULL;
    LY_ERR lyrc;

    ly_ctx = LYD_CTX(config);

    switch (config->value_type) {
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_XML:
        lyrc = lyd_parse_data_mem(ly_ctx, config->value.str, LYD_XML, parse_options, 0, &root);
        break;
    case LYD_ANYDATA_DATATREE:
        lyrc = lyd_dup_siblings(config->value.tree, NULL, LYD_DUP_RECURSIVE, &root);
        break;
    case LYD_ANYDATA_LYB:
        lyrc = lyd_parse_data_mem(ly_ctx, config->value.mem, LYD_LYB, parse_options, 0, &root);
        break;
    case LYD_ANYDATA_JSON:
        EINT;
        *rc = SR_ERR_INTERNAL;
        return NULL;
    }
    if (lyrc) {
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
filter_xpath_buf_append_attrs(const struct lyd_meta *meta, char **buf, int size)
{
    const struct lyd_meta *next;
    int new_size;
    char *buf_new;

    LY_LIST_FOR(meta, next) {
        new_size = size + 2 + strlen(next->annotation->module->name) + 1 + strlen(next->name) + 2 +
                strlen(next->value.canonical) + 2;
        buf_new = realloc(*buf, new_size);
        if (!buf_new) {
            EMEM;
            return -1;
        }
        *buf = buf_new;
        sprintf((*buf) + (size - 1), "[@%s:%s='%s']", next->annotation->module->name, next->name, next->value.canonical);
        size = new_size;
    }

    return size;
}

/* top-level content node with namespace and optional attributes */
static int
filter_xpath_buf_add_top_content(const struct lyd_node *node, struct np2_filter *filter)
{
    int size;
    char *buf;

    assert(!lyd_parent(node) && node->schema);

    size = 1 + strlen(node->schema->module->name) + 1 + strlen(LYD_NAME(node)) + 9 + strlen(LYD_CANON_VALUE(node)) + 3;
    buf = malloc(size);
    if (!buf) {
        EMEM;
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%s']", node->schema->module->name, LYD_NAME(node), LYD_CANON_VALUE(node));

    size = filter_xpath_buf_append_attrs(node->meta, &buf, size);
    if (size < 1) {
        free(buf);
        return size;
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
filter_xpath_buf_append_content(const struct lyd_node *node, char **buf, int size)
{
    const struct lys_module *mod = NULL;
    int new_size;
    char *buf_new, quot;

    assert(node->schema && (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)));

    /* do we print the module name? */
    if (!node->parent || (lyd_parent(node)->schema->module != node->schema->module)) {
        mod = node->schema->module;
    }

    new_size = size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "[%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    size = new_size;

    size = filter_xpath_buf_append_attrs(node->meta, buf, size);
    if (size < 1) {
        return size;
    }

    new_size = size + 2 + strlen(LYD_CANON_VALUE(node)) + 2;
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;

    if (strchr(LYD_CANON_VALUE(node), '\'')) {
        quot = '\"';
    } else {
        quot = '\'';
    }
    sprintf((*buf) + (size - 1), "=%c%s%c]", quot, LYD_CANON_VALUE(node), quot);

    return new_size;
}

/* containment/selection node with namespace and optional attributes */
static int
filter_xpath_buf_append_node(const struct lyd_node *node, char **buf, int size)
{
    const struct lys_module *mod = NULL;
    const struct lyd_node_opaq *opaq;
    int new_size;
    char *buf_new;

    assert(node->schema || !((struct lyd_node_opaq *)node)->value || strws(((struct lyd_node_opaq *)node)->value));

    /* do we print the module? */
    if (node->schema && (!node->parent || (lyd_parent(node)->schema->module != node->schema->module))) {
        mod = node->schema->module;
    } else if (!node->schema) {
        opaq = (struct lyd_node_opaq *)node;
        if (!opaq->name.module_ns) {
            /* no namespace, will not match anything */
            return 0;
        }

        mod = ly_ctx_get_module_implemented_ns(LYD_CTX(node), opaq->name.module_ns);
        if (!mod) {
            /* unknown namespace, will not match anything */
        }

        if (lyd_parent(node)->schema->module == mod) {
            mod = NULL;
        }
    }

    new_size = size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "/%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    size = new_size;

    if (node->schema) {
        size = filter_xpath_buf_append_attrs(node->meta, buf, size);
    } else {
        /* TODO print opaq attributes */
    }

    return size;
}

static int
filter_xpath_buf_add_r(const struct lyd_node *node, char **buf, int size, struct np2_filter *filter)
{
    const struct lyd_node *child;
    int s, only_content_match;

    /* containment node or selection node */
    size = filter_xpath_buf_append_node(node, buf, size);
    if (size < 1) {
        return size;
    }

    if (!lyd_child(node)) {
        /* just a selection node */
        if (op_filter_xpath_add_filter(*buf, 1, filter)) {
            return -1;
        }
        return 0;
    }

    /* append child content match nodes */
    only_content_match = 1;
    LY_LIST_FOR(lyd_child(node), child) {
        if (child->schema && LYD_CANON_VALUE(child) && !strws(LYD_CANON_VALUE(child))) {
            /* there is a content filter, append all of them */
            size = filter_xpath_buf_append_content(child, buf, size);
            if (size < 1) {
                return size;
            }
        } else {
            /* can no longer be just a content match */
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
    LY_LIST_FOR(lyd_child(node), child) {
        if (lyd_child(child)) {
            /* child containment node */
            filter_xpath_buf_add_r(child, buf, size, filter);
        } else if (child->schema || !((struct lyd_node_opaq *)child)->value || strws(((struct lyd_node_opaq *)child)->value)) {
            /* child selection node */
            s = filter_xpath_buf_append_node(child, buf, size);
            if (!s) {
                continue;
            } else if (s < 0) {
                return s;
            }

            if (op_filter_xpath_add_filter(*buf, 1, filter)) {
                return -1;
            }
        } /* else child content node, already handled, or invalid opaque node, skipped */
    }

    return 0;
}

static int
op_filter_build_xpath_from_subtree(const struct lyd_node *node, struct np2_filter *filter)
{
    const struct lyd_node *iter;
    char *buf = NULL;

    LY_LIST_FOR(node, iter) {
        if (iter->schema && LYD_CANON_VALUE(iter) && !strws(LYD_CANON_VALUE(iter))) {
            /* special case of top-level content match node */
            if (filter_xpath_buf_add_top_content(iter, filter)) {
                goto error;
            }
        } else if (iter->schema || !((struct lyd_node_opaq *)iter)->value || strws(((struct lyd_node_opaq *)iter)->value)) {
            /* containment or selection node */
            if (filter_xpath_buf_add_r(iter, &buf, 1, filter)) {
                goto error;
            }
        }
    }

    free(buf);
    return 0;

error:
    free(buf);
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
op_filter_create(const struct lyd_node *filter_node, struct np2_filter *filter)
{
    struct lyd_meta *meta;

    meta = lyd_find_meta(filter_node->meta, NULL, "type");
    if (meta && !strcmp(meta->value.canonical, "xpath")) {
        meta = lyd_find_meta(filter_node->meta, NULL, "select");
        if (!meta) {
            ERR("RPC with an XPath filter without the \"select\" attribute.");
            return -1;
        }
    } else {
        meta = NULL;
    }

    if (!meta) {
        /* subtree */
        if (((struct lyd_node_any *)filter_node)->value_type != LYD_ANYDATA_DATATREE) {
            /* empty filter, fair enough */
            return 0;
        }

        if (op_filter_build_xpath_from_subtree(((struct lyd_node_any *)filter_node)->value.tree, filter)) {
            return -1;
        }
    } else {
        /* xpath */
        if (!meta->value.canonical || !strlen(meta->value.canonical)) {
            /* empty select, okay, I guess... */
            return 0;
        }
        if (op_filter_xpath_add_filter(meta->value.canonical, 1, filter)) {
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
        if (lyd_merge_siblings(data, node, LYD_MERGE_DESTRUCT)) {
            lyd_free_siblings(node);
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
        if (lyd_find_xpath(*data, filter->filters[i].str, &set)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        for (j = 0; j < set->count; ++j) {
            if (lyd_dup_single(set->dnodes[j], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &node)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }

            /* always find parent */
            while (node->parent) {
                node = lyd_parent(node);
            }

            /* merge */
            if (lyd_merge_tree(filtered_data, node, LYD_MERGE_DESTRUCT)) {
                lyd_free_tree(node);
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        ly_set_free(set, NULL);
        set = NULL;
    }

    if (!has_filter) {
        /* no filter, just use all the data */
        *filtered_data = *data;
        *data = NULL;
    }

cleanup:
    ly_set_free(set, NULL);
    return rc;
}
