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

#define _GNU_SOURCE /* asprintf() */

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
#include "compat.h"
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

struct timespec
np_gettimespec(int force_real)
{
    struct timespec ts;

    if (force_real) {
        clock_gettime(CLOCK_REALTIME, &ts);
    } else {
        clock_gettime(NP_CLOCK_ID, &ts);
    }

    return ts;
}

int64_t
np_difftimespec(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts2->tv_sec) - ((int64_t)ts1->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts2->tv_nsec) - ((int64_t)ts1->tv_nsec);

    return nsec_diff ? nsec_diff / 1000000L : 0;
}

void
np_addtimespec(struct timespec *ts, uint32_t msec)
{
    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));

    ts->tv_sec += msec / 1000;
    ts->tv_nsec += (msec % 1000) * 1000000L;

    if (ts->tv_nsec >= 1000000000L) {
        ++ts->tv_sec;
        ts->tv_nsec -= 1000000000L;
    } else if (ts->tv_nsec < 0) {
        --ts->tv_sec;
        ts->tv_nsec += 1000000000L;
    }

    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));
}

struct timespec
np_modtimespec(const struct timespec *ts, uint32_t msec)
{
    struct timespec ret;
    uint64_t ts_msec;

    /* convert ts to msec first */
    ts_msec = ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
    ts_msec %= msec;

    ret.tv_sec = ts_msec / 1000;
    ret.tv_nsec = (ts_msec % 1000) * 1000000;

    return ret;
}

int
np_get_nc_sess_by_id(uint32_t sr_id, uint32_t nc_id, struct nc_session **nc_sess)
{
    uint32_t i;
    struct nc_session *ncs = NULL;
    struct np2_user_sess *user_sess;

    assert((sr_id && !nc_id) || (!sr_id && nc_id));

    for (i = 0; (ncs = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (sr_id) {
            user_sess = nc_session_get_data(ncs);
            if (sr_session_get_id(user_sess->sess) == sr_id) {
                break;
            }
        } else {
            if (nc_session_get_id(ncs) == nc_id) {
                break;
            }
        }
    }

    if (!ncs) {
        if (nc_id) {
            ERR("Failed to find NETCONF session with NC ID %u.", nc_id);
        }
        return SR_ERR_INTERNAL;
    }

    *nc_sess = ncs;
    return SR_ERR_OK;
}

int
np_get_user_sess(sr_session_ctx_t *ev_sess, struct nc_session **nc_sess, struct np2_user_sess **user_sess)
{
    struct np2_user_sess *us;
    const char *orig_name;
    uint32_t *nc_id, size;
    struct nc_session *ncs;
    int rc;

    orig_name = sr_session_get_orig_name(ev_sess);
    if (!orig_name || strcmp(orig_name, "netopeer2")) {
        ERR("Unknown originator name \"%s\" in event session.", orig_name);
        return SR_ERR_INTERNAL;
    }

    sr_session_get_orig_data(ev_sess, 0, &size, (const void **)&nc_id);

    rc = np_get_nc_sess_by_id(0, *nc_id, &ncs);
    if (rc) {
        return rc;
    }

    /* NETCONF session */
    if (nc_sess) {
        *nc_sess = ncs;
    }
    if (!user_sess) {
        return SR_ERR_OK;
    }

    /* user sysrepo session */
    us = nc_session_get_data(ncs);
    ATOMIC_INC_RELAXED(us->ref_count);
    *user_sess = us;

    return SR_ERR_OK;
}

void
np_release_user_sess(struct np2_user_sess *user_sess)
{
    ATOMIC_T prev_ref_count;

    if (!user_sess) {
        return;
    }

    prev_ref_count = ATOMIC_DEC_RELAXED(user_sess->ref_count);
    if (ATOMIC_LOAD_RELAXED(prev_ref_count) == 1) {
        /* is 0 now, free */
        sr_session_stop(user_sess->sess);
        free(user_sess);
    }
}

static LY_ERR
sub_ntf_lysc_has_notif_clb(struct lysc_node *node, void *UNUSED(data), ly_bool *UNUSED(dfs_continue))
{
    if (node->nodetype == LYS_NOTIF) {
        return LY_EEXIST;
    }

    return LY_SUCCESS;
}

int
np_ly_mod_has_notif(const struct lys_module *mod)
{
    if (lysc_module_dfs_full(mod, sub_ntf_lysc_has_notif_clb, NULL) == LY_EEXIST) {
        return 1;
    }
    return 0;
}

int
np_ly_mod_has_data(const struct lys_module *mod, uint32_t config_mask)
{
    const struct lysc_node *root, *node;

    LY_LIST_FOR(mod->compiled->data, root) {
        LYSC_TREE_DFS_BEGIN(mod->compiled->data, node) {
            if (node->flags & config_mask) {
                return 1;
            }

            LYSC_TREE_DFS_END(mod->compiled->data, node);
        }
    }

    return 0;
}

int
np2srv_new_session_cb(const char *UNUSED(client_name), struct nc_session *new_session)
{
    int c;
    sr_val_t *event_data;
    sr_session_ctx_t *sr_sess = NULL;
    struct np2_user_sess *user_sess = NULL;
    const struct lys_module *mod;
    char *host = NULL;
    uint32_t nc_id;
    const char *username;

    /* monitor NETCONF session */
    ncm_session_add(new_session);

    /* start sysrepo session for every NETCONF session (so that it can be used for notification subscriptions and
     * held lock persistence) */
    c = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (c != SR_ERR_OK) {
        ERR("Failed to start a sysrepo session (%s).", sr_strerror(c));
        goto error;
    }

    /* create user session with ref-count so that it is not freed while being used */
    user_sess = malloc(sizeof *user_sess);
    if (!user_sess) {
        EMEM;
        goto error;
    }
    user_sess->sess = sr_sess;
    ATOMIC_STORE_RELAXED(user_sess->ref_count, 1);
    nc_session_set_data(new_session, user_sess);

    /* set NC ID and NETCONF username for sysrepo callbacks */
    sr_session_set_orig_name(sr_sess, "netopeer2");
    nc_id = nc_session_get_id(new_session);
    sr_session_push_orig_data(sr_sess, sizeof nc_id, &nc_id);
    username = nc_session_get_username(new_session);
    sr_session_push_orig_data(sr_sess, strlen(username) + 1, username);

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
        c = sr_event_notif_send(np2srv.sr_sess, "/ietf-netconf-notifications:netconf-session-start", event_data,
                host ? 3 : 2, np2srv.sr_timeout, 1);
        if (c != SR_ERR_OK) {
            WRN("Failed to send a notification (%s).", sr_strerror(c));
        } else {
            VRB("Generated new event (netconf-session-start).");
        }
        free(event_data);
    }

    return 0;

error:
    ncm_session_del(new_session);
    sr_session_stop(sr_sess);
    free(user_sess);
    return -1;
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
        return 0;
    }

    /* get max capab string size and allocate it */
    j = strlen(main_cpblt) + 1;
    for (i = 0; url_protocol_str[i]; ++i) {
        j += strlen(url_protocol_str[i]) + 1;
    }
    cpblt = malloc(j);
    if (!cpblt) {
        EMEM;
        return -1;
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
    return 0;
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

    if ((aux_size < 1) || (data->size == 0)) {
        /* no space or nothing left */
        return 0;
    }

    copied = (data->size > aux_size) ? aux_size : data->size;
    memcpy(ptr, data->memory, copied);
    data->memory = data->memory + copied; /* move pointer */
    data->size = data->size - copied; /* decrease amount of data left */
    return copied;
}

/**
 * @brief Open specific URL using curl.
 *
 * @param[in] url URL to open.
 * @return FD with the URL contents;
 * @return -1 on error.
 */
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
    struct lyd_node_opaq *opaq;
    int fd;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    fd = url_open(url);
    if (fd == -1) {
        *rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(sr_sess, "Could not open URL.");
        return NULL;
    }

    /* load the whole config element */
    if (lyd_parse_data_fd(ly_ctx, fd, LYD_XML, parse_options, 0, &config)) {
        *rc = SR_ERR_LY;
        sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
        return NULL;
    }

    if (!config || config->schema) {
        *rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(sr_sess, "Missing top-level \"config\" element in URL data.");
        return NULL;
    }

    opaq = (struct lyd_node_opaq *)config;
    if (strcmp(opaq->name.name, "config") || strcmp(opaq->name.module_ns, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        *rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(sr_sess, "Invalid top-level element in URL data, expected \"config\" with "
                "namespace \"urn:ietf:params:xml:ns:netconf:base:1.0\".");
        return NULL;
    }

    data = opaq->child;
    lyd_unlink_siblings(data);
    lyd_free_tree(config);
    return data;
}

int
op_export_url(const char *url, struct lyd_node *data, uint32_t print_options, int *rc, sr_session_ctx_t *sr_sess)
{
    CURL *curl;
    CURLcode res;
    struct np2srv_url_mem mem_data;
    char curl_buffer[CURL_ERROR_SIZE], *str_data;
    struct lyd_node *config;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    /* print the config as expected by the other end */
    if (lyd_new_opaq2(NULL, ly_ctx, "config", NULL, NULL, "urn:ietf:params:xml:ns:netconf:base:1.0", &config)) {
        *rc = SR_ERR_LY;
        sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
        return -1;
    }
    if (data) {
        lyd_insert_child(config, data);
    }
    lyd_print_mem(&str_data, config, LYD_XML, print_options);

    /* do not free data */
    lyd_unlink_siblings(data);
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
        sr_session_set_error_message(sr_sess, curl_buffer);
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

    assert(config && config->schema && (config->schema->nodetype & LYD_NODE_ANY));

    if (!config->value.str) {
        /* nothing to do, no data */
        return NULL;
    }

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
        sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
    }

    return root;
}

/**
 * @brief Learn whether a string is white-space-only.
 *
 * @param[in] str String to examine.
 * @return 1 if there are only white-spaces in @p str;
 * @return 0 otherwise.
 */
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

/**
 * @brief Add another XPath filter into NP2 filter structure.
 *
 * @param[in] new_filter New XPath filter to add.
 * @param[in] selection Whether @p new_filter is selection or content filter.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success;
 * @return -1 on error.
 */
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

/**
 * @brief Append subtree filter metadata to XPath filter string buffer.
 *
 * Handles metadata.
 *
 * @param[in] meta Subtree filter node metadata.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @return New @p buf size;
 * @return -1 on error.
 */
static int
filter_xpath_buf_append_attrs(const struct lyd_meta *meta, char **buf, int size)
{
    const struct lyd_meta *next;
    int new_size;
    char *buf_new;

    LY_LIST_FOR(meta, next) {
        new_size = size + 2 + strlen(next->annotation->module->name) + 1 + strlen(next->name) + 2 +
                strlen(lyd_get_meta_value(next)) + 2;
        buf_new = realloc(*buf, new_size);
        if (!buf_new) {
            EMEM;
            return -1;
        }
        *buf = buf_new;
        sprintf((*buf) + (size - 1), "[@%s:%s='%s']", next->annotation->module->name, next->name, lyd_get_meta_value(next));
        size = new_size;
    }

    return size;
}

/**
 * @brief Process a subtree top-level content node with namespace and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
filter_xpath_buf_add_top_content(const struct lyd_node *node, struct np2_filter *filter)
{
    int size;
    char *buf;

    assert(!lyd_parent(node) && node->schema);

    size = 1 + strlen(node->schema->module->name) + 1 + strlen(LYD_NAME(node)) + 9 + strlen(lyd_get_value(node)) + 3;
    buf = malloc(size);
    if (!buf) {
        EMEM;
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%s']", node->schema->module->name, LYD_NAME(node), lyd_get_value(node));

    size = filter_xpath_buf_append_attrs(node->meta, &buf, size);
    if (size < 1) {
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

/**
 * @brief Get the module to print for a node if needed based on JSON instid module inheritence.
 *
 * @param[in] node Node that is printed.
 * @return Module to print;
 * @return NULL if no module needs to be printed.
 */
static const struct lys_module *
filter_xpath_print_node_module(const struct lyd_node *node)
{
    const struct lys_module *mod;
    const struct lyd_node *parent;
    const struct lyd_node_opaq *opaq, *opaq2;

    parent = lyd_parent(node);

    if (!parent) {
        /* print the module */
    } else if (node->schema && parent->schema) {
        /* 2 data nodes */
        if (node->schema->module == parent->schema->module) {
            return NULL;
        }
    } else if (node->schema || parent->schema) {
        /* 1 data node, 1 opaque node */
        mod = node->schema ? node->schema->module : parent->schema->module;
        opaq = node->schema ? (struct lyd_node_opaq *)parent : (struct lyd_node_opaq *)node;
        assert(opaq->format == LY_VALUE_XML);

        /* in dict */
        if (mod->ns == opaq->name.module_ns) {
            return NULL;
        }
    } else {
        /* 2 opaque nodes */
        opaq = (struct lyd_node_opaq *)node;
        opaq2 = (struct lyd_node_opaq *)parent;

        /* in dict */
        if (opaq->name.module_ns == opaq2->name.module_ns) {
            return NULL;
        }
    }

    /* module will be printed, get it */
    mod = NULL;
    if (node->schema) {
        mod = node->schema->module;
    } else {
        opaq = (struct lyd_node_opaq *)node;
        if (opaq->name.module_ns) {
            mod = ly_ctx_get_module_implemented_ns(LYD_CTX(node), opaq->name.module_ns);
        }
    }

    return mod;
}

/**
 * @brief Append subtree filter node to XPath filter string buffer.
 *
 * Handles content nodes with optional namespace and attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @return New @p buf size;
 * @return -1 on error.
 */
static int
filter_xpath_buf_append_content(const struct lyd_node *node, char **buf, int size)
{
    const struct lys_module *mod = NULL;
    int new_size;
    char *buf_new, quot;

    assert(!node->schema || (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)));

    /* do we print the module name? */
    mod = filter_xpath_print_node_module(node);

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

    new_size = size + 2 + strlen(lyd_get_value(node)) + 2;
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;

    if (strchr(lyd_get_value(node), '\'')) {
        quot = '\"';
    } else {
        quot = '\'';
    }
    sprintf((*buf) + (size - 1), "=%c%s%c]", quot, lyd_get_value(node), quot);

    return new_size;
}

/**
 * @brief Append subtree filter node to XPath filter string buffer.
 *
 * Handles containment/selection nodes with namespace and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @return New @p buf size;
 * @return -1 on error.
 */
static int
filter_xpath_buf_append_node(const struct lyd_node *node, char **buf, int size)
{
    const struct lys_module *mod = NULL;
    int new_size;
    char *buf_new;

    /* do we print the module name? */
    mod = filter_xpath_print_node_module(node);

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

/**
 * @brief Process a subtree filter node by constructing an XPath filter string and adding it
 * to an NP2 filter structure, recursively.
 *
 * @param[in] node Subtree filter node.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
filter_xpath_buf_add_r(const struct lyd_node *node, char **buf, int size, struct np2_filter *filter)
{
    const struct lyd_node *child;
    int s, only_content_match;

    /* containment node or selection node */
    size = filter_xpath_buf_append_node(node, buf, size);
    if (size < 1) {
        return -1;
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
        if (lyd_get_value(child) && !strws(lyd_get_value(child))) {
            /* there is a content filter, append all of them */
            size = filter_xpath_buf_append_content(child, buf, size);
            if (size < 1) {
                return -1;
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
        } else {
            /* child selection node or content node (both should be included in the output) */
            s = filter_xpath_buf_append_node(child, buf, size);
            if (!s) {
                continue;
            } else if (s < 0) {
                return -1;
            }

            if (op_filter_xpath_add_filter(*buf, 1, filter)) {
                return -1;
            }
        }
    }

    return 0;
}

int
op_filter_subtree2xpath(const struct lyd_node *node, struct np2_filter *filter)
{
    const struct lyd_node *iter;
    char *buf = NULL;

    LY_LIST_FOR(node, iter) {
        if (iter->schema && lyd_get_value(iter) && !strws(lyd_get_value(iter))) {
            /* special case of top-level content match node */
            if (filter_xpath_buf_add_top_content(iter, filter)) {
                goto error;
            }
        } else if (iter->schema || !((struct lyd_node_opaq *)iter)->value || strws(((struct lyd_node_opaq *)iter)->value)) {
            /* containment or selection node */
            if (filter_xpath_buf_add_r(iter, &buf, 1, filter)) {
                goto error;
            }
        } else {
            WRN("Skipping unsupported top-level filter node \"%s\".", LYD_NAME(iter));
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
    uint32_t i;

    for (i = 0; i < filter->count; ++i) {
        free(filter->filters[i].str);
    }
    free(filter->filters);
    filter->filters = NULL;
    filter->count = 0;
}

/**
 * @brief Append string to another string by enlarging it.
 *
 * @param[in] str String to append.
 * @param[in,out] ret String to append to, is enlarged.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
np_append_str(const char *str, char **ret)
{
    void *mem;
    int len;

    if (!*ret) {
        *ret = strdup(str);
        if (!*ret) {
            EMEM;
            return -1;
        }
    } else {
        len = strlen(*ret);
        mem = realloc(*ret, len + strlen(str) + 1);
        if (!mem) {
            EMEM;
            return -1;
        }
        *ret = mem;
        strcat(*ret + len, str);
    }

    return 0;
}

int
op_filter_filter2xpath(const struct np2_filter *filter, char **xpath)
{
    int rc;
    uint32_t i;

    *xpath = NULL;

    /* all selection filters first */
    for (i = 0; i < filter->count; ++i) {
        if (!filter->filters[i].selection && (filter->count > 1)) {
            ERR("Several top-level content match filters are not supported as they are redundant.");
            rc = SR_ERR_UNSUPPORTED;
            goto error;
        }

        /* put all selection filters into parentheses */
        if (!*xpath) {
            if (np_append_str("(", xpath)) {
                rc = SR_ERR_NO_MEMORY;
                goto error;
            }

            if (np_append_str(filter->filters[i].str, xpath)) {
                rc = SR_ERR_NO_MEMORY;
                goto error;
            }
        } else {
            if (np_append_str(" | ", xpath)) {
                rc = SR_ERR_NO_MEMORY;
                goto error;
            }

            if (np_append_str(filter->filters[i].str, xpath)) {
                rc = SR_ERR_NO_MEMORY;
                goto error;
            }
        }
    }

    if (*xpath) {
        /* finish parentheses */
        if (np_append_str(")", xpath)) {
            rc = SR_ERR_NO_MEMORY;
            goto error;
        }
    }

    return SR_ERR_OK;

error:
    free(*xpath);
    *xpath = NULL;
    return rc;
}

int
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_oper_options_t get_opts,
        const struct np2_filter *filter, sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    const sr_error_info_t *err_info;
    struct lyd_node *node;
    uint32_t i;
    int rc;

    for (i = 0; i < filter->count; ++i) {
        /* get the selected data */
        rc = sr_get_data(session, filter->filters[i].str, max_depth, np2srv.sr_timeout, get_opts, &node);
        if (rc) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filter->filters[i].str, sr_strerror(rc));
            sr_session_get_error(session, &err_info);
            sr_session_set_error_message(ev_sess, err_info->err[0].message);
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
    int has_filter = 0, rc = SR_ERR_OK;
    struct ly_set *set = NULL;
    uint32_t i, j;

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
