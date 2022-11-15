/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common routines
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
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
#include <libyang/plugins_types.h>
#include <nc_server.h>
#include <sysrepo/netconf_acm.h>

#include "common.h"
#include "compat.h"
#include "err_netconf.h"
#include "log.h"
#include "netconf_monitoring.h"

struct np2srv np2srv = {.unix_mode = -1, .unix_uid = -1, .unix_gid = -1};

int
np_ignore_rpc(sr_session_ctx_t *ev_sess, sr_event_t event, int *rc)
{
    if (event == SR_EV_ABORT) {
        /* silent ignore */
        *rc = SR_ERR_OK;
        return 1;
    }

    if (!NP_IS_ORIG_NP(ev_sess)) {
        /* forbidden */
        sr_session_set_error_message(ev_sess, "Non-NETCONF originating RPC will not be executed.");
        *rc = SR_ERR_UNSUPPORTED;
        return 1;
    }

    return 0;
}

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

static int
np_ps_match_cb(struct nc_session *session, void *cb_data)
{
    struct np_ps_match_data *match_data = cb_data;
    struct np2_user_sess *user_sess;

    if (match_data->sr_id) {
        user_sess = nc_session_get_data(session);
        if (sr_session_get_id(user_sess->sess) == match_data->sr_id) {
            return 1;
        }
    } else {
        if (nc_session_get_id(session) == match_data->nc_id) {
            return 1;
        }
    }

    return 0;
}

int
np_get_nc_sess_by_id(uint32_t sr_id, uint32_t nc_id, const char *func, struct nc_session **nc_sess)
{
    struct np_ps_match_data match_data;
    struct nc_session *ncs = NULL;

    assert((sr_id && !nc_id) || (!sr_id && nc_id));

    *nc_sess = NULL;

    /* find the session */
    match_data.sr_id = sr_id;
    match_data.nc_id = nc_id;
    ncs = nc_ps_find_session(np2srv.nc_ps, np_ps_match_cb, &match_data);

    if (!ncs) {
        if (nc_id) {
            ERR("%s: Failed to find NETCONF session with NC ID %u.", func, nc_id);
        }
        return SR_ERR_INTERNAL;
    }

    *nc_sess = ncs;
    return SR_ERR_OK;
}

int
np_get_user_sess(sr_session_ctx_t *ev_sess, const char *func, struct nc_session **nc_sess, struct np2_user_sess **user_sess)
{
    struct np2_user_sess *us;
    const char *orig_name;
    uint32_t *nc_id, size;
    struct nc_session *ncs;
    int rc;

    orig_name = sr_session_get_orig_name(ev_sess);
    if (!orig_name || strcmp(orig_name, "netopeer2")) {
        ERR("%s: Unknown originator name \"%s\" in event session.", func, orig_name);
        return SR_ERR_INTERNAL;
    }

    sr_session_get_orig_data(ev_sess, 0, &size, (const void **)&nc_id);

    rc = np_get_nc_sess_by_id(0, *nc_id, func, &ncs);
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
        LYSC_TREE_DFS_BEGIN(root, node) {
            if (node->flags & config_mask) {
                return 1;
            }

            LYSC_TREE_DFS_END(root, node);
        }
    }

    return 0;
}

const struct ly_ctx *
np2srv_acquire_ctx_cb(void *cb_data)
{
    return sr_acquire_context(cb_data);
}

void
np2srv_release_ctx_cb(void *cb_data)
{
    sr_release_context(cb_data);
}

int
np2srv_new_session_cb(const char *UNUSED(client_name), struct nc_session *new_session)
{
    int c;
    sr_val_t *event_data;
    sr_session_ctx_t *sr_sess = NULL;
    struct np2_user_sess *user_sess = NULL;
    const struct ly_ctx *ly_ctx;
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

    /* set NACM username for it to be applied */
    if (sr_nacm_set_user(sr_sess, username)) {
        goto error;
    }

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

    ly_ctx = nc_session_get_ctx(new_session);
    if ((mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-netconf-notifications"))) {
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
        c = sr_notif_send(np2srv.sr_sess, "/ietf-netconf-notifications:netconf-session-start", event_data, host ? 3 : 2,
                np2srv.sr_timeout, 1);
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
op_parse_url(const char *url, int validate, int *rc, sr_session_ctx_t *sr_sess)
{
    struct lyd_node *config, *data = NULL;
    struct ly_ctx *ly_ctx;
    struct lyd_node_opaq *opaq;
    int fd;

    ly_ctx = (struct ly_ctx *)sr_acquire_context(np2srv.sr_conn);

    fd = url_open(url);
    if (fd == -1) {
        *rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(sr_sess, "Could not open URL.");
        goto cleanup;
    }

    /* load the whole config element */
    if (lyd_parse_data_fd(ly_ctx, fd, LYD_XML, LYD_PARSE_OPAQ | LYD_PARSE_ONLY | LYD_PARSE_NO_STATE, 0, &config)) {
        *rc = SR_ERR_LY;
        sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
        goto cleanup;
    }

    if (!config || config->schema) {
        *rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(sr_sess, "Missing top-level \"config\" element in URL data.");
        goto cleanup;
    }

    opaq = (struct lyd_node_opaq *)config;
    if (strcmp(opaq->name.name, "config") || strcmp(opaq->name.module_ns, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        *rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(sr_sess, "Invalid top-level element in URL data, expected \"config\" with "
                "namespace \"urn:ietf:params:xml:ns:netconf:base:1.0\".");
        goto cleanup;
    }

    data = opaq->child;
    lyd_unlink_siblings(data);
    lyd_free_tree(config);

    if (validate) {
        /* separate validation if requested */
        if (lyd_validate_all(&data, NULL, LYD_VALIDATE_NO_STATE, NULL)) {
            *rc = SR_ERR_LY;
            sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
            goto cleanup;
        }
    }

cleanup:
    sr_release_context(np2srv.sr_conn);
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
    int ret = 0;

    ly_ctx = (struct ly_ctx *)sr_acquire_context(np2srv.sr_conn);

    /* print the config as expected by the other end */
    if (lyd_new_opaq2(NULL, ly_ctx, "config", NULL, NULL, "urn:ietf:params:xml:ns:netconf:base:1.0", &config)) {
        *rc = SR_ERR_LY;
        sr_session_set_error_message(sr_sess, ly_errmsg(ly_ctx));
        ret = -1;
        goto cleanup;
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
        ret = -1;
        goto curl_cleanup;
    }

curl_cleanup:
    curl_easy_cleanup(curl);
    curl_global_cleanup();

cleanup:
    sr_release_context(np2srv.sr_conn);
    return ret;
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
    LY_ERR lyrc = 0;

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
        if (!lyrc && !(parse_options & (LYD_PARSE_ONLY | LYD_PARSE_OPAQ))) {
            /* separate validation if requested */
            lyrc = lyd_validate_all(&root, NULL, LYD_VALIDATE_NO_STATE, NULL);
        }
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
 * @param[in] node Subtree filter node with the metadata/attributes.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @return New @p buf size;
 * @return -1 on error.
 */
static int
filter_xpath_buf_append_attrs(const struct lyd_node *node, char **buf, int size)
{
    const struct lyd_meta *next;
    int new_size;
    char *buf_new;

    if (!node->schema) {
        /* TODO unsupported */
        return size;
    }

    LY_LIST_FOR(node->meta, next) {
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
 * @brief Process a subtree top-level content node and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
filter_xpath_buf_add_top_content(const struct lyd_node *node, const struct lys_module *top_mod, struct np2_filter *filter)
{
    int size;
    char *buf;

    assert(!lyd_parent(node));

    if (!top_mod) {
        top_mod = node->schema->module;
    }

    size = 1 + strlen(top_mod->name) + 1 + strlen(LYD_NAME(node)) + 9 + strlen(lyd_get_value(node)) + 3;
    buf = malloc(size);
    if (!buf) {
        EMEM;
        return -1;
    }
    sprintf(buf, "/%s:%s[text()='%s']", top_mod->name, LYD_NAME(node), lyd_get_value(node));

    size = filter_xpath_buf_append_attrs(node, &buf, size);
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
 * @param[in] top_mod Optional top-level module to use.
 * @return Module to print;
 * @return NULL if no module needs to be printed.
 */
static const struct lys_module *
filter_xpath_print_node_module(const struct lyd_node *node, const struct lys_module *top_mod)
{
    const struct lys_module *mod;
    const struct lyd_node *parent;
    const struct lyd_node_opaq *opaq, *opaq2;

    parent = lyd_parent(node);

    if (!parent) {
        /* print the module */
        if (top_mod) {
            /* explicit top-level module */
            return top_mod;
        }
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
 * @brief Get value of a node to use in XPath filter.
 *
 * @param[in] node Subtree filter node.
 * @param[out] dynamic Whether the value eneds to be freed.
 * @return String value to use;
 * @return NULL on error.
 */
static char *
filter_xpath_buf_get_value(const struct lyd_node *node, int *dynamic)
{
    struct lyd_node_opaq *opaq;
    const char *ptr;
    const struct lys_module *mod;
    char *val_str;

    *dynamic = 0;

    if (node->schema) {
        /* data node, canonical value should be fine */
        return (char *)lyd_get_value(node);
    }

    opaq = (struct lyd_node_opaq *)node;

    if (!(ptr = strchr(opaq->value, ':'))) {
        /* no prefix, use it directly */
        return (char *)opaq->value;
    }

    /* assume identity, try to get its module */
    mod = lyplg_type_identity_module(LYD_CTX(node), NULL, opaq->value, ptr - opaq->value, opaq->format,
            opaq->val_prefix_data);

    if (!mod) {
        /* unknown module, use as is */
        return (char *)opaq->value;
    }

    /* print the module name instead of the prefix */
    if (asprintf(&val_str, "%s:%s", mod->name, ptr + 1) == -1) {
        return NULL;
    }
    *dynamic = 1;
    return val_str;
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
    int new_size, dynamic = 0;
    char *buf_new, *val_str, quot;

    assert(!node->schema || (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)));

    /* do we print the module name? */
    mod = filter_xpath_print_node_module(node, NULL);

    new_size = size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        goto error;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "[%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    size = new_size;

    size = filter_xpath_buf_append_attrs(node, buf, size);
    if (size < 1) {
        goto error;
    }

    /* get proper value */
    val_str = filter_xpath_buf_get_value(node, &dynamic);
    if (!val_str) {
        goto error;
    }

    new_size = size + 2 + strlen(val_str) + 2;
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        goto error;
    }
    *buf = buf_new;

    /* learn which quotes are safe to use */
    if (strchr(val_str, '\'')) {
        quot = '\"';
    } else {
        quot = '\'';
    }

    /* append */
    sprintf((*buf) + (size - 1), "=%c%s%c]", quot, val_str, quot);

    if (dynamic) {
        free(val_str);
    }
    return new_size;

error:
    EMEM;
    if (dynamic) {
        free(val_str);
    }
    return -1;
}

/**
 * @brief Append subtree filter node to XPath filter string buffer.
 *
 * Handles containment/selection nodes with namespace and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @return New @p buf size;
 * @return -1 on error.
 */
static int
filter_xpath_buf_append_node(const struct lyd_node *node, const struct lys_module *top_mod, char **buf, int size)
{
    const struct lys_module *mod = NULL;
    int new_size;
    char *buf_new;

    /* do we print the module name? */
    mod = filter_xpath_print_node_module(node, top_mod);

    new_size = size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    if (!buf_new) {
        EMEM;
        return -1;
    }
    *buf = buf_new;
    sprintf((*buf) + (size - 1), "/%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    size = new_size;

    size = filter_xpath_buf_append_attrs(node, buf, size);

    return size;
}

/**
 * @brief Process a subtree filter node by constructing an XPath filter string and adding it
 * to an NP2 filter structure, recursively.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
filter_xpath_buf_add_r(const struct lyd_node *node, const struct lys_module *top_mod, char **buf, int size,
        struct np2_filter *filter)
{
    const struct lyd_node *child;
    int s, only_content_match, selection;

    /* containment node or selection node */
    size = filter_xpath_buf_append_node(node, top_mod, buf, size);
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
            filter_xpath_buf_add_r(child, NULL, buf, size, filter);
        } else {
            /* child selection node or content node (both should be included in the output) */
            s = filter_xpath_buf_append_node(child, NULL, buf, size);
            if (!s) {
                continue;
            } else if (s < 0) {
                return -1;
            }

            selection = (lyd_get_value(child) && !strws(lyd_get_value(child))) ? 0 : 1;
            if (op_filter_xpath_add_filter(*buf, selection, filter)) {
                return -1;
            }
        }
    }

    return 0;
}

/**
 * @brief Process a top-level subtree filter node.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] filter NP2 filter structure to add to.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
filter_xpath_create_top(const struct lyd_node *node, const struct lys_module *top_mod, struct np2_filter *filter)
{
    char *buf = NULL;

    if (lyd_get_value(node) && !strws(lyd_get_value(node))) {
        /* special case of top-level content match node */
        if (filter_xpath_buf_add_top_content(node, top_mod, filter)) {
            goto error;
        }
    } else {
        /* containment or selection node */
        if (filter_xpath_buf_add_r(node, top_mod, &buf, 1, filter)) {
            goto error;
        }
    }

    free(buf);
    return 0;

error:
    free(buf);
    return -1;
}

int
op_filter_create_subtree(const struct lyd_node *node, sr_session_ctx_t *ev_sess, struct np2_filter *filter)
{
    int rc = SR_ERR_OK, match;
    const struct lyd_node *iter;
    const struct lys_module *mod;
    const struct lysc_node *snode;
    uint32_t idx;

    LY_LIST_FOR(node, iter) {
        if (!iter->schema && !((struct lyd_node_opaq *)iter)->name.prefix) {
            /* no top-level namespace, generate all possible XPaths */
            match = 0;
            idx = 0;
            while ((mod = ly_ctx_get_module_iter(LYD_CTX(iter), &idx))) {
                if (!mod->implemented) {
                    continue;
                }

                snode = NULL;
                while ((snode = lys_getnext(snode, NULL, mod->compiled, 0))) {
                    if (snode->name == ((struct lyd_node_opaq *)iter)->name.name) {
                        /* match */
                        match = 1;
                        if (filter_xpath_create_top(iter, mod, filter)) {
                            rc = SR_ERR_NO_MEMORY;
                            goto cleanup;
                        }
                    }
                }
            }

            if (!match) {
                sr_session_set_error_message(ev_sess,
                        "Subtree filter node \"%s\" without a namespace does not match any YANG nodes.", LYD_NAME(iter));
                rc = SR_ERR_NOT_FOUND;
                goto cleanup;
            }
        } else {
            /* iter has a valid schema/namespace */
            if (filter_xpath_create_top(iter, NULL, filter)) {
                rc = SR_ERR_NO_MEMORY;
                goto cleanup;
            }
        }
    }

cleanup:
    if (rc) {
        op_filter_erase(filter);
    }
    return rc;
}

int
op_filter_create_xpath(const char *xpath, struct np2_filter *filter)
{
    int rc = SR_ERR_OK;

    memset(filter, 0, sizeof *filter);

    /* create a single filter */
    filter->filters = malloc(sizeof *filter->filters);
    if (!filter->filters) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    filter->count = 1;
    filter->filters[0].str = strdup(xpath);
    filter->filters[0].selection = 1;
    if (!filter->filters[0].str) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    if (rc) {
        op_filter_erase(filter);
    }
    return rc;
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

    /* combine all filters into one */
    for (i = 0; i < filter->count; ++i) {
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
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts,
        const struct np2_filter *filter, sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    sr_data_t *sr_data;
    uint32_t i;
    int rc;
    LY_ERR lyrc;

    for (i = 0; i < filter->count; ++i) {
        /* get the selected data */
        rc = sr_get_data(session, filter->filters[i].str, max_depth, np2srv.sr_timeout, get_opts, &sr_data);
        if (rc) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filter->filters[i].str, sr_strerror(rc));
            np_err_sr2nc_get(ev_sess, session);
            return rc;
        }

        if (!sr_data) {
            /* no data */
            continue;
        }

        /* merge */
        lyrc = lyd_merge_siblings(data, sr_data->tree, LYD_MERGE_DESTRUCT);
        sr_data->tree = NULL;
        sr_release_data(sr_data);
        if (lyrc) {
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
        if (lyd_find_xpath3(NULL, *data, filter->filters[i].str, NULL, &set)) {
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
