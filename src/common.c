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
#include <pthread.h>
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

    if (sr_session_get_orig_name(ev_sess) && strcmp(sr_session_get_orig_name(ev_sess), "netopeer2")) {
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
        clock_gettime(COMPAT_CLOCK_ID, &ts);
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
np_acquire_user_sess(const struct nc_session *ncs, struct np2_user_sess **user_sess)
{
    struct np2_user_sess *us;
    struct timespec ts_timeout;

    /* increase ref_count */
    us = nc_session_get_data(ncs);
    ATOMIC_INC_RELAXED(us->ref_count);

    ts_timeout = np_gettimespec(0);
    np_addtimespec(&ts_timeout, NP2SRV_USER_SESS_LOCK_TIMEOUT);

    /* LOCK */
    if (pthread_mutex_clocklock(&us->lock, COMPAT_CLOCK_ID, &ts_timeout)) {
        ATOMIC_DEC_RELAXED(us->ref_count);
        return SR_ERR_TIME_OUT;
    }

    *user_sess = us;
    return SR_ERR_OK;
}

int
np_find_user_sess(sr_session_ctx_t *ev_sess, const char *func, struct nc_session **nc_sess, struct np2_user_sess **user_sess)
{
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
    return np_acquire_user_sess(ncs, user_sess);
}

void
np_release_user_sess(struct np2_user_sess *user_sess)
{
    if (!user_sess) {
        return;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&user_sess->lock);

    if (ATOMIC_DEC_RELAXED(user_sess->ref_count) == 1) {
        /* is 0 now, free */
        sr_session_stop(user_sess->sess);
        pthread_mutex_destroy(&user_sess->lock);
        free(user_sess);
    }
}

static LY_ERR
sub_ntf_lysc_has_notif_clb(struct lysc_node *node, void *UNUSED(data), ly_bool *UNUSED(dfs_continue))
{
    LY_ARRAY_COUNT_TYPE u;
    const struct lysc_ext *ext;

    if (node->nodetype == LYS_NOTIF) {
        return LY_EEXIST;
    } else {
        LY_ARRAY_FOR(node->exts, u) {
            ext = node->exts[u].def;
            if (!strcmp(ext->name, "mount-point") && !strcmp(ext->module->name, "ietf-yang-schema-mount")) {
                /* any data including notifications could be mounted */
                return LY_EEXIST;
            }
        }
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

int
np_ntf_add_dup(const struct lyd_node *notif, const struct timespec *timestamp, struct np_rt_notif **ntfs,
        uint32_t *ntf_count)
{
    void *mem;

    mem = realloc(*ntfs, (*ntf_count + 1) * sizeof **ntfs);
    if (!mem) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    *ntfs = mem;

    if (lyd_dup_single(notif, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &(*ntfs)[*ntf_count].notif)) {
        return SR_ERR_LY;
    }
    (*ntfs)[*ntf_count].timestamp = *timestamp;
    ++(*ntf_count);

    return SR_ERR_OK;
}

int
np_ntf_send(struct nc_session *ncs, const struct timespec *timestamp, struct lyd_node **ly_ntf, int use_ntf)
{
    int rc = SR_ERR_OK;
    struct nc_server_notif *nc_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char *datetime = NULL;

    /* create the notification object, all the passed arguments must exist until it is sent */
    ly_time_ts2str(timestamp, &datetime);
    if (use_ntf) {
        /* take ownership of the objects */
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_FREE);
        *ly_ntf = NULL;
        datetime = NULL;
    } else {
        /* objects const, their lifetime must last until the notif is sent */
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_CONST);
    }

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ?
                "failed" : "timed out");
        goto cleanup;
    }

    /* NETCONF monitoring notification counter */
    ncm_session_notification(ncs);

cleanup:
    if (use_ntf) {
        lyd_free_tree(*ly_ntf);
        *ly_ntf = NULL;
    }
    free(datetime);
    nc_server_notif_free(nc_ntf);
    return rc;
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
np2srv_new_session_cb(const char *UNUSED(client_name), struct nc_session *new_session, void *UNUSED(user_data))
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
    user_sess = calloc(1, sizeof *user_sess);
    if (!user_sess) {
        EMEM;
        goto error;
    }
    user_sess->sess = sr_sess;
    ATOMIC_STORE_RELAXED(user_sess->ref_count, 1);
    pthread_mutex_init(&user_sess->lock, NULL);
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
                np2srv.sr_timeout, 0);
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

int
op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts, const char *xp_filter,
        sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    sr_data_t *sr_data = NULL;
    int rc;
    LY_ERR lyrc;

    /* get the selected data */
    rc = sr_get_data(session, xp_filter, max_depth, np2srv.sr_timeout, get_opts, &sr_data);
    if (rc && (rc != SR_ERR_NOT_FOUND)) {
        ERR("Getting data \"%s\" from sysrepo failed (%s).", xp_filter, sr_strerror(rc));
        np_err_sr2nc_get(ev_sess, session);
        return rc;
    }

    if (sr_data) {
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
