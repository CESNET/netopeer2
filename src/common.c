/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common routines
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
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
#include <stdarg.h>
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
#include <sysrepo/error_format.h>
#include <sysrepo/netconf_acm.h>

#include "common.h"
#include "compat.h"
#include "log.h"
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
    struct np_user_sess *user_sess;

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
np_acquire_user_sess(const struct nc_session *ncs, struct np_user_sess **user_sess)
{
    struct np_user_sess *us;
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

void
np_release_user_sess(struct np_user_sess *user_sess)
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

    if (nc_session_get_status(ncs) != NC_STATUS_RUNNING) {
        /* is being closed */
        goto cleanup;
    }

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

/**
 * @brief Create common session parameters to identify a management session.
 *
 * Detail description is in the common-session-parms grouping located in the ietf-netconf-notifications module.
 *
 * @param[in] new_session Created NC session.
 * @param[in,out] notif Notification to which the session parameters are to be added.
 * @return 0 on success.
 */
static LY_ERR
np_prepare_notif_common_session_parms(const struct nc_session *session, struct lyd_node *notif)
{
    char *value;
    char num32[11]; /* max bytes for 32-bit unsigned number + \0 */

    assert(session && notif);

    /* create 'username' node */
    value = (char *)nc_session_get_username(session);
    if (lyd_new_term(notif, notif->schema->module, "username", value, 0, NULL)) {
        return -1;
    }

    /* create 'session-id' node */
    sprintf(num32, "%" PRIu32, nc_session_get_id(session));
    if (lyd_new_term(notif, notif->schema->module, "session-id", num32, 0, NULL)) {
        return -1;
    }

    /* create 'source-host' node */
    if (nc_session_get_ti(session) != NC_TI_UNIX) {
        value = (char *)nc_session_get_host(session);
        if (lyd_new_term(notif, notif->schema->module, "source-host", value, 0, NULL)) {
            return -1;
        }
    }

    return 0;
}

int
np_send_notif_session_start(const struct nc_session *new_session, sr_session_ctx_t *sr_session, uint32_t sr_timeout)
{
    int rc = 0, r;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    struct lyd_node *notif = NULL;

    /* get module */
    ly_ctx = nc_session_get_ctx(new_session);
    mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-netconf-notifications");
    if (!mod) {
        goto cleanup;
    }

    /* create 'netconf-session-start' notification */
    if (lyd_new_inner(NULL, mod, "netconf-session-start", 0, &notif)) {
        rc = -1;
        goto cleanup;
    }

    /* create 'common-session-parms' grouping */
    if ((rc = np_prepare_notif_common_session_parms(new_session, notif))) {
        goto cleanup;
    }

    /* create 'session-type' leaf */
    mod = ly_ctx_get_module_implemented(ly_ctx, "netopeer-notifications");
    if (mod && lyd_new_term(notif, mod, "session-type", nc_session_is_callhome(new_session) ? "call-home" : "standard",
            0, NULL)) {
        goto cleanup;
    }

    /* send notification */
    if ((r = sr_notif_send_tree(sr_session, notif, sr_timeout, 0))) {
        WRN("Failed to send a notification (%s).", sr_strerror(r));
        rc = -1;
        goto cleanup;
    }

    VRB("Generated new event (netconf-session-start).");

cleanup:
    lyd_free_tree(notif);
    return rc;
}

int
np_send_notif_session_end(const struct nc_session *session, sr_session_ctx_t *sr_session, uint32_t sr_timeout)
{
    int rc = 0, r;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    struct lyd_node *notif = NULL;
    char num32[11]; /* max bytes for 32-bit unsigned number + \0 */
    char *value;

    /* get module */
    ly_ctx = nc_session_get_ctx(session);
    mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-netconf-notifications");
    if (!mod) {
        goto cleanup;
    }

    /* create 'netconf-session-end' notification */
    if (lyd_new_inner(NULL, mod, "netconf-session-end", 0, &notif)) {
        rc = -1;
        goto cleanup;
    }

    /* create 'common-session-parms' grouping */
    if ((rc = np_prepare_notif_common_session_parms(session, notif))) {
        goto cleanup;
    }

    /* create 'killed-by' node */
    if (nc_session_get_killed_by(session)) {
        sprintf(num32, "%" PRIu32, nc_session_get_killed_by(session));
        if (lyd_new_term(notif, notif->schema->module, "killed-by", num32, 0, NULL)) {
            rc = -1;
            goto cleanup;
        }
    }

    /* create 'termination-reason' node */
    switch (nc_session_get_term_reason(session)) {
    case NC_SESSION_TERM_CLOSED:
        value = "closed";
        break;
    case NC_SESSION_TERM_KILLED:
        value = "killed";
        break;
    case NC_SESSION_TERM_DROPPED:
        value = "dropped";
        break;
    case NC_SESSION_TERM_TIMEOUT:
        value = "timeout";
        break;
    default:
        value = "other";
        break;
    }
    if (lyd_new_term(notif, notif->schema->module, "termination-reason", value, 0, NULL)) {
        rc = -1;
        goto cleanup;
    }

    /* create 'session-type' leaf */
    mod = ly_ctx_get_module_implemented(ly_ctx, "netopeer-notifications");
    if (mod && lyd_new_term(notif, mod, "session-type", nc_session_is_callhome(session) ? "call-home" : "standard",
            0, NULL)) {
        goto cleanup;
    }

    /* send notification */
    if ((r = sr_notif_send_tree(sr_session, notif, sr_timeout, 0))) {
        WRN("Failed to send a notification (%s).", sr_strerror(r));
        rc = -1;
        goto cleanup;
    }

    VRB("Generated new event (netconf-session-end).");

cleanup:
    lyd_free_tree(notif);
    return rc;
}

int
np_send_notif_confirmed_commit(const struct nc_session *session, sr_session_ctx_t *sr_session, enum np_cc_event event,
        uint32_t cc_timeout, uint32_t sr_timeout)
{
    int rc = 0, r;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    struct lyd_node *notif = NULL;
    char num32[11]; /* max bytes for 32-bit unsigned number + \0 */
    char *value;

    /* get context */
    if (session) {
        ly_ctx = nc_session_get_ctx(session);
    } else {
        assert(event == NP_CC_TIMEOUT);
        ly_ctx = sr_session_acquire_context(sr_session);
    }

    /* get module */
    mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-netconf-notifications");
    if (!mod) {
        goto cleanup;
    }

    /* create 'netconf-confirmed-commit' notification */
    if (lyd_new_inner(NULL, mod, "netconf-confirmed-commit", 0, &notif)) {
        rc = -1;
        goto cleanup;
    }

    /* create 'common-session-parms' grouping */
    if ((event != NP_CC_TIMEOUT) && (rc = np_prepare_notif_common_session_parms(session, notif))) {
        goto cleanup;
    }

    /* create 'confirm-event' node */
    switch (event) {
    case NP_CC_START:
        value = "start";
        break;
    case NP_CC_CANCEL:
        value = "cancel";
        break;
    case NP_CC_TIMEOUT:
        value = "timeout";
        break;
    case NP_CC_EXTEND:
        value = "extend";
        break;
    case NP_CC_COMPLETE:
        value = "complete";
        break;
    default:
        rc = -1;
        goto cleanup;
    }
    if (lyd_new_term(notif, notif->schema->module, "confirm-event", value, 0, NULL)) {
        rc = -1;
        goto cleanup;
    }

    /* create 'timeout' node */
    if (cc_timeout) {
        assert((event == NP_CC_START) || (event == NP_CC_EXTEND));
        sprintf(num32, "%" PRIu32, cc_timeout);
        if (lyd_new_term(notif, notif->schema->module, "timeout", num32, 0, NULL)) {
            rc = -1;
            goto cleanup;
        }
    }

    /* send notification */
    if ((r = sr_notif_send_tree(sr_session, notif, sr_timeout, 0))) {
        WRN("Failed to send a notification (%s).", sr_strerror(r));
        rc = -1;
        goto cleanup;
    }

    VRB("Generated new event (netconf-confirmed-commit).");

cleanup:
    lyd_free_tree(notif);
    return rc;
}

int
np_send_notif_rpc(sr_session_ctx_t *sr_session, enum np_rpc_exec_stage stage, const char *rpc_name, const char *ds_str,
        uint32_t sr_timeout)
{
    int rc = 0, r;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    struct lyd_node *notif = NULL;

    /* get module */
    ly_ctx = sr_session_acquire_context(sr_session);
    sr_session_release_context(sr_session);
    mod = ly_ctx_get_module_implemented(ly_ctx, "netopeer-notifications");
    if (!mod) {
        goto cleanup;
    }

    /* notification */
    if (lyd_new_inner(NULL, mod, "netconf-rpc-execution", 0, &notif)) {
        rc = -1;
        goto cleanup;
    }

    /* stage-of-execution */
    switch (stage) {
    case NP_RPC_STAGE_PRE:
        if (lyd_new_term(notif, NULL, "pre-execution", NULL, 0, NULL)) {
            rc = -1;
            goto cleanup;
        }
        break;
    case NP_RPC_STAGE_POST_SUCCESS:
        if (lyd_new_term(notif, NULL, "post-execution", "success", 0, NULL)) {
            rc = -1;
            goto cleanup;
        }
        break;
    case NP_RPC_STAGE_POST_FAIL:
        if (lyd_new_term(notif, NULL, "post-execution", "fail", 0, NULL)) {
            rc = -1;
            goto cleanup;
        }
        break;
    }

    /* name */
    if (lyd_new_term(notif, NULL, "name", rpc_name, 0, NULL)) {
        rc = -1;
        goto cleanup;
    }

    /* datastore */
    if (ds_str && lyd_new_term(notif, NULL, "datastore", ds_str, 0, NULL)) {
        rc = -1;
        goto cleanup;
    }

    /* send the notification */
    if ((r = sr_notif_send_tree(sr_session, notif, sr_timeout, 0))) {
        WRN("Failed to send a notification (%s).", sr_strerror(r));
        rc = -1;
        goto cleanup;
    }

    VRB("Generated new event (%s %s).", (stage == NP_RPC_STAGE_PRE) ? "pre" : "post", rpc_name);

cleanup:
    lyd_free_tree(notif);
    return rc;
}

const struct ly_ctx *
np_acquire_ctx_cb(void *cb_data)
{
    return sr_acquire_context(cb_data);
}

void
np_release_ctx_cb(void *cb_data)
{
    sr_release_context(cb_data);
}

int
np_new_session_cb(const char *UNUSED(client_name), struct nc_session *new_session, void *UNUSED(user_data))
{
    int c;
    sr_session_ctx_t *sr_sess = NULL;
    struct np_user_sess *user_sess = NULL;
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
    user_sess->ntf_arg.nc_sess = new_session;

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

    /* generate ietf-netconf-notification's netconf-session-start event for sysrepo */
    np_send_notif_session_start(new_session, np2srv.sr_sess, np2srv.sr_timeout);

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

    return 0;

error:
    ncm_session_del(new_session);
    sr_session_stop(sr_sess);
    free(user_sess);
    return -1;
}

#ifdef NP2SRV_URL_CAPAB

int
np_url_setcap(void)
{
    uint32_t i, j;
    char *cpblt, *url_protocols = NULL;
    int len = 0;
    curl_version_info_data *curl_data;
    const char *main_cpblt = "urn:ietf:params:netconf:capability:url:1.0?scheme=";

# ifdef NP2SRV_URL_FILE_PROTO
    const char *url_protocols_all[] = {"file", "ftp", "ftps", "http", "https", "scp", "sftp"};
# else
    const char *url_protocols_all[] = {"ftp", "ftps", "http", "https", "scp", "sftp"};
# endif

    assert(!np2srv.url_protocols);

    curl_data = curl_version_info(CURLVERSION_NOW);
    for (i = 0; curl_data->protocols[i]; ++i) {
        for (j = 0; j < (sizeof url_protocols_all / sizeof *url_protocols_all); ++j) {
            if (!strcmp(curl_data->protocols[i], url_protocols_all[j])) {
                /* add supported protocol */
                url_protocols = realloc(url_protocols, len + (len ? 1 : 0) + strlen(url_protocols_all[j]) + 1);
                len += sprintf(url_protocols + len, "%s%s", len ? "," : "", url_protocols_all[j]);
                break;
            }
        }
    }
    if (!url_protocols) {
        /* no protocols supported */
        return 0;
    }

    /* generate the capability string and set it */
    if (asprintf(&cpblt, "%s%s", main_cpblt, url_protocols) == -1) {
        free(url_protocols);
        return 1;
    }
    nc_server_set_capability(cpblt);
    free(cpblt);

    /* store the supported URL protocols for libcurl */
    np2srv.url_protocols = url_protocols;
    return 0;
}

struct np_url_mem {
    char *memory;
    size_t size;
};

static size_t
url_writedata(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct np_url_mem *data = userdata;

    data->memory = realloc(data->memory, data->size + (size * nmemb) + 1);
    memcpy(data->memory + data->size, ptr, size * nmemb);
    data->size += size * nmemb;

    return size * nmemb;
}

static size_t
url_readdata(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t copied = 0, aux_size = size * nmemb;
    struct np_url_mem *data = userdata;

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
 * @brief Set supported protocols for libcurl.
 *
 * @param[in] curl CURL struct to modify.
 */
static void
url_set_protocols(CURL *curl)
{
#if CURL_AT_LEAST_VERSION(7, 85, 0)
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, np2srv.url_protocols);
#else
    long proto = 0;
    char *ptr, *ptr2;

    ptr = np2srv.url_protocols;
    do {
        ptr2 = strchr(ptr, ',');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }

        if (!strncmp(ptr, "file", ptr2 - ptr)) {
            proto |= CURLPROTO_FILE;
        } else if (!strncmp(ptr, "ftp", ptr2 - ptr)) {
            proto |= CURLPROTO_FTP;
        } else if (!strncmp(ptr, "ftps", ptr2 - ptr)) {
            proto |= CURLPROTO_FTPS;
        } else if (!strncmp(ptr, "http", ptr2 - ptr)) {
            proto |= CURLPROTO_HTTP;
        } else if (!strncmp(ptr, "https", ptr2 - ptr)) {
            proto |= CURLPROTO_HTTPS;
        } else if (!strncmp(ptr, "scp", ptr2 - ptr)) {
            proto |= CURLPROTO_SCP;
        } else if (!strncmp(ptr, "sftp", ptr2 - ptr)) {
            proto |= CURLPROTO_SFTP;
        }

        ptr = ptr2 + 1;
    } while (ptr2[0]);

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, proto);
#endif
}

/**
 * @brief Get a specific URL using curl.
 *
 * @param[in] ly_ctx Context for errors.
 * @param[in] url URL to open.
 * @param[out] url_data Data downloaded from the URL.
 * @return Error reply on error, NULL on success.
 */
static struct nc_server_reply *
url_get(const struct ly_ctx *ly_ctx, const char *url, char **url_data)
{
    struct nc_server_reply *reply = NULL;
    CURL *curl;
    char curl_buffer[CURL_ERROR_SIZE];
    struct np_url_mem mem_data = {0};

    if (!np2srv.url_protocols) {
        ERR("No URL protocols enabled.");
        return np_reply_err_op_failed(NULL, ly_ctx, "No URL protocols enabled.");
    }

    DBG("Getting file from URL: %s (via curl)", url);

    /* set up libcurl */
    curl_global_init(URL_INIT_FLAGS);
    curl = curl_easy_init();
    url_set_protocols(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, url_writedata);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem_data);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_buffer);

    /* download data */
    if (curl_easy_perform(curl) != CURLE_OK) {
        ERR("Failed to download data (curl: %s).", curl_buffer);
        reply = np_reply_err_op_failed(NULL, ly_ctx, curl_buffer);
        goto cleanup;
    }

    if (mem_data.memory) {
        /* add terminating zero */
        mem_data.memory[mem_data.size] = '\0';
    }

cleanup:
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    *url_data = mem_data.memory;
    return reply;
}

struct nc_server_reply *
np_op_parse_url(const struct ly_ctx *ly_ctx, const char *url, int validate, struct lyd_node **config)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node *node;
    struct lyd_node_opaq *opaq;
    char *url_data = NULL;

    if ((reply = url_get(ly_ctx, url, &url_data))) {
        goto cleanup;
    }

    /* load the whole config element */
    if (lyd_parse_data_mem(ly_ctx, url_data, LYD_XML, LYD_PARSE_OPAQ | LYD_PARSE_ONLY | LYD_PARSE_NO_STATE, 0, &node)) {
        reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
        goto cleanup;
    }

    if (!node || node->schema) {
        node = nc_err(ly_ctx, NC_ERR_MISSING_ELEM, NC_ERR_TYPE_APP, "config");
        reply = nc_server_reply_err(node);
        goto cleanup;
    }

    opaq = (struct lyd_node_opaq *)node;
    if (strcmp(opaq->name.name, "config")) {
        node = nc_err(ly_ctx, NC_ERR_UNKNOWN_ELEM, NC_ERR_TYPE_APP, opaq->name.name);
        reply = nc_server_reply_err(node);
        goto cleanup;
    } else if (strcmp(opaq->name.module_ns, "urn:ietf:params:xml:ns:netconf:base:1.0")) {
        node = nc_err(ly_ctx, NC_ERR_UNKNOWN_NS, NC_ERR_TYPE_APP, opaq->name.name, opaq->name.module_ns);
        reply = nc_server_reply_err(node);
        goto cleanup;
    }

    *config = opaq->child;
    lyd_unlink_siblings(*config);
    lyd_free_tree(node);

    if (validate) {
        /* separate validation if requested */
        if (lyd_validate_all(config, NULL, LYD_VALIDATE_NO_STATE, NULL)) {
            reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            goto cleanup;
        }
    }

cleanup:
    free(url_data);
    return reply;
}

struct nc_server_reply *
np_op_export_url(const struct ly_ctx *ly_ctx, const char *url, struct lyd_node *data, uint32_t print_options)
{
    struct nc_server_reply *reply = NULL;
    CURL *curl;
    struct np_url_mem mem_data;
    CURLcode r = 0;
    char curl_buffer[CURL_ERROR_SIZE], *str_data = NULL;
    struct lyd_node *config;

    if (!np2srv.url_protocols) {
        ERR("No URL protocols enabled.");
        return np_reply_err_op_failed(NULL, ly_ctx, "No URL protocols enabled.");
    }

    /* print the config as expected by the other end */
    if (lyd_new_opaq2(NULL, ly_ctx, "config", NULL, NULL, "urn:ietf:params:xml:ns:netconf:base:1.0", &config)) {
        return np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
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
    url_set_protocols(curl);
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_URL, url);
    }
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    }
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_READFUNCTION, url_readdata);
    }
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_READDATA, &mem_data);
    }
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_INFILESIZE, (long)mem_data.size);
    }
    if (!r) {
        r = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_buffer);
    }
    if (r) {
        ERR("Failed to set a curl option.");
        reply = np_reply_err_op_failed(NULL, ly_ctx, "Failed to set a curl option.");
        goto cleanup;
    }

    if (curl_easy_perform(curl)) {
        ERR("Failed to upload data (curl: %s).", curl_buffer);
        reply = np_reply_err_op_failed(NULL, ly_ctx, curl_buffer);
        goto cleanup;
    }

cleanup:
    free(str_data);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return reply;
}

#else

int
np_url_setcap(void)
{
    return EXIT_SUCCESS;
}

#endif

struct nc_server_reply *
np_op_parse_config(struct lyd_node_any *node, uint32_t parse_options, struct lyd_node **config)
{
    struct nc_server_reply *reply = NULL;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    sr_data_t *sr_ln2_nc_server = NULL;
    struct lyd_node *ignored_mod;
    char *xpath = NULL, *msg;
    struct ly_set *set = NULL;

    assert(node && node->schema && (node->schema->nodetype & LYD_NODE_ANY));

    if (!node->value.str) {
        /* nothing to do, no data */
        goto cleanup;
    }

    ly_ctx = LYD_CTX(node);

    /* get/parse the data */
    switch (node->value_type) {
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_XML:
        if (lyd_parse_data_mem(ly_ctx, node->value.str, LYD_XML, parse_options, 0, config)) {
            reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            goto cleanup;
        }
        break;
    case LYD_ANYDATA_DATATREE:
        if (lyd_dup_siblings(node->value.tree, NULL, LYD_DUP_RECURSIVE, config)) {
            reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            goto cleanup;
        }
        if (!(parse_options & (LYD_PARSE_ONLY | LYD_PARSE_OPAQ))) {
            /* separate validation if requested */
            if (lyd_validate_all(config, NULL, LYD_VALIDATE_NO_STATE, NULL)) {
                reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
                goto cleanup;
            }
        }
        break;
    case LYD_ANYDATA_LYB:
        if (lyd_parse_data_mem(ly_ctx, node->value.mem, LYD_LYB, parse_options, 0, config)) {
            reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            goto cleanup;
        }
        break;
    case LYD_ANYDATA_JSON:
        EINT;
        reply = np_reply_err_op_failed(NULL, ly_ctx, "Internal error.");
        goto cleanup;
    }

    if (*config) {
        /* get the list of ignored modules, skip NACM */
        if (sr_get_data(np2srv.sr_sess, "/libnetconf2-netconf-server:ln2-netconf-server/ignored-hello-module", 0,
                np2srv.sr_timeout, 0, &sr_ln2_nc_server)) {
            reply = np_reply_err_sr(np2srv.sr_sess, "get");
            goto cleanup;
        }

        if (sr_ln2_nc_server) {
            LY_LIST_FOR(lyd_child(sr_ln2_nc_server->tree), ignored_mod) {
                if (strcmp(LYD_NAME(ignored_mod), "ignored-hello-module")) {
                    continue;
                }

                ly_mod = ly_ctx_get_module_implemented(ly_ctx, lyd_get_value(ignored_mod));
                if (!ly_mod) {
                    /* module not implemented or not in the context */
                    continue;
                }

                /* find any module data */
                if (asprintf(&xpath, "/%s:*", ly_mod->name) == -1) {
                    reply = np_reply_err_op_failed(NULL, ly_ctx, "Memory allocation failed.");
                    goto cleanup;
                }
                if (lyd_find_xpath(*config, xpath, &set)) {
                    reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
                    goto cleanup;
                }

                if (set->count) {
                    /* invalid data */
                    if (asprintf(&msg, "Config includes data of the module \"%s\" that is not supported by NETCONF.",
                            ly_mod->name) == -1) {
                        msg = NULL;
                    }
                    reply = np_reply_err_invalid_val(ly_ctx, msg, LYD_NAME(set->dnodes[0]));
                    free(msg);
                    goto cleanup;
                }

                /* next iter */
                free(xpath);
                xpath = NULL;
                ly_set_free(set, NULL);
                set = NULL;
            }
        }
    }

cleanup:
    sr_release_data(sr_ln2_nc_server);
    free(xpath);
    ly_set_free(set, NULL);
    return reply;
}

/**
 * @brief Remove any data referencing or belonging to a module that should be ignored for NETCONF.
 *
 * @param[in,out] data Data tree to modify.
 * @param[in] ignored_mod Name of the ignored module.
 */
static void
np_op_filter_data_ignored_mod(struct lyd_node **data, const char *ignored_mod)
{
    const struct lys_module *ly_mod;
    struct ly_set *set = NULL;
    char *xpath = NULL;
    uint32_t i;

    ly_mod = ly_ctx_get_module_implemented(LYD_CTX(*data), ignored_mod);
    if (!ly_mod) {
        /* module not implemented or not in the context */
        goto cleanup;
    }

    /* remove from ietf-yang-library data and the module's data directly */
    if (asprintf(&xpath, "/ietf-yang-library:yang-library/module-set/module[name='%s'] | "
            "/ietf-yang-library:modules-state/module[conformance-type='implement'][name='%s'] | "
            "/sysrepo-monitoring:sysrepo-state/module[name='%s'] |"
            "/ietf-netconf-monitoring:netconf-state/schemas/schema[identifier='%s'] |"
            "/%s:*", ly_mod->name, ly_mod->name, ly_mod->name, ly_mod->name, ly_mod->name) == -1) {
        goto cleanup;
    }
    if (lyd_find_xpath(*data, xpath, &set)) {
        goto cleanup;
    }

    /* just free all the found nodes */
    for (i = 0; i < set->count; ++i) {
        if (set->dnodes[i] == *data) {
            *data = (*data)->next;
        }
        lyd_free_tree(set->dnodes[i]);
    }

cleanup:
    free(xpath);
    ly_set_free(set, NULL);
}

struct nc_server_reply *
np_op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts, const char *xp_filter,
        struct lyd_node **data)
{
    sr_data_t *sr_data = NULL, *sr_ln2_nc_server = NULL;
    struct lyd_node *e, *ignored_mod;
    const sr_error_info_t *err_info;
    const sr_error_info_err_t *err;
    struct nc_server_reply *reply = NULL;
    int r;

    if (!xp_filter) {
        /* empty filter matches no data */
        return NULL;
    }

    /* get the selected data */
    r = sr_get_data(session, xp_filter, max_depth, np2srv.sr_timeout, get_opts, &sr_data);
    if (r && (r != SR_ERR_NOT_FOUND)) {
        ERR("Getting data \"%s\" from sysrepo failed (%s).", xp_filter, sr_strerror(r));

        sr_session_get_error(session, &err_info);
        err = &err_info->err[0];
        if (strstr(err->message, " result is not a node set.")) {
            /* invalid-value */
            e = nc_err(sr_session_acquire_context(session), NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
            sr_session_release_context(session);
            nc_err_set_msg(e, err->message, "en");
            reply = nc_server_reply_err(e);
        } else {
            /* other error */
            reply = np_reply_err_sr(session, "get");
        }
        goto cleanup;
    }

    if (sr_data) {
        /* get the list of ignored modules, skip NACM */
        if (sr_get_data(np2srv.sr_sess, "/libnetconf2-netconf-server:ln2-netconf-server/ignored-hello-module", 0,
                np2srv.sr_timeout, 0, &sr_ln2_nc_server)) {
            reply = np_reply_err_sr(np2srv.sr_sess, "get");
            goto cleanup;
        }
        if (sr_ln2_nc_server) {
            LY_LIST_FOR(lyd_child(sr_ln2_nc_server->tree), ignored_mod) {
                if (strcmp(LYD_NAME(ignored_mod), "ignored-hello-module")) {
                    continue;
                }

                /* remove data connected with the module */
                np_op_filter_data_ignored_mod(&sr_data->tree, lyd_get_value(ignored_mod));
            }
        }

        /* merge */
        r = lyd_merge_siblings(data, sr_data->tree, LYD_MERGE_DESTRUCT);
        sr_data->tree = NULL;
        sr_release_data(sr_data);
        if (r) {
            /* other error */
            reply = np_reply_err_op_failed(session, NULL, ly_last_logmsg());
            goto cleanup;
        }
    }

cleanup:
    sr_release_data(sr_ln2_nc_server);
    return reply;
}

struct nc_server_reply *
np_reply_success(const struct lyd_node *rpc, struct lyd_node *output)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node *node;
    NC_WD_MODE nc_wd;

    if (output) {
        /* get with-defaults mode */
        if (!strcmp(rpc->schema->module->name, "ietf-netconf")) {
            /* augment */
            lyd_find_path(rpc, "ietf-netconf-with-defaults:with-defaults", 0, &node);
        } else if (!lys_find_child(rpc->schema, rpc->schema->module, "with-defaults", 0, LYS_LEAF, 0)) {
            /* no with-defaults mode */
            node = NULL;
        } else {
            /* grouping */
            lyd_find_path(rpc, "with-defaults", 0, &node);
        }
        if (node) {
            if (!strcmp(lyd_get_value(node), "report-all")) {
                nc_wd = NC_WD_ALL;
            } else if (!strcmp(lyd_get_value(node), "report-all-tagged")) {
                nc_wd = NC_WD_ALL_TAG;
            } else if (!strcmp(lyd_get_value(node), "trim")) {
                nc_wd = NC_WD_TRIM;
            } else {
                nc_wd = NC_WD_EXPLICIT;
            }
        } else {
            nc_server_get_capab_withdefaults(&nc_wd, NULL);
        }

        /* data reply owning 'output' */
        reply = nc_server_reply_data(output, nc_wd, NC_PARAMTYPE_FREE);
    } else {
        /* OK reply */
        reply = nc_server_reply_ok();
    }

    return reply;
}

/**
 * @brief Find the nth substring delimited by quotes.
 *
 * For example: abcd"ef"ghij"kl"mn -> index 0 is "ef", index 1 is "kl".
 *
 * @param[in] msg Input string with quoted substring.
 * @param[in] index Number starting from 0 specifying the nth substring.
 * @return Copied nth substring without quotes.
 */
static char *
np_err_reply_get_quoted_string(const char *msg, uint32_t index)
{
    const char *start = NULL, *end = NULL, *iter, *tmp;
    uint32_t quote_cnt = 0, last_quote;

    assert(msg);

    last_quote = (index + 1) * 2;
    for (iter = msg; *iter; ++iter) {
        if (*iter != '\"') {
            continue;
        }
        /* updating the start and end pointers - swap */
        tmp = end;
        end = iter;
        start = tmp;
        if (++quote_cnt == last_quote) {
            /* nth substring found */
            break;
        }
    }

    if (!start) {
        return NULL;
    }

    /* skip the first quote */
    ++start;

    /* copy substring */
    return strndup(start, end - start);
}

/**
 * @brief Create NC rpc-error by specifying all the fields.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] error_type NETCONF error-type.
 * @param[in] error_tag NETCONF error-tag.
 * @param[in] error_app_tag NETCONF error-app-tag.
 * @param[in] error_path NETCONF error-path.
 * @param[in] error_message NETCONF error-message.
 * @param[in] error_info_elem Array of NETCONF error-info elements.
 * @param[in] error_info_val Array of NETCONF error-info element values.
 * @param[in] error_info_count Count of items in @p error_info_elem and @p error_info_val.
 * @return NC rpc-error opaque node tree.
 */
static struct lyd_node *
np_err_create(const struct ly_ctx *ly_ctx, const char *error_type, const char *error_tag, const char *error_app_tag,
        const char *error_path, const char *error_message, const char **error_info_elem, const char **error_info_val,
        uint32_t error_info_count)
{
    struct lyd_node *e_first = NULL, *e, *err_info;
    const char *ns;
    uint32_t i;

    /* rpc-error */
    if (lyd_new_opaq2(NULL, ly_ctx, "rpc-error", NULL, NULL, NC_NS_BASE, &e)) {
        goto error;
    }

    /* error-type */
    if (lyd_new_opaq2(e, NULL, "error-type", error_type, NULL, NC_NS_BASE, NULL)) {
        goto error;
    }

    /* error-tag */
    if (lyd_new_opaq2(e, NULL, "error-tag", error_tag, NULL, NC_NS_BASE, NULL)) {
        goto error;
    }

    /* error-severity */
    if (lyd_new_opaq2(e, NULL, "error-severity", "error", NULL, NC_NS_BASE, NULL)) {
        goto error;
    }

    if (error_app_tag) {
        /* error-app-tag */
        if (nc_err_set_app_tag(e, error_app_tag)) {
            goto error;
        }
    }

    if (error_path) {
        /* error-path */
        if (nc_err_set_path(e, error_path)) {
            goto error;
        }
    }

    /* error-message */
    if (nc_err_set_msg(e, error_message, "en")) {
        goto error;
    }

    /* error-info */
    err_info = NULL;
    for (i = 0; i < error_info_count; ++i) {
        if (!err_info) {
            if (lyd_new_opaq2(e, NULL, "error-info", NULL, NULL, NC_NS_BASE, &err_info)) {
                goto error;
            }
        }
        if (!strcmp(error_info_elem[i], "bad-attribute") || !strcmp(error_info_elem[i], "bad-element") ||
                !strcmp(error_info_elem[i], "bad-namespace") || !strcmp(error_info_elem[i], "session-id")) {
            /* NETCONF error-info */
            ns = NC_NS_BASE;
        } else if (!strcmp(error_info_elem[i], "non-unique") || !strcmp(error_info_elem[i], "missing-choice")) {
            /* YANG error-info */
            ns = "urn:ietf:params:xml:ns:yang:1";
        } else {
            /* custom (unknown) */
            ns = "urn:netconf:custom-error-info";
        }
        if (lyd_new_opaq2(err_info, NULL, error_info_elem[i], error_info_val[i], NULL, ns, NULL)) {
            goto error;
        }
    }

    /* append */
    lyd_insert_sibling(e_first, e, &e_first);

    return e_first;

error:
    lyd_free_siblings(e_first);
    return NULL;
}

/**
 * @brief Create NC rpc-error from a SR error.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] err_msg Error message.
 * @param[in] err_code Error code.
 * @param[in] err_path Optional error path.
 * @param[in] rpc_name Failed RPC name.
 * @return NC rpc-error opaque node tree.
 */
static struct lyd_node *
np_err(const struct ly_ctx *ly_ctx, const char *err_msg, int err_code, const char *err_path, const char *rpc_name)
{
    struct lyd_node *e = NULL;
    const struct lysc_node *cn;
    char *ptr, *str = NULL, *str2 = NULL;
    struct nc_session *nc_sess;
    const char *err_info_elem[2], *err_info_val[2], *err_type, *err_tag, *msg;

    if (!strncmp(err_msg, "Unique data leaf(s)", 19)) {
        /* data-not-unique */
        assert(err_path);
        err_info_elem[0] = "non-unique";
        err_info_val[0] = err_path;
        e = np_err_create(ly_ctx, "protocol", "operation-failed", "data-not-unique", NULL,
                "Unique constraint violated.", err_info_elem, err_info_val, 1);
    } else if (!strncmp(err_msg, "Too many", 8)) {
        /* too-many-elements */
        assert(err_path);
        e = np_err_create(ly_ctx, "protocol", "operation-failed", "too-many-elements", err_path, "Too many elements.",
                NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Too few", 7)) {
        /* too-few-elements */
        assert(err_path);
        e = np_err_create(ly_ctx, "protocol", "operation-failed", "too-few-elements", err_path, "Too few elements.",
                NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Must condition", 14)) {
        /* get the must condition error message */
        ptr = strrchr(err_msg, '(');
        --ptr;
        str = strndup(err_msg, ptr - err_msg);

        /* must-violation */
        assert(err_path);
        e = np_err_create(ly_ctx, "protocol", "operation-failed", "must-violation", err_path, str, NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Invalid leafref value", 21) && strstr(err_msg, "no target instance")) {
        /* get the value */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* create error message */
        if (asprintf(&str2, "Required leafref target with value \"%s\" missing.", str) == -1) {
            goto cleanup;
        }

        /* instance-required */
        assert(err_path);
        e = np_err_create(ly_ctx, "protocol", "data-missing", "instance-required", err_path, str2, NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Invalid instance-identifier", 26) && strstr(err_msg, "required instance not found")) {
        /* get the value */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* create error message */
        if (asprintf(&str2, "Required instance-identifier \"%s\" missing.", str) == -1) {
            goto cleanup;
        }

        /* instance-required */
        assert(err_path);
        e = np_err_create(ly_ctx, "protocol", "data-missing", "instance-required", err_path, str2, NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Mandatory choice", 16)) {
        /* get the choice */
        assert(err_path);
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* missing-choice */
        err_info_elem[0] = "missing-choice";
        err_info_val[0] = str;
        e = np_err_create(ly_ctx, "protocol", "data-missing", "mandatory-choice", err_path, "Missing mandatory choice.",
                err_info_elem, err_info_val, 1);
    } else if (strstr(err_msg, "instance to insert next to not found.")) {
        /* get the node name */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* create error message */
        if (asprintf(&str2, "Missing insert anchor \"%s\" instance.", str) == -1) {
            goto cleanup;
        }

        /* missing-instance */
        e = np_err_create(ly_ctx, "protocol", "bad-attribute", "missing-instance", NULL, str2, NULL, NULL, 0);
    } else if (!strncmp(err_msg, "Invalid non-", 12) || !strncmp(err_msg, "Invalid type", 12) ||
            !strncmp(err_msg, "Unsatisfied range", 17) || !strncmp(err_msg, "Unsatisfied pattern", 19) ||
            strstr(err_msg, "min/max bounds")) {
        /* create error message */
        ptr = strrchr(err_msg, '(');
        if (ptr) {
            str = strndup(err_msg, (ptr - 1) - err_msg);
        }

        /* get element name */
        assert(err_path);
        ptr = strrchr(err_path, ':');
        if (!ptr) {
            ptr = strrchr(err_path, '/');
        }
        assert(ptr);
        ++ptr;

        /* bad-element */
        err_info_elem[0] = "bad-element";
        err_info_val[0] = ptr;
        e = np_err_create(ly_ctx, "application", "bad-element", NULL, err_path, str ? str : err_msg, err_info_elem,
                err_info_val, 1);
    } else if (!strncmp(err_msg, "Node \"", 6) && strstr(err_msg, " not found")) {
        /* get the node name */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* unknown-element */
        err_info_elem[0] = "bad-element";
        err_info_val[0] = str;
        e = np_err_create(ly_ctx, "application", "unknown-element", NULL, NULL, err_msg, err_info_elem,
                err_info_val, 1);
    } else if (!strncmp(err_msg, "No (implemented) module with namespace", 38)) {
        /* get the namespace */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* get the node name */
        str2 = np_err_reply_get_quoted_string(err_msg, 1);

        /* unknown-namespace */
        err_info_elem[0] = "bad-element";
        err_info_val[0] = str2;
        err_info_elem[1] = "bad-namespace";
        err_info_val[1] = str;
        e = np_err_create(ly_ctx, "application", "unknown-namespace", NULL, NULL, "An unexpected namespace is present.",
                err_info_elem, err_info_val, 2);
    } else if (!strncmp(err_msg, "Mandatory node", 14)) {
        /* missing-element */
        str = np_err_reply_get_quoted_string(err_msg, 0);

        /* get error type */
        cn = lys_find_path(ly_ctx, NULL, err_path, 0);
        if (cn && ((cn->nodetype & LYS_RPC) || (cn->nodetype & LYS_INPUT))) {
            err_type = "protocol";
        } else {
            err_type = "application";
        }

        /* missing-element */
        err_info_elem[0] = "bad-element";
        err_info_val[0] = str;
        e = np_err_create(ly_ctx, err_type, "missing-element", NULL, err_path, "An expected element is missing.",
                err_info_elem, err_info_val, 1);
    } else if ((ptr = strstr(err_msg, "DS-locked by session "))) {
        /* get NC SID based on SR SID */
        np_get_nc_sess_by_id(atoi(ptr + 21), 0, __func__, &nc_sess);
        if (asprintf(&str, "%" PRIu32, nc_sess ? nc_session_get_id(nc_sess) : 0) == -1) {
            goto cleanup;
        }

        /* get error tag/message */
        if (!strcmp(rpc_name, "commit")) {
            err_tag = "in-use";
            msg = "The request requires a resource that already is in use.";
        } else {
            err_tag = "lock-denied";
            msg = "Access to the requested lock is denied because the lock is currently held by another entity.";
        }

        /* in-use/lock-denied */
        err_info_elem[0] = "session-id";
        err_info_val[0] = str;
        e = np_err_create(ly_ctx, "protocol", err_tag, NULL, NULL, msg, err_info_elem, err_info_val, 1);
    } else if (strstr(err_msg, "to be created already exists.")) {
        /* data-exists */
        e = np_err_create(ly_ctx, "protocol", "data-exists", NULL, NULL, err_msg, NULL, NULL, 0);
    } else if (strstr(err_msg, "does not exist.")) {
        /* data-missing */
        e = np_err_create(ly_ctx, "protocol", "data-missing", NULL, NULL, err_msg, NULL, NULL, 0);
    } else if (err_code == SR_ERR_NO_MEMORY) {
        /* resource-denied */
        e = np_err_create(ly_ctx, "application", "resource-denied", NULL, NULL, err_msg, NULL, NULL, 0);
    } else {
        /* generic error */
        e = np_err_create(ly_ctx, "application", "operation-failed", NULL, NULL, err_msg, NULL, NULL, 0);
    }

cleanup:
    free(str);
    free(str2);
    return e;
}

struct nc_server_reply *
np_reply_err_sr(sr_session_ctx_t *session, const char *rpc_name)
{
    struct nc_server_reply *reply = NULL;
    const sr_error_info_t *err_info;
    struct lyd_node *e;
    const struct ly_ctx *ly_ctx;
    const char *ptr, *err_type, *err_tag, *err_app_tag, *err_path, *err_msg, **err_info_elem = NULL, **err_info_val = NULL;
    char *path = NULL;
    size_t i;
    uint32_t err_info_count;

    ly_ctx = sr_acquire_context(np2srv.sr_conn);

    /* get the error from the session */
    sr_session_get_error(session, &err_info);

    /* try to find a NETCONF error(s) */
    for (i = 0; i < err_info->err_count; ++i) {
        if (err_info->err[i].error_format && !strcmp(err_info->err[i].error_format, "NETCONF")) {
            /* NETCONF error, read it */
            if (sr_err_get_netconf_error(&err_info->err[i], &err_type, &err_tag, &err_app_tag, &err_path, &err_msg,
                    &err_info_elem, &err_info_val, &err_info_count)) {
                goto cleanup;
            }
            e = np_err_create(ly_ctx, err_type, err_tag, err_app_tag, err_path, err_msg, err_info_elem, err_info_val,
                    err_info_count);
            free(err_info_elem);
            free(err_info_val);
        } else {
            /* get path */
            if ((ptr = strstr(err_info->err[i].message, "(path \""))) {
                ptr += 7;
            }
            if (ptr) {
                path = strndup(ptr, strchr(ptr, '\"') - ptr);
            }

            /* sysrepo/libyang error, create a NETCONF error if possible */
            e = np_err(ly_ctx, err_info->err[i].message, err_info->err[i].err_code, path, rpc_name);
            free(path);
            path = NULL;
        }
        if (!e) {
            /* no memory */
            goto cleanup;
        }

        /* add into the error reply */
        if (reply) {
            nc_server_reply_add_err(reply, e);
        } else {
            reply = nc_server_reply_err(e);
        }
    }

cleanup:
    sr_release_context(np2srv.sr_conn);
    return reply;
}

struct nc_server_reply *
np_reply_err_valid(const struct ly_ctx *ly_ctx)
{
    struct nc_server_reply *reply = NULL;
    const struct ly_err_item *eitem;
    struct lyd_node *e;

    for (eitem = ly_err_first(ly_ctx); eitem; eitem = eitem->next) {
        /* create a NETCONF error */
        e = np_err(ly_ctx, eitem->msg, SR_ERR_OPERATION_FAILED, eitem->data_path, "validate");

        /* add into the error reply */
        if (reply) {
            nc_server_reply_add_err(reply, e);
        } else {
            reply = nc_server_reply_err(e);
        }
    }

    return reply;
}

struct nc_server_reply *
np_reply_err_op_failed(sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, const char *msg)
{
    struct lyd_node *e;

    assert(session || ly_ctx);

    e = nc_err(ly_ctx ? ly_ctx : sr_session_acquire_context(session), NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    if (!ly_ctx) {
        sr_session_release_context(session);
    }

    nc_err_set_msg(e, msg, "en");
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_invalid_val(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem)
{
    struct lyd_node *e;

    e = nc_err(ly_ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, msg, "en");
    if (bad_elem) {
        nc_err_add_bad_elem(e, bad_elem);
    }
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_lock_denied(const struct ly_ctx *ly_ctx, const char *msg, uint32_t nc_id)
{
    struct lyd_node *e;

    e = nc_err(ly_ctx, NC_ERR_LOCK_DENIED, NC_ERR_TYPE_APP, nc_id);
    nc_err_set_msg(e, msg, "en");
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_missing_attr(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_attr, const char *bad_elem)
{
    struct lyd_node *e;

    e = nc_err(ly_ctx, NC_ERR_MISSING_ATTR, NC_ERR_TYPE_PROT, bad_attr, bad_elem);
    nc_err_set_msg(e, msg, "en");
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_missing_elem(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem)
{
    struct lyd_node *e;

    e = nc_err(ly_ctx, NC_ERR_MISSING_ELEM, NC_ERR_TYPE_PROT, bad_elem);
    nc_err_set_msg(e, msg, "en");
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_bad_elem(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem)
{
    struct lyd_node *e;

    e = nc_err(ly_ctx, NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, bad_elem);
    nc_err_set_msg(e, msg, "en");
    return nc_server_reply_err(e);
}

struct nc_server_reply *
np_reply_err_in_use(const struct ly_ctx *ly_ctx, const char *msg, uint32_t sr_id)
{
    struct lyd_node *e;
    struct nc_session *nc_sess;

    /* error info session ID */
    np_get_nc_sess_by_id(sr_id, 0, __func__, &nc_sess);

    e = nc_err(ly_ctx, NC_ERR_IN_USE, NC_ERR_TYPE_PROT);
    nc_err_set_msg(e, msg, "en");
    if (nc_sess) {
        nc_err_set_sid(e, nc_session_get_id(nc_sess));
    }
    return nc_server_reply_err(e);
}
