/**
 * @file common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common structures and functions
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

#ifndef NP2SRV_COMMON_H_
#define NP2SRV_COMMON_H_

#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <nc_server.h>
#include <sysrepo.h>

#include "compat.h"
#include "config.h"

struct np_ps_match_data {
    uint32_t sr_id;
    uint32_t nc_id;
};

struct np_rt_notif {
    struct lyd_node *notif;
    struct timespec timestamp;
};

struct np_ntf_arg {
    struct nc_session *nc_sess;
    uint32_t sr_sub_count;
    ATOMIC_T sr_ntf_replay_complete_count;
    ATOMIC_T sr_ntf_stop_count;

    struct np_rt_notif *rt_notifs;  /* buffered realtime notifications received before replay complete */
    uint32_t rt_notif_count;
};

/* user session structure assigned as data of NC sessions */
struct np_user_sess {
    sr_session_ctx_t *sess;
    ATOMIC_T ref_count;
    pthread_mutex_t lock;

    struct np_ntf_arg ntf_arg;
};

/* server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;         /**< sysrepo connection */
    sr_session_ctx_t *sr_sess;      /**< sysrepo server session */
    sr_subscription_ctx_t *sr_data_sub; /**< sysrepo data subscription context */
    sr_subscription_ctx_t *sr_nacm_stats_sub;   /**< sysrepo NACM global stats subscription context */
    sr_subscription_ctx_t *sr_notif_sub;    /**< sysrepo notification subscription context */

    const char *unix_path;          /**< path to the UNIX socket to listen on */
    mode_t unix_mode;               /**< UNIX socket mode */
    uid_t unix_uid;                 /**< UNIX socket UID */
    gid_t unix_gid;                 /**< UNIX socket GID */

    uint32_t sr_timeout;            /**< timeout in ms for all sysrepo functions */
    const char *ext_data_path;      /**< path to the data file with data for LY ext data callback */

    const char *server_dir;         /**< path to server files (just confirmed commit for the moment) */
    char *url_protocols;           /**< list of supported URL protocols */

    struct nc_pollsession *nc_ps;   /**< libnetconf2 pollsession structure */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};

extern struct np2srv np2srv;

/**
 * @brief Sleep in milliseconds.
 *
 * @param[in] ms Milliseconds to sleep.
 * @return 0 on success;
 * @return -1 on error.
 */
int np_sleep(uint32_t ms);

/**
 * @brief Get current real or monotonic time, monotic preferred if available.
 *
 * @param[in] force_real If set, realtime is always returned.
 * @return Current time in timespec.
 */
struct timespec np_gettimespec(int force_real);

/**
 * @brief Get the difference between 2 timestamps in milliseconds.
 *
 * @param[in] ts1 First timestamp.
 * @param[in] ts2 Second timestamp.
 * @return Difference in milliseconds, positive if @p ts1 < @p ts2, negative if @p ts1 > @p ts2.
 */
int64_t np_difftimespec(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Add milliseconds to a timestamp.
 *
 * @param[in] ts Timestamp to modify.
 * @param[in] msec Milliseconds to add to @p ts.
 */
void np_addtimespec(struct timespec *ts, uint32_t msec);

/**
 * @brief Get the remainder (operation modulo) after dividing timestamp by milliseconds.
 *
 * @param[in] ts Timestamp to divide.
 * @param[in] msec Interval in milliseconds to divide @p ts by.
 * @return Result of @p ts % @p msec in milliseconds.
 */
struct timespec np_modtimespec(const struct timespec *ts, uint32_t msec);

/**
 * @brief Get NC session by SR or NC session ID.
 *
 * @param[in] sr_id Search by sysrepo SID, set only if @p nc_id is 0.
 * @param[in] nc_id Search by NETCONF SID, set only if @p sr_id is 0.
 * @param[in] func Caller function, for logging.
 * @param[out] nc_sess Found NETCONF session.
 * @return SR error value, logs only if @p nc_id is set.
 */
int np_get_nc_sess_by_id(uint32_t sr_id, uint32_t nc_id, const char *func, struct nc_session **nc_sess);

/**
 * @brief Get SR user session from a NC session.
 *
 * Increases refcount of the session, needs ::np_release_user_sess() call to decrease.
 *
 * @param[in] nc_sess NC session to use.
 * @param[out] user_sess Sysrepo user session.
 * @return SR error value.
 */
int np_acquire_user_sess(const struct nc_session *ncs, struct np_user_sess **user_sess);

/**
 * @brief Release SR user session, free if no longer referenced.
 *
 * Decreases refcount after ::np_find_user_sess() or ::np_acquire_user_sess() call.
 *
 * @param[in] user_sess Sysrepo user session.
 */
void np_release_user_sess(struct np_user_sess *user_sess);

/**
 * @brief Learn whether a module includes any notification definitions.
 *
 * @param[in] mod Module to examine.
 * @return non-zero if there are some notifications;
 * @return 0 if there are no notifications.
 */
int np_ly_mod_has_notif(const struct lys_module *mod);

/**
 * @brief Learn whether a module includes any data node definitions.
 *
 * @param[in] mod Module to examine.
 * @param[in] config_mask Required config mask of the data nodes.
 * @return non-zero if there are some data;
 * @return 0 if there are no data.
 */
int np_ly_mod_has_data(const struct lys_module *mod, uint32_t config_mask);

/**
 * @brief Add a notification duplicate into an array.
 *
 * @param[in] notif Notification to store.
 * @param[in] timestamp Notification timestamp.
 * @param[in,out] ntfs Notification array to add to.
 * @param[in,out] ntf_count Count of notifications in @p ntfs.
 * @return SR error value.
 */
int np_ntf_add_dup(const struct lyd_node *notif, const struct timespec *timestamp, struct np_rt_notif **ntfs,
        uint32_t *ntf_count);

/**
 * @brief Send a notification to a NETCONF client.
 *
 * @param[in] ncs NC session to use.
 * @param[in] timestamp Notification timestamp.
 * @param[in,out] ly_ntf Notification to send, may be spent.
 * @param[in] use_ntf Whether to spend @p ly_ntf or not.
 * @return SR error value.
 */
int np_ntf_send(struct nc_session *ncs, const struct timespec *timestamp, struct lyd_node **ly_ntf, int use_ntf);

/**
 * @brief Send notification netconf-session-start.
 *
 * @param[in] new_session Created NC session.
 * @param[in] sr_session Sysrepo server session.
 * @param[in] sr_timeout Notification callback timeout in milliseconds.
 * @return 0 on success.
 */
int np_send_notif_session_start(const struct nc_session *new_session, sr_session_ctx_t *sr_session, uint32_t sr_timeout);

/**
 * @brief Send notification netconf-session-end.
 *
 * @param[in] new_session NC session.
 * @param[in] sr_session Sysrepo server session.
 * @param[in] sr_timeout Notification callback timeout in milliseconds.
 * @return 0 on success.
 */
int np_send_notif_session_end(const struct nc_session *session, sr_session_ctx_t *sr_session, uint32_t sr_timeout);

enum np_cc_event {
    NP_CC_START = 0,    /**< The confirmed-commit has started. */
    NP_CC_CANCEL,       /**< The confirmed-commit has been canceled, e.g., due to the session being terminated,
                             or an explicit <cancel-commit> operation. */
    NP_CC_TIMEOUT,      /**< The confirmed-commit has been canceled due to the confirm-timeout interval expiring. */
    NP_CC_EXTEND,       /**< The confirmed-commit timeout has been extended, e.g., by a new <confirmed-commit> operation. */
    NP_CC_COMPLETE      /**< The confirmed-commit has been completed. */
};

/**
 * @brief Send notification netconf-confirmed-commit.
 *
 * @param[in] new_session NC session. For :NP_CC_TIMEOUT can be NULL.
 * @param[in] sr_session Sysrepo session.
 * @param[in] event Type of confirm-commit event.
 * @param[in] cc_timout For event :NP_CC_START or :NP_CC_EXTEND. Number of seconds when the confirmed-commit 'timeout'
 * event might occur.
 * @param[in] sr_timeout Notification callback timeout in milliseconds.
 * @return 0 on success.
 */
int np_send_notif_confirmed_commit(const struct nc_session *session, sr_session_ctx_t *sr_session,
        enum np_cc_event event, uint32_t cc_timeout, uint32_t sr_timeout);

enum np_rpc_exec_stage {
    NP_RPC_STAGE_PRE,           /**< pre-RPC execution */
    NP_RPC_STAGE_POST_SUCCESS,  /**< post-RPC successful execution */
    NP_RPC_STAGE_POST_FAIL      /**< post-RPC failed execution */
};

/**
 * @brief Send notification netconf-rpc-execution.
 *
 * @param[in] sr_session Sysrepo session.
 * @param[in] stage RPC execution stage.
 * @param[in] rpc_name Executed RPC name.
 * @param[in] ds_str Optional relevant RPC datastore.
 * @param[in] sr_timeout Notification callback timeout in milliseconds.
 * @return 0 on success;
 * @return -1 on error.
 */
int np_send_notif_rpc(sr_session_ctx_t *sr_session, enum np_rpc_exec_stage stage, const char *rpc_name,
        const char *ds_str, uint32_t sr_timeout);

/**
 * @brief NP2 callback for acquiring context.
 */
const struct ly_ctx *np_acquire_ctx_cb(void *cb_data);

/**
 * @brief NP2 callback for releasing context.
 */
void np_release_ctx_cb(void *cb_data);

/**
 * @brief NP2 callback for a new session creation.
 *
 * @param[in] client_name CH client name, unused.
 * @param[in] new_session Created NC session.
 * @param[in] user_data Arbitrary data, unused.
 * @return 0 on success;
 * @return -1 on error.
 */
int np_new_session_cb(const char *client_name, struct nc_session *new_session, void *user_data);

/**
 * @brief Set URL capability to be advertised for new NETCONF sessions.
 *
 * @return 0 on success;
 * @return -1 on error.
 */
int np_url_setcap(void);

#ifdef NP2SRV_URL_CAPAB

/**
 * @brief Parse YANG data found at an URL (encapsulated in `config` element).
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] url URL to access.
 * @param[in] validate Whether to validate nested data.
 * @param[out] config Parsed data.
 * @return Error reply on error, NULL on success.
 */
struct nc_server_reply *np_op_parse_url(const struct ly_ctx *ly_ctx, const char *url, int validate, struct lyd_node **config);

/**
 * @brief Upload YANG data to an URL (encapsulated in `config` element).
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] url URL to upload to.
 * @param[in] data Data to upload, are temporarily modified.
 * @param[in] print_options Options for printing the data.
 * @return Error reply on error, NULL on success.
 */
struct nc_server_reply *np_op_export_url(const struct ly_ctx *ly_ctx, const char *url, struct lyd_node *data,
        uint32_t print_options);

#endif

/**
 * @brief Parse YANG data in a `config` YANG anyxml node.
 *
 * @param[in] node Config node with the data.
 * @param[in] parse_options Options for parsing the data.
 * @param[out] config Parsed data.
 * @return Error reply on error, NULL on success.
 */
struct nc_server_reply *np_op_parse_config(struct lyd_node_any *node, uint32_t parse_options, struct lyd_node **config);

/**
 * @brief Get all data matching the NP2 filter.
 *
 * @param[in] session SR session to get the data on.
 * @param[in] max_depth Max depth fo the retrieved data.
 * @param[in] get_opts SR get options to use.
 * @param[in] xp_filter XPath filter to use.
 * @param[out] data Retrieved data.
 * @return Error reply on error, NULL on success.
 */
struct nc_server_reply *np_op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts,
        const char *xp_filter, struct lyd_node **data);

/**
 * @brief Create NC data/OK reply.
 *
 * @param[in] rpc Executed RPC.
 * @param[in] output RPC output data, if any. Always spent.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_success(const struct lyd_node *rpc, struct lyd_node *output);

/**
 * @brief Create NC error reply based on SR error info.
 *
 * @param[in] session Session to read the error from.
 * @param[in] rpc_name Failed RPC name.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_sr(sr_session_ctx_t *session, const char *rpc_name);

/**
 * @brief Create NC error reply based on failed libyang validation.
 *
 * @param[in] ly_ctx Context to read the error(s) from.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_valid(const struct ly_ctx *ly_ctx);

/**
 * @brief Create NC error reply operation-failed with a generic message.
 *
 * @param[in] session Session to get context from, not needed if @p ly_ctx is set.
 * @param[in] ly_ctx Context to use directly, if available.
 * @param[in] msg Error message to use.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_op_failed(sr_session_ctx_t *session, const struct ly_ctx *ly_ctx, const char *msg);

/**
 * @brief Create NC error reply invalid-value.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] bad_elem Optional name of the bad element.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_invalid_val(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem);

/**
 * @brief Create NC error reply lock-denied.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] nc_id NETCONF session ID of the session holding the lock.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_lock_denied(const struct ly_ctx *ly_ctx, const char *msg, uint32_t nc_id);

/**
 * @brief Create NC error reply missing-attribute.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] bad_attr Bad attribute.
 * @param[in] bad_elem Bad element.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_missing_attr(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_attr,
        const char *bad_elem);

/**
 * @brief Create NC error reply missing-element.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] bad_elem Bad element.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_missing_elem(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem);

/**
 * @brief Create NC error reply bad-element.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] bad_elem Bad element.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_bad_elem(const struct ly_ctx *ly_ctx, const char *msg, const char *bad_elem);

/**
 * @brief Create NC error reply in-use.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] msg Error message to use.
 * @param[in] sr_id SR ID of the session holding the resource.
 * @return Server reply structure.
 */
struct nc_server_reply *np_reply_err_in_use(const struct ly_ctx *ly_ctx, const char *msg, uint32_t sr_id);

/**
 * @brief Transform a datastore into a string identity.
 *
 * @param[in] str Identity.
 * @param[out] ds Datastore.
 * @return Sysrepo error value.
 */
const char *sub_ntf_ds2ident(sr_datastore_t ds);

#endif /* NP2SRV_COMMON_H_ */
