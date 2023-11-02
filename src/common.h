/**
 * @file common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common structures and functions
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
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
struct np2_user_sess {
    sr_session_ctx_t *sess;
    ATOMIC_T ref_count;
    pthread_mutex_t lock;

    struct np_ntf_arg ntf_arg;
};

/* server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;         /**< sysrepo connection */
    sr_session_ctx_t *sr_sess;      /**< sysrepo server session */
    sr_subscription_ctx_t *sr_rpc_sub;  /**< sysrepo RPC subscription context */
    sr_subscription_ctx_t *sr_create_sub_rpc_sub;   /**< sysrepo \<create-subscription\> RPC subscription context */
    sr_subscription_ctx_t *sr_data_sub; /**< sysrepo data subscription context */
    sr_subscription_ctx_t *sr_nacm_stats_sub;   /**< sysrepo NACM global stats subscription context */
    sr_subscription_ctx_t *sr_notif_sub;    /**< sysrepo notification subscription context */

    uint32_t sr_timeout;            /**< timeout in ms for all sysrepo functions */
    const char *ext_data_path;      /**< path to the data file with data for LY ext data callback */

    const char *server_dir;         /**< path to server files (just confirmed commit for the moment) */

    struct nc_pollsession *nc_ps;   /**< libnetconf2 pollsession structure */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};

extern struct np2srv np2srv;

/**
 * @brief Check whether to ignore an RPC callback event.
 *
 * @param[in] ev_sess Event session to generate an error for.
 * @param[in] event RPC callback event.
 * @param[out] rc Return code to return.
 * @return Whether the RPC should be processed or not.
 */
int np_ignore_rpc(sr_session_ctx_t *ev_sess, sr_event_t event, int *rc);

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
 * @return Difference in milliseconds, positivne if @p ts1 < @p ts2, negative if @p ts1 > @p ts2.
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
int np_acquire_user_sess(const struct nc_session *ncs, struct np2_user_sess **user_sess);

/**
 * @brief Find NC session and/or SR user session based on SR event session.
 *
 * Increases refcount of the session if @p user_sess is set, needs ::np_release_user_sess() call to decrease.
 *
 * @param[in] ev_sess Sysrepo event session.
 * @param[in] func Caller function, for logging.
 * @param[out] nc_sess Optional found NC session.
 * @param[out] user_sess Optional sysrepo user session.
 * @return SR error value.
 */
int np_find_user_sess(sr_session_ctx_t *ev_sess, const char *func, struct nc_session **nc_sess,
        struct np2_user_sess **user_sess);

/**
 * @brief Release SR user session, free if no longer referenced.
 *
 * Decreases refcount after ::np_find_user_sess() or ::np_acquire_user_sess() call.
 *
 * @param[in] user_sess Sysrepo user session.
 */
void np_release_user_sess(struct np2_user_sess *user_sess);

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
 * @brief NP2 callback for acquiring context.
 */
const struct ly_ctx *np2srv_acquire_ctx_cb(void *cb_data);

/**
 * @brief NP2 callback for releasing context.
 */
void np2srv_release_ctx_cb(void *cb_data);

/**
 * @brief NP2 callback for a new session creation.
 *
 * @param[in] client_name CH client name, unused.
 * @param[in] new_session Created NC session.
 * @param[in] user_data Arbitrary data, unused.
 * @return 0 on success;
 * @return -1 on error.
 */
int np2srv_new_session_cb(const char *client_name, struct nc_session *new_session, void *user_data);

/**
 * @brief Set URL capability to be advertised for new NETCONF sessions.
 *
 * @return 0 on success;
 * @return -1 on error.
 */
int np2srv_url_setcap(void);

#ifdef NP2SRV_URL_CAPAB

/**
 * @brief Parse YANG data found at an URL (encapsulated in `config` element).
 *
 * @param[in] url URL to access.
 * @param[in] validate Whether to validate nested data.
 * @param[out] rc SR error value.
 * @param[in,out] sr_sess SR session to set error on.
 * @return Parsed data.
 */
struct lyd_node *op_parse_url(const char *url, int validate, int *rc, sr_session_ctx_t *sr_sess);

/**
 * @brief Upload YANG data to an URL (encapsulated in `config` element).
 *
 * @param[in] url URL to upload to.
 * @param[in] data Data to upload.
 * @param[in] print_options Options for printing the data.
 * @param[out] rc SR error value.
 * @param[in,out] sr_sess SR session to set error on.
 * @return 0 on success;
 * @return -1 on error.
 */
int op_export_url(const char *url, struct lyd_node *data, uint32_t print_options, int *rc, sr_session_ctx_t *sr_sess);

#endif

/**
 * @brief Parse YANG data in a `config` YANG anyxml node.
 *
 * @param[in] config Config node with the data.
 * @param[in] parse_options Options for parsing the data.
 * @param[out] rc SR error value.
 * @param[in,out] sr_sess SR session to set error on.
 * @return Parsed data.
 */
struct lyd_node *op_parse_config(struct lyd_node_any *config, uint32_t parse_options, int *rc, sr_session_ctx_t *sr_sess);

struct np2_filter {
    struct {
        char *str;      /**< filter string */
        int selection;  /**< selection or content filter */
    } *filters;
    uint32_t count;
};

/**
 * @brief Create NP2 filter structure from a subtree filter.
 *
 * @param[in] node Subtree filter.
 * @param[in,out] ev_sess SR event session to set the error on.
 * @param[in,out] filter Generated NP2 filter.
 * @return SR error value.
 */
int op_filter_create_subtree(const struct lyd_node *node, sr_session_ctx_t *ev_sess, struct np2_filter *filter);

/**
 * @brief Create NP2 filter structure from an XPath filter.
 *
 * @param[in] xpath XPath filter.
 * @param[out] filter Generated NP2 filter.
 * @return SR error value.
 */
int op_filter_create_xpath(const char *xpath, struct np2_filter *filter);

/**
 * @brief Erase all members of an NP2 filter structure.
 *
 * @param[in] filter NP2 filter to erase.
 */
void op_filter_erase(struct np2_filter *filter);

/**
 * @brief Transform NP2 filter structure into XPath filter.
 *
 * @param[in] filter NP2 filter structure.
 * @param[out] xpath Generated XPath filter.
 * @return SR error value.
 */
int op_filter_filter2xpath(const struct np2_filter *filter, char **xpath);

/**
 * @brief Get all data matching the NP2 filter.
 *
 * @param[in] session SR session to get the data on.
 * @param[in] max_depth Max depth fo the retrieved data.
 * @param[in] get_opts SR get options to use.
 * @param[in] filter NP2 filter to use.
 * @param[in,out] ev_sess SR event session to set the error on.
 * @param[out] data Retrieved data.
 * @return SR error value.
 */
int op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_options_t get_opts,
        const struct np2_filter *filter, sr_session_ctx_t *ev_sess, struct lyd_node **data);

/**
 * @brief Filter out only the data matching the NP2 filter.
 *
 * @param[in,out] data Input data to filter. May be used and set to NULL.
 * @param[in] filter NP2 filter to use.
 * @param[in] with_selection Whether to apply even selection filters in @p filter.
 * @param[out] filtered_data Data from @p data selected by @p filter.
 * @return SR error value.
 */
int op_filter_data_filter(struct lyd_node **data, const struct np2_filter *filter, int with_selection,
        struct lyd_node **filtered_data);

#endif /* NP2SRV_COMMON_H_ */
