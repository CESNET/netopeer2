/**
 * @file main.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server - NETCONF server
 *
 * Copyright (c) 2016 - 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE

#include <errno.h>
#ifdef DEBUG
    #include <execinfo.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"
#include "netconf_monitoring.h"

#include "../modules/ietf-netconf@2011-06-01.h"
#include "../modules/ietf-netconf-monitoring.h"
#include "../modules/ietf-netconf-with-defaults@2011-06-01.h"
#include "../modules/nc-notifications@2008-07-14.h"
#include "../modules/notifications@2008-07-14.h"
#include "../modules/ietf-netconf-notifications@2012-02-06.h"

struct np2srv np2srv;
struct np2srv_dslock dslock;
pthread_rwlock_t dslock_rwl = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @brief Control flags for the main loop
 */
enum LOOPCTRL {
    LOOP_CONTINUE = 0, /**< Continue processing */
    LOOP_RESTART = 1,  /**< restart the process */
    LOOP_STOP = 2      /**< stop the process */
};
/** @brief flag for main loop */
volatile enum LOOPCTRL control = LOOP_CONTINUE;

static void *worker_thread(void *arg);
static void np2srv_feature_change_clb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx);
static void np2srv_module_install_clb(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx);

int
np2srv_sr_reconnect(void)
{
    int rc;
    uint16_t i;
    struct nc_session *nc_sess;
    struct np2_sessions *np2_sess;

    if (!np2srv.disconnected) {
        sr_unsubscribe(np2srv.sr_sess.srs, np2srv.sr_subscr);
        /* connection and all the sessions get freed */
        sr_disconnect(np2srv.sr_conn);

        /* TODO generate notif sysrepo down */
        np2srv.disconnected = 1;
    }

    /* create new connection and sessions */
    rc = sr_connect("netopeer2", SR_CONN_DAEMON_REQUIRED | SR_CONN_DAEMON_START, &np2srv.sr_conn);
    if (rc != SR_ERR_OK) {
        goto finish;
    }

    /* server session */
    rc = sr_session_start(np2srv.sr_conn, np2srv.sr_sess.ds, np2srv.sr_sess.opts, &np2srv.sr_sess.srs);
    if (rc != SR_ERR_OK) {
        goto finish;
    }

    /* subscribe for notifications about new modules */
    rc = sr_module_install_subscribe(np2srv.sr_sess.srs, np2srv_module_install_clb, NULL, 0, &np2srv.sr_subscr);
    if (rc != SR_ERR_OK) {
        goto finish;
    }

    /* subscribe for changes of features state */
    rc = sr_feature_enable_subscribe(np2srv.sr_sess.srs, np2srv_feature_change_clb, NULL, SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr);
    if (rc != SR_ERR_OK) {
        goto finish;
    }

    /* client sessions, client subscriptions are stored in persistent files, no need to make them again */
    for (i = 0; (nc_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        np2_sess = (struct np2_sessions *)nc_session_get_data(nc_sess);
        rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(nc_sess), np2_sess->ds, np2_sess->opts, &np2_sess->srs);
        if (rc != SR_ERR_OK) {
            goto finish;
        }
    }

finish:
    switch (rc) {
    case SR_ERR_DISCONNECT:
        ERR("Failed to connect to sysrepod, it will be retried on the next communication with sysrepo.");
        rc = -1;
        break;
    case SR_ERR_OK:
        if (np2srv.disconnected) {
            /* TODO generate notif sysrepo up */
            np2srv.disconnected = 0;
        }
        rc = 0;
        break;
    default:
        ERR("Failed to connect to sysrepod (%s), exiting.", sr_strerror(rc));
        control = LOOP_STOP;
        rc = -1;
        break;
    }

    return rc;
}

int
np_sleep(unsigned int miliseconds)
{
    struct timespec ts;

    ts.tv_sec = miliseconds / 1000;
    ts.tv_nsec = (miliseconds % 1000) * 1000000;
    return nanosleep(&ts, NULL);
}

/**
 * @brief Print version information to the stdout.
 */
static void
print_version(void)
{
    fprintf(stdout, "netopeer2-server %s\n", NP2SRV_VERSION);
    fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
}

/**
 * @brief Command line options definition for getopt()
 */
#ifndef NDEBUG
#   define OPTSTRING "dhv:Vc:"
#else
#   define OPTSTRING "dhv:V"
#endif
/**
 * @brief Print command line options description
 * @param[in] progname Name of the process.
 */
static void
print_usage(char* progname)
{
    fprintf(stdout, "Usage: %s [-dhV] [-v level] [-c category]\n", progname);
    fprintf(stdout, " -d                  debug mode (do not daemonize and print\n");
    fprintf(stdout, "                     verbose messages to stderr instead of syslog)\n");
    fprintf(stdout, " -h                  display help\n");
    fprintf(stdout, " -V                  show program version\n");
    fprintf(stdout, " -v level            verbose output level:\n");
    fprintf(stdout, "                         0 - errors\n");
    fprintf(stdout, "                         1 - errors and warnings\n");
    fprintf(stdout, "                         2 - errors, warnings and verbose messages\n");
#ifndef NDEBUG
    fprintf(stdout, " -c category[,category]*  verbose debug level, print only these debug message categories\n");
    fprintf(stdout, " categories: DICT, YANG, YIN, XPATH, DIFF, MSG, EDIT_CONFIG, SSH, SYSREPO\n");
#endif
    fprintf(stdout, "\n");
}

/**
 * @brief Signal handler to control the process
 */
void
signal_handler(int sig)
{
#ifdef DEBUG
#   define STACK_DEPTH 20
    void *stack_buf[STACK_DEPTH];
    int depth;
#endif
    static int quit = 0;

    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGQUIT:
    case SIGABRT:
        /* stop the process */
        if (quit == 0) {
            /* first attempt */
            quit = 1;
        } else {
            /* second attempt */
            exit(EXIT_FAILURE);
        }
        control = LOOP_STOP;
        break;
    case SIGHUP:
    case SIGUSR1:
        /* restart the process */
        control = LOOP_RESTART;
        break;
#ifdef DEBUG
    case SIGSEGV:
        depth = backtrace(stack_buf, STACK_DEPTH);
        fprintf(stderr, "Segmentation fault, backtrace:\n");
        backtrace_symbols_fd(stack_buf, depth, STDERR_FILENO);
#endif
        /* fall through */
    default:
        exit(EXIT_FAILURE);
    }
}

static int
np2srv_module_assign_clbs(const struct lys_module *mod)
{
    struct lys_node *snode, *next;

    if (!strcmp(mod->name, "ietf-netconf-monitoring") || !strcmp(mod->name, "ietf-netconf")) {
        /* skip it, use internal implementations from libnetconf2 */
        return EXIT_SUCCESS;
    }

    /* set RPC and Notifications callbacks */
    LY_TREE_DFS_BEGIN(mod->data, next, snode) {
        if (snode->nodetype & (LYS_RPC | LYS_ACTION)) {
            nc_set_rpc_callback(snode, op_generic);
            goto dfs_nextsibling;
        }

        /* modified LY_TREE_DFS_END() */
        next = snode->child;
        /* child exception for leafs, leaflists and anyxml without children */
        if (snode->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
            next = NULL;
        }
        if (!next) {
            /* no children */
dfs_nextsibling:
            /* try siblings */
            next = snode->next;
        }
        while (!next) {
            /* parent is already processed, go to its sibling */
            snode = lys_parent(snode);
            if (!snode) {
                /* we are done, no next element to process */
                break;
            }
            next = snode->next;
        }
    }

    return EXIT_SUCCESS;
}

static void
np2srv_clean_dslock(struct nc_session *ncs)
{
    pthread_rwlock_wrlock(&dslock_rwl);

    if (dslock.running == ncs) {
        dslock.running = NULL;
    }
    if (dslock.startup == ncs) {
        dslock.startup = NULL;
    }
    if (dslock.candidate == ncs) {
        dslock.candidate = NULL;
    }

    pthread_rwlock_unlock(&dslock_rwl);
}

void
free_ds(void *ptr)
{
    struct np2_sessions *s;

    if (ptr) {
        s = (struct np2_sessions *)ptr;
        if (s->srs) {
            sr_session_stop(s->srs);
        }
        np2srv_clean_dslock(s->ncs);
        free(s);
    }
}

int
np2srv_verify_clb(const struct nc_session *session)
{
    char buf[256];
    const char *user;
    size_t buflen = 256;
    struct passwd pwd, *ret;
    int rc;

    user = nc_session_get_username(session);

    errno = 0;
    rc = getpwnam_r(user, &pwd, buf, buflen, &ret);
    if (!ret) {
        if (!rc) {
            ERR("Username \"%s\" resolved by TLS authentication does not exist on the system.", user);
        } else {
            ERR("Getting system passwd entry for \"%s\" failed (%s).", user, strerror(rc));
        }
        return 0;
    }

    return 1;
}

static char *
np2srv_ly_import_clb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *submod_rev,
                     void *UNUSED(user_data), LYS_INFORMAT *format, void (**free_module_data)(void *model_data))
{
    char *data = NULL;

    *free_module_data = free;
    *format = LYS_YIN;
    if (submod_rev || (submod_name && !mod_name)) {
        np2srv_sr_get_submodule_schema(np2srv.sr_sess.srs, submod_name, submod_rev, SR_SCHEMA_YIN, &data, NULL);
    } else {
        np2srv_sr_get_schema(np2srv.sr_sess.srs, mod_name, mod_rev, submod_name, SR_SCHEMA_YIN, &data, NULL);
    }

    return data;
}

static void
np2srv_send_capab_change_notif(const char *added_uri, const char *deleted_uri, const char *modified_uri)
{
    sr_val_t *data;

    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-notifications", NULL, 1)) {
        return;
    }

    /* generate ietf-netconf-notification's netconf-capability-change event for sysrepo */
    data = calloc(3, sizeof *data);
    data[0].xpath = "/ietf-netconf-notifications:netconf-capability-change/changed-by";
    data[0].type = SR_CONTAINER_T;
    data[1].xpath = "/ietf-netconf-notifications:netconf-capability-change/changed-by/server";
    data[1].type = SR_LEAF_EMPTY_T;
    if (added_uri) {
        assert(!deleted_uri && !modified_uri);
        data[2].xpath = "/ietf-netconf-notifications:netconf-capability-change/added-capability";
        data[2].type = SR_STRING_T;
        data[2].data.string_val = (char *)added_uri;
    } else if (deleted_uri) {
        assert(!added_uri && !modified_uri);
        data[2].xpath = "/ietf-netconf-notifications:netconf-capability-change/deleted-capability";
        data[2].type = SR_STRING_T;
        data[2].data.string_val = (char *)deleted_uri;
    } else {
        assert(!added_uri && !deleted_uri);
        data[2].xpath = "/ietf-netconf-notifications:netconf-capability-change/modified-capability";
        data[2].type = SR_STRING_T;
        data[2].data.string_val = (char *)modified_uri;
    }

    if (!np2srv_sr_event_notif_send(np2srv.sr_sess.srs, "/ietf-netconf-notifications:netconf-capability-change", data,
                                    3, SR_EV_NOTIF_DEFAULT, NULL)) {
        VRB("Generated new event (netconf-capability-change).");
    }
    free(data);
}

static char *
np2srv_create_capab(const struct lys_module *mod)
{
    int i, has_features = 0;
    char *cpb, *tmp;

    cpb = malloc(strlen(mod->ns) + 8 + strlen(mod->name) + (mod->rev_size ? 10 + strlen(mod->rev[0].date) : 0) + 1);
    if (!cpb) {
        EMEM;
        return NULL;
    }

    sprintf(cpb, "%s?module=%s%s%s", mod->ns, mod->name, mod->rev_size ? "&revision=" : "",
                mod->rev_size ? mod->rev[0].date : "");

    for (i = 0; i < mod->features_size; ++i) {
        if (mod->features[i].flags & LYS_FENABLED) {
            if (!has_features) {
                tmp = realloc(cpb, strlen(cpb) + 10 + strlen(mod->features[i].name) + 1);
            } else {
                tmp = realloc(cpb, strlen(cpb) + 1 + strlen(mod->features[i].name) + 1);
            }
            if (!tmp) {
                EMEM;
                free(cpb);
                return NULL;
            }
            cpb = tmp;

            if (!has_features) {
                strcat(cpb, "&features=");
                has_features = 1;
            } else {
                strcat(cpb, ",");
            }
            strcat(cpb, mod->features[i].name);
        }
    }

    return cpb;
}

static void
np2srv_module_install_clb(const char *module_name, const char *revision, sr_module_state_t state, void *UNUSED(private_ctx))
{
    char *data = NULL, *cpb;
    const struct lys_module *mod;
    struct lyd_node *info;
    sr_schema_t *schemas = NULL;
    size_t count, i, j;

    if (!strcmp(module_name, "ietf-yang-library") || (state == SR_MS_IMPORTED)) {
        /* yang-library module is completely managed by sysrepo, ignore this,
         * imported module will either be loaded when parsing an imported module or it should not be needed */
        return;
    }

    if (state == SR_MS_IMPLEMENTED) {
        /* adding another module into the current libyang context */
        if (np2srv_sr_get_schema(np2srv.sr_sess.srs, module_name, revision, NULL, SR_SCHEMA_YIN, &data, NULL)) {
            return;
        }

        /* lock for modifying libyang context */
        pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);
        VRB("Loading added schema \"%s%s%s\" from sysrepo.", module_name, revision ? "@" : "",
            revision ? revision : "");
        mod = lys_parse_mem(np2srv.ly_ctx, data, LYS_IN_YIN);
        free(data);

        if (!mod) {
            pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
            ERR("Unable to parse installed module %s%s%s from sysrepo, schema won't be available.", module_name,
                revision ? "@" : "", revision ? revision : "");
            return;
        } else {
            /* get module's features */
            if (np2srv_sr_list_schemas(np2srv.sr_sess.srs, &schemas, &count, NULL)) {
                pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
                return;
            }

            for (i = 0; i < count; i++) {
                if (strcmp(schemas[i].module_name, module_name)) {
                    continue;
                }
                for (j = 0; j < schemas[i].enabled_feature_cnt; ++j) {
                    lys_features_enable(mod, schemas[i].enabled_features[j]);
                }
                break;
            }

            /* set RPC, action and notification callbacks */
            np2srv_module_assign_clbs(mod);

            cpb = np2srv_create_capab(mod);
            np2srv_send_capab_change_notif(cpb, NULL, NULL);
            free(cpb);
        }
    } else {
        VRB("Removing schema \"%s%s%s\" according to changes in sysrepo.", module_name, revision ? "@" : "",
            revision ? revision : "");

        /* lock for modifying libyang context */
        pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);

        /* remove the specified module from the context */
        mod = ly_ctx_get_module(np2srv.ly_ctx, module_name, revision, 0);
        cpb = np2srv_create_capab(mod);
        /* the function can fail in case the module was already removed
         * because of dependency in some of the previous calls */
        if (!ly_ctx_remove_module(mod, NULL)) {
            np2srv_send_capab_change_notif(NULL, cpb, NULL);
        } else {
            ERR("Removing module \"%s%s%s\" failed.", module_name, revision ? "@" : "", revision ? revision : "");
        }
        free(cpb);
    }

    /* unlock libyang context */
    pthread_rwlock_unlock(&np2srv.ly_ctx_lock);

    /* generate yang-library-change notification */
    info = ly_ctx_info(np2srv.ly_ctx);
    if (info) {
        op_ntf_yang_lib_change(info);
        VRB("Generated new internal event (yang-library-change).");
        lyd_free_withsiblings(info);
    }
}

static void
np2srv_feature_change_clb(const char *module_name, const char *feature_name, bool enabled, void *UNUSED(private_ctx))
{
    const struct lys_module *mod;
    char *cpb;

    /* lock for modifying libyang context */
    pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);

    mod = ly_ctx_get_module(np2srv.ly_ctx, module_name, NULL, 0);
    if (!mod) {
        pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
        ERR("Sysrepo module %s to change feature %s does not present in Netopeer2.", module_name, feature_name);
        return;
    }

    if (enabled) {
        lys_features_enable(mod, feature_name);
    } else {
        lys_features_disable(mod, feature_name);
    }
    cpb = np2srv_create_capab(mod);
    pthread_rwlock_unlock(&np2srv.ly_ctx_lock);

    np2srv_send_capab_change_notif(NULL, NULL, cpb);
    free(cpb);
}

static int
connect_ds(struct nc_session *ncs)
{
    struct np2_sessions *s;

    if (!ncs) {
        return EXIT_FAILURE;
    }

    s = calloc(1, sizeof *s);
    if (!s) {
        EMEM;
        return EXIT_FAILURE;
    }
    s->ncs = ncs;
    s->ds = SR_DS_RUNNING;
    s->opts = SR_SESS_ENABLE_NACM;

    if (np2srv_sr_session_start_user(nc_session_get_username(ncs), s->ds, s->opts, &s->srs, NULL)) {
        goto error;
    }

    /* connect sysrepo sessions (datastore) with NETCONF session */
    nc_session_set_data(ncs, s);

    return EXIT_SUCCESS;

error:
    if (s->srs) {
        np2srv_sr_session_stop(s->srs, NULL);
    }
    free(s);
    return EXIT_FAILURE;
}

void
np2srv_new_session_clb(const char *UNUSED(client_name), struct nc_session *new_session)
{
    int c, monitored;
    sr_val_t *event_data;
    const struct lys_module *mod;
    char *host;

    if (connect_ds(new_session)) {
        /* error */
        ERR("Terminating session %d due to failure when connecting to sysrepo.",
            nc_session_get_id(new_session));
        nc_session_free(new_session, free_ds);
        return;
    }

    switch (nc_session_get_ti(new_session)) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
        ncm_session_add(new_session);
        monitored = 1;
        break;
#endif
    default:
        WRN("Session %d uses a transport protocol not supported by ietf-netconf-monitoring, will not be monitored.",
            nc_session_get_id(new_session));
        monitored = 0;
        break;
    }

    c = 0;
    while ((c < 3) && nc_ps_add_session(np2srv.nc_ps, new_session)) {
        /* presumably timeout, give it a shot 2 times */
        np_sleep(10);
        ++c;
    }

    if (c == 3) {
        /* there is some serious problem in synchronization/system planner */
        EINT;
        if (monitored) {
            ncm_session_del(new_session);
        }
        nc_session_free(new_session, free_ds);
    }

    if ((mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-notifications", NULL, 1))) {
        /* generate ietf-netconf-notification's netconf-session-start event for sysrepo */
        host = (char*)nc_session_get_host(new_session);
        event_data = calloc(host ? 3 : 2, sizeof *event_data);
        event_data[0].xpath = "/ietf-netconf-notifications:netconf-session-start/username";
        event_data[0].type = SR_STRING_T;
        event_data[0].data.string_val = (char*)nc_session_get_username(new_session);
        event_data[1].xpath = "/ietf-netconf-notifications:netconf-session-start/session-id";
        event_data[1].type = SR_UINT32_T;
        event_data[1].data.uint32_val = nc_session_get_id(new_session);
        if (host) {
            event_data[2].xpath = "/ietf-netconf-notifications:netconf-session-start/source-host";
            event_data[2].type = SR_STRING_T;
            event_data[2].data.string_val = host;
        }
        if (!np2srv_sr_event_notif_send(np2srv.sr_sess.srs, "/ietf-netconf-notifications:netconf-session-start", event_data,
                                        host ? 3 : 2, SR_EV_NOTIF_DEFAULT, NULL)) {
            VRB("Generated new event (netconf-session-start).");
        }
        free(event_data);
    }
}

static void
np2srv_del_session_clb(struct nc_session *session)
{
    int i;
    char *host;
    sr_val_t *event_data;
    const struct lys_module *mod;
    size_t c = 0;

    if (nc_session_get_notif_status(session)) {
        op_ntf_unsubscribe(session);
    }
    if (nc_ps_del_session(np2srv.nc_ps, session)) {
        ERR("Removing session from ps failed.");
    }

    switch (nc_session_get_ti(session)) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
        ncm_session_del(session);
        break;
#endif
    default:
        break;
    }

    if ((mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-notifications", NULL, 1))) {
        /* generate ietf-netconf-notification's netconf-session-end event for sysrepo */
        host = (char *)nc_session_get_host(session);
        c = 3;
        if (host) {
            ++c;
        }
        if (nc_session_get_killed_by(session)) {
            ++c;
        }
        i = 0;
        event_data = calloc(c, sizeof *event_data);
        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/username";
        event_data[i].type = SR_STRING_T;
        event_data[i++].data.string_val = (char*)nc_session_get_username(session);
        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/session-id";
        event_data[i].type = SR_UINT32_T;
        event_data[i++].data.uint32_val = nc_session_get_id(session);
        if (host) {
            event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/source-host";
            event_data[i].type = SR_STRING_T;
            event_data[i++].data.string_val = host;
        }
        if (nc_session_get_killed_by(session)) {
            event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/killed-by";
            event_data[i].type = SR_UINT32_T;
            event_data[i++].data.uint32_val = nc_session_get_killed_by(session);
        }
        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/termination-reason";
        event_data[i].type = SR_ENUM_T;
        switch (nc_session_get_term_reason(session)) {
        case NC_SESSION_TERM_CLOSED:
            event_data[i++].data.enum_val = "closed";
            break;
        case NC_SESSION_TERM_KILLED:
            event_data[i++].data.enum_val = "killed";
            break;
        case NC_SESSION_TERM_DROPPED:
            event_data[i++].data.enum_val = "dropped";
            break;
        case NC_SESSION_TERM_TIMEOUT:
            event_data[i++].data.enum_val = "timeout";
            break;
        default:
            event_data[i++].data.enum_val = "other";
            break;
        }
        if (!np2srv_sr_event_notif_send(np2srv.sr_sess.srs, "/ietf-netconf-notifications:netconf-session-end", event_data, c,
                                        SR_EV_NOTIF_DEFAULT, NULL)) {
            VRB("Generated new event (netconf-session-end).");
        }
        free(event_data);
    }

    nc_session_free(session, free_ds);
}

static int
np2srv_init_schemas(void)
{
    int rc;
    char *data = NULL;
    const struct lys_module *mod;
    sr_schema_t *schemas = NULL;
    size_t count, i, j;

    /* get the list of schemas from sysrepo */
    if (np2srv_sr_list_schemas(np2srv.sr_sess.srs, &schemas, &count, NULL)) {
        return -1;
    }

    /* subscribe for notifications about new modules */
    rc = sr_module_install_subscribe(np2srv.sr_sess.srs, np2srv_module_install_clb, NULL, 0, &np2srv.sr_subscr);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing to module install failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* subscribe for changes of features state */
    rc = sr_feature_enable_subscribe(np2srv.sr_sess.srs, np2srv_feature_change_clb, NULL, SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing to feature enable failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* init rwlock for libyang context */
#ifdef HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP
    pthread_rwlockattr_t attr;
    rc = pthread_rwlockattr_init(&attr);
    if (rc) {
        ERR("Initiating schema context lock attributes failed (%s)", strerror(rc));
        goto error;
    }
    /* prefer write locks */
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    rc = pthread_rwlock_init(&np2srv.ly_ctx_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
#else
    rc = pthread_rwlock_init(&np2srv.ly_ctx_lock, NULL);
#endif
    if (rc) {
        ERR("Initiating schema context lock failed (%s)", strerror(rc));
        goto error;
    }

    /* build libyang context */
    /* the lock is not supposed to be locked here. In case of first calling, it needn't be used because we are still
     * single-threaded, in other cases the caller (np2srv_module_install_clb()) is supposed to lock it */
    np2srv.ly_ctx = ly_ctx_new(NULL, 0);
    if (!np2srv.ly_ctx) {
        goto error;
    }
    ly_ctx_set_module_imp_clb(np2srv.ly_ctx, np2srv_ly_import_clb, NULL);

    /* 1) use modules from sysrepo */
    for (i = 0; i < count; i++) {
        data = NULL;
        mod = NULL;
        VRB("Loading schema \"%s%s%s\" from sysrepo.", schemas[i].module_name, schemas[i].revision.revision ? "@" : "",
            schemas[i].revision.revision ? schemas[i].revision.revision : "");
        if ((mod = ly_ctx_get_module(np2srv.ly_ctx, schemas[i].module_name, schemas[i].revision.revision, 0))) {
            VRB("Module %s%s%s already present in context.", schemas[i].module_name,
                schemas[i].revision.revision ? "@" : "",
                schemas[i].revision.revision ? schemas[i].revision.revision : "");
            if (schemas[i].implemented && !mod->implemented && lys_set_implemented(mod)) {
                WRN("Implementing %s%s%s schema failed, data from this module won't be available.",
                    schemas[i].module_name, schemas[i].revision.revision ? "@" : "",
                    schemas[i].revision.revision ? schemas[i].revision.revision : "");
            }
        } else if (!np2srv_sr_get_schema(np2srv.sr_sess.srs, schemas[i].module_name,
                schemas[i].revision.revision, NULL, SR_SCHEMA_YIN, &data, NULL)) {
            mod = lys_parse_mem(np2srv.ly_ctx, data, LYS_IN_YIN);
            free(data);
        }

        if (!mod) {
            WRN("Getting %s%s%s schema from sysrepo failed, data from this module won't be available.",
                schemas[i].module_name, schemas[i].revision.revision ? "@" : "",
                schemas[i].revision.revision ? schemas[i].revision.revision : "");
        } else {
            /* set features according to sysrepo */
            for (j = 0; j < schemas[i].enabled_feature_cnt; ++j) {
                lys_features_enable(mod, schemas[i].enabled_features[j]);
            }

            /* set RPC and Notifications callbacks */
            np2srv_module_assign_clbs(mod);
        }
    }
    ly_ctx_set_module_imp_clb(np2srv.ly_ctx, np2srv_ly_import_clb, NULL);
    sr_free_schemas(schemas, count);
    schemas = NULL;

    /* 2) add internally used schemas: ietf-netconf, ... */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf", "2011-06-01", 1);
    if (!mod && !(mod = lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_2011_06_01_yin, LYS_IN_YIN))) {
        goto error;
    }
    lys_features_enable(mod, "writable-running");
    lys_features_enable(mod, "candidate");
    /* TODO lys_features_enable(mod, "confirmed-commit"); */
    lys_features_enable(mod, "rollback-on-error");
    lys_features_enable(mod, "validate");
    lys_features_enable(mod, "startup");
    /* TODO lys_features_enable(mod, "url"); */
    lys_features_enable(mod, "xpath");

    /* ... ietf-netconf-monitoring (leave get-schema RPC empty, libnetconf2 will use its callback), */
    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-monitoring", "2010-10-04", 1) &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_monitoring_yin, LYS_IN_YIN)) {
        goto error;
    }

    /* ... ietf-netconf-with-defaults */
    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-with-defaults", "2011-06-01", 1) &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_with_defaults_2011_06_01_yin, LYS_IN_YIN)) {
        goto error;
    }

    /* ... notifications, nc-notifications, and ietf-netconf-notifications */
    if (!ly_ctx_get_module(np2srv.ly_ctx, "notifications", "2008-07-14", 1) &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)notifications_2008_07_14_yin, LYS_IN_YIN)) {
        goto error;
    }
    if (!ly_ctx_get_module(np2srv.ly_ctx, "nc-notifications", "2008-07-14", 1) &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)nc_notifications_2008_07_14_yin, LYS_IN_YIN)) {
        goto error;
    }
    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-notifications", "2012-02-06", 1) &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_notifications_2012_02_06_yin, LYS_IN_YIN)) {
        goto error;
    }

    /* debug - list schemas
    struct lyd_node *ylib = ly_ctx_info(np2srv.ly_ctx);
    lyd_print_file(stdout, ylib, LYD_JSON, LYP_WITHSIBLINGS);
    lyd_free(ylib);
    */

    return 0;

error:
    if (schemas) {
        sr_free_schemas(schemas, count);
    }
    ly_ctx_destroy(np2srv.ly_ctx, NULL);
    return -1;
}

static int
np2srv_default_hostkey_clb(const char *name, void *UNUSED(user_data), char **privkey_path, char **UNUSED(privkey_data),
                           int *UNUSED(privkey_data_rsa))
{
    if (!strcmp(name, "default")) {
        *privkey_path = strdup(NP2SRV_HOST_KEY);
        return 0;
    }

    EINT;
    return 1;
}

static int
server_init(void)
{
    const struct lys_node *snode;
    const struct lys_module *mod;
    int rc;

    /* connect to the sysrepo */
    rc = sr_connect("netopeer2", SR_CONN_DAEMON_REQUIRED | SR_CONN_DAEMON_START, &np2srv.sr_conn);
    if (rc != SR_ERR_OK) {
        ERR("Connecting to sysrepo failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* server session */
    np2srv.sr_sess.ds = SR_DS_STARTUP;
    np2srv.sr_sess.opts = SR_SESS_DEFAULT;
    rc = sr_session_start(np2srv.sr_conn, np2srv.sr_sess.ds, np2srv.sr_sess.opts, &np2srv.sr_sess.srs);
    if (rc != SR_ERR_OK) {
        ERR("Creating sysrepo session failed (%s).", sr_strerror(rc));
        goto error;
    }

    VRB("Netopeer2 connected to sysrepod.");

    /* init libyang context with schemas */
    if (np2srv_init_schemas()) {
        goto error;
    }

    /* init monitoring */
    ncm_init();

    /* init libnetconf2 */
    if (nc_server_init(np2srv.ly_ctx)) {
        goto error;
    }

    /* prepare poll session structure for libnetconf2 */
    np2srv.nc_ps = nc_ps_new();

    /* set with-defaults capability basic-mode */
    nc_server_set_capab_withdefaults(NC_WD_EXPLICIT, NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT);

    /* set capabilities for the NETCONF Notifications */
    nc_server_set_capability("urn:ietf:params:netconf:capability:notification:1.0");
    nc_server_set_capability("urn:ietf:params:netconf:capability:interleave:1.0");

    /* set NETCONF operations callbacks */
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get-config", 0);
    nc_set_rpc_callback(snode, op_get);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:edit-config", 0);
    nc_set_rpc_callback(snode, op_editconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:copy-config", 0);
    nc_set_rpc_callback(snode, op_copyconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:delete-config", 0);
    nc_set_rpc_callback(snode, op_deleteconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:lock", 0);
    nc_set_rpc_callback(snode, op_lock);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:unlock", 0);
    nc_set_rpc_callback(snode, op_unlock);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get", 0);
    nc_set_rpc_callback(snode, op_get);

    /* leave close-session RPC empty, libnetconf2 will use its callback */

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:commit", 0);
    nc_set_rpc_callback(snode, op_commit);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:discard-changes", 0);
    nc_set_rpc_callback(snode, op_discardchanges);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:validate", 0);
    nc_set_rpc_callback(snode, op_validate);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:kill-session", 0);
    nc_set_rpc_callback(snode, op_kill);

    /* TODO
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:cancel-commit", 0);
    nc_set_rpc_callback(snode, op_cancel);
     */

    /* set Notifications subscription callback */
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/notifications:create-subscription", 0);
    nc_set_rpc_callback(snode, op_ntf_subscribe);

    /* set server options */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-server", NULL, 1);
    if (mod && strcmp(NP2SRV_KEYSTORED_DIR, "none")) {
#ifdef ENABLED_TLS
        nc_server_tls_set_verify_clb(np2srv_verify_clb);
#endif
        if (ietf_netconf_server_init(mod)) {
            goto error;
        }

        mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-system", NULL, 1);
        if (mod) {
            if (ietf_system_init(mod)) {
                goto error;
            }
        } else {
            WRN("Sysrepo does not implement the \"ietf-system\" module, SSH publickey authentication will not work.");
        }
    } else {
        WRN("Sysrepo does not have the \"ietf-netconf-server\" module or keystored keys dir unknown, using default NETCONF server options.");
        nc_server_ssh_set_hostkey_clb(np2srv_default_hostkey_clb, NULL, NULL);
        if (nc_server_add_endpt("main", NC_TI_LIBSSH)) {
            goto error;
        }
        if (nc_server_endpt_set_address("main", "0.0.0.0")) {
            goto error;
        }
        if (nc_server_endpt_set_port("main", 830)) {
            goto error;
        }
        if (nc_server_ssh_endpt_add_hostkey("main", "default", -1)) {
            goto error;
        }
    }

    return 0;

error:
    ERR("Server init failed.");
    return -1;
}

static void *
worker_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    int rc, idx = *((int *)arg), monitored;
    struct nc_session *ncs;

    nc_libssh_thread_verbosity(np2_verbose_level);

    while ((control == LOOP_CONTINUE) && np2srv.workers[idx]) {

        /* lock for using libyang context */
        pthread_rwlock_rdlock(&np2srv.ly_ctx_lock);

        /* check context that could be destroyed by np2srv_module_install_clb() */
        if (!np2srv.ly_ctx) {
            pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
            control = LOOP_STOP;
            break;
        }

        /* try to accept new NETCONF sessions */
        if (nc_server_endpt_count()
                && (!np2srv.nc_max_sessions || (nc_ps_session_count(np2srv.nc_ps) < np2srv.nc_max_sessions))) {
            msgtype = nc_accept(0, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                np2srv_new_session_clb(NULL, ncs);
            }
        }

        /* listen for incoming requests on active NETCONF sessions */
        rc = nc_ps_poll(np2srv.nc_ps, 0, &ncs);

        if (rc & (NC_PSPOLL_NOSESSIONS | NC_PSPOLL_TIMEOUT)) {
            /* if there is no active session or timeout, rest for a while */
            pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
            np_sleep(10);
            continue;
        }

        switch (nc_session_get_ti(ncs)) {
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
            monitored = 1;
            break;
#endif
        default:
            monitored = 0;
            break;
        }

        /* process the result of nc_ps_poll(), increase counters */
        if (rc & NC_PSPOLL_BAD_RPC) {
            if (monitored) {
                ncm_session_bad_rpc(ncs);
            }
            VRB("Session %d: thread %d event bad RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_RPC) {
            if (monitored) {
                ncm_session_rpc(ncs);
            }
            VRB("Session %d: thread %d event new RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_REPLY_ERROR) {
            if (monitored) {
                ncm_session_rpc_reply_error(ncs);
            }
            VRB("Session %d: thread %d event reply error.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_SESSION_TERM) {
            VRB("Session %d: thread %d event session terminated.", nc_session_get_id(ncs), idx);
            np2srv_del_session_clb(ncs);
        } else if (rc & NC_PSPOLL_SSH_CHANNEL) {
            /* a new SSH channel on existing session was created */
            VRB("Session %d: thread %d event new SSH channel.", nc_session_get_id(ncs), idx);
            msgtype = nc_session_accept_ssh_channel(ncs, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                np2srv_new_session_clb(NULL, ncs);
            } else if (msgtype == NC_MSG_BAD_HELLO) {
                if (monitored) {
                    ncm_bad_hello();
                }
            }
        }
        pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
    }

    /* cleanup */
    nc_thread_destroy();
    free(arg);
    np2srv.workers[idx] = 0;
    return NULL;
}

int
main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    int c, *idx, i;
    int daemonize = 1, verb = 0;
    int pidfd;
    char pid[8];
#ifndef NDEBUG
    char *ptr;
#endif
    struct sigaction action;
    sigset_t block_mask;
    pthread_attr_t thread_attr;

    /* until daemonized, write messages to both syslog and stderr */
    openlog("netopeer2-server", LOG_PID | LOG_PERROR, LOG_DAEMON);

    /* process command line options */
    while ((c = getopt(argc, argv, OPTSTRING)) != -1) {
        switch (c) {
        case 'd':
            daemonize = 0;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'v':
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }
            verb = 1;

            c = atoi(optarg);
            /* normalize verbose level */
            np2_verbose_level = (c > NC_VERB_ERROR) ? ((c > NC_VERB_VERBOSE) ? NC_VERB_VERBOSE : c) : NC_VERB_ERROR;
            switch (np2_verbose_level) {
            case NC_VERB_ERROR:
                np2_libssh_verbose_level = 0;
                np2_sr_verbose_level = SR_LL_ERR;
                break;
            case NC_VERB_WARNING:
                np2_sr_verbose_level = SR_LL_WRN;
                np2_libssh_verbose_level = 1;
                break;
            case NC_VERB_VERBOSE:
                np2_sr_verbose_level = SR_LL_INF;
                np2_libssh_verbose_level = 1;
                break;
            }

            nc_verbosity(np2_verbose_level);
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
#ifndef NDEBUG
        case 'c':
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }

            /* set verbose for all, we change to debug later if requested */
            np2_verbose_level = NC_VERB_VERBOSE;
            nc_verbosity(np2_verbose_level);
            np2_libssh_verbose_level = 1;

            ptr = strtok(optarg, ",");
            do {
                if (!strcmp(ptr, "DICT")) {
                    verb |= LY_LDGDICT;
                } else if (!strcmp(ptr, "YANG")) {
                    verb |= LY_LDGYANG;
                } else if (!strcmp(ptr, "YIN")) {
                    verb |= LY_LDGYIN;
                } else if (!strcmp(ptr, "XPATH")) {
                    verb |= LY_LDGXPATH;
                } else if (!strcmp(ptr, "DIFF")) {
                    verb |= LY_LDGDIFF;
                } else if (!strcmp(ptr, "MSG")) {
                    /* NETCONF messages - only lnc2 debug verbosity */
                    nc_verbosity(NC_VERB_DEBUG);
                } else if (!strcmp(ptr, "EDIT_CONFIG")) {
                    /* edit-config operations - only netopeer2 debug verbosity */
                    np2_verbose_level = NC_VERB_DEBUG;
                } else if (!strcmp(ptr, "SSH")) {
                    /* 2 should be always enough, 3 is too much useless info */
                    np2_libssh_verbose_level = 2;
                } else if (!strcmp(ptr, "SYSREPO")) {
                    np2_sr_verbose_level = SR_LL_DBG;
                } else {
                    ERR("Unknown debug message category \"%s\", use -h.", ptr);
                    return EXIT_FAILURE;
                }
            } while ((ptr = strtok(NULL, ",")));
            /* set final verbosity ofr libssh and libyang */
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
            if (verb) {
                ly_verb(LY_LLDBG);
                ly_verb_dbg(verb);
            }

            verb = 1;
            break;
#endif

        default:
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    /* daemonize */
    if (daemonize == 1) {
        if (daemon(0, 0) != 0) {
            ERR("Daemonizing netopeer2-server failed (%s)", strerror(errno));
            return EXIT_FAILURE;
        }

        /* from now print only to syslog, not stderr */
        openlog("netopeer2-server", LOG_PID, LOG_DAEMON);
    }

    /* make sure we are the only instance - lock the PID file and write the PID */
    pidfd = open(NP2SRV_PIDFILE, O_RDWR | O_CREAT, 0640);
    if (pidfd < 0) {
        ERR("Unable to open Netopeer2 PID file '%s': %s.", NP2SRV_PIDFILE, strerror(errno));
        return EXIT_FAILURE;
    }
    if (lockf(pidfd, F_TLOCK, 0) < 0) {
        close(pidfd);
        if (errno == EACCES || errno == EAGAIN) {
            ERR("Another instance of the Netopeer2 server is running.");
        } else {
            ERR("Unable to lock Netopeer2 PID file '%s': %s.", NP2SRV_PIDFILE, strerror(errno));
        }
        return EXIT_FAILURE;
    }
    ftruncate(pidfd, 0);
    c = snprintf(pid, sizeof(pid), "%d\n", getpid());
    if (write(pidfd, pid, c) < c) {
        ERR("Failed to write indo PID file.");
        close(pidfd);
        return EXIT_FAILURE;
    }
    close(pidfd);

    /* set the signal handler */
    sigfillset (&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
#ifdef DEBUG
    sigaction(SIGSEGV, &action, NULL);
#endif
    /* ignore SIGPIPE */
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    /* set printer callbacks for the used libraries and set proper log levels */
    nc_set_print_clb(np2log_clb_nc2); /* libnetconf2 */
    ly_set_log_clb(np2log_clb_ly, 1); /* libyang */
    sr_log_set_cb(np2log_clb_sr); /* sysrepo, log level is checked by callback */

restart:
    /* initiate NETCONF server */
    if (server_init()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    /* start additional worker threads */
    for (i = 1; i < NP2SRV_THREAD_COUNT; ++i) {
        idx = malloc(sizeof *idx);
        *idx = i;
        pthread_create(&np2srv.workers[*idx], &thread_attr, worker_thread, idx);
    }
    pthread_attr_destroy(&thread_attr);

    /* one worker will use this thread */
    np2srv.workers[0] = pthread_self();
    idx = malloc(sizeof *idx);
    *idx = 0;
    worker_thread(idx);

    /* wait for finishing processing thread */
    do {
        for (i = 0; i < NP2SRV_THREAD_COUNT; ++i) {
            if (np2srv.workers[i]) {
                break;
            }
        }
    } while (i < NP2SRV_THREAD_COUNT);

cleanup:
    /* disconnect from sysrepo */
    if (np2srv.sr_subscr) {
        sr_unsubscribe(np2srv.sr_sess.srs, np2srv.sr_subscr);
    }

    /* libnetconf2 cleanup */
    if (np2srv.nc_ps) {
        nc_ps_clear(np2srv.nc_ps, 1, free_ds);
    }
    nc_ps_free(np2srv.nc_ps);

    /* clears all the sessions also */
    sr_disconnect(np2srv.sr_conn);

    nc_server_destroy();

    /* monitoring cleanup */
    ncm_destroy();

    /* libyang cleanup */
    ly_ctx_destroy(np2srv.ly_ctx, NULL);

    /* are we requested to stop or just to restart? */
    if (control == LOOP_RESTART) {
        goto restart;
    }

    return ret;
}
