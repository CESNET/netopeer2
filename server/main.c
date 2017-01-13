/**
 * @file main.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief netopeer2-server - NETCONF server
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

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

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"
#include "netconf_monitoring.h"

#include "../modules/ietf-netconf@2011-06-01.h"
#include "../modules/ietf-netconf-monitoring.h"
#include "../modules/ietf-netconf-with-defaults@2011-06-01.h"

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

/**
 * @brief Print version information to the stdout.
 */
static void
print_version(void)
{
    fprintf(stdout, "Netopeer2 Server %s\n", NP2SRV_VERSION);
    fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
    return;
}

/**
 * @brief Command line options definition for getopt()
 */
#define OPTSTRING "dhv:V"
/**
 * @brief Print command line options description
 * @param[in] progname Name of the process.
 */
static void
print_usage(char* progname)
{
    fprintf(stdout, "Usage: %s [-dhV] [-v level]\n", progname);
    fprintf(stdout, " -d                  debug mode (do not daemonize and print\n");
    fprintf(stdout, "                     verbose messages to stderr instead of syslog)\n");
    fprintf(stdout, " -h                  display help\n");
    fprintf(stdout, " -V                  show program version\n");
    fprintf(stdout, " -v level            verbose output level:\n");
    fprintf(stdout, "                         0 - errors\n");
    fprintf(stdout, "                         1 - errors and warnings\n");
    fprintf(stdout, "                         2 - errors, warnings and verbose messages\n");
    fprintf(stdout, "                         3 - all messages including debug notes\n");
    exit(0);
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
        /* fall through */
#endif
    default:
        exit(EXIT_FAILURE);
    }
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
np2srv_ly_import_clb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *UNUSED(submod_rev),
                     void *UNUSED(user_data), LYS_INFORMAT *format, void (**free_module_data)(void *model_data))
{
    char *data = NULL;
    int rc;

    *free_module_data = free;
    *format = LYS_YIN;
    rc = sr_get_schema(np2srv.sr_sess.srs, mod_name, mod_rev, submod_name, SR_SCHEMA_YIN, &data);
    if (rc == SR_ERR_OK) {
        return data;
    } else if (submod_name) {
        ERR("Unable to get %s module (as dependency of %s) from sysrepo (%s).", mod_name, submod_name, sr_strerror(rc));
    } else {
        ERR("Unable to get %s module from sysrepo (%s).", mod_name, sr_strerror(rc));
    }

    return NULL;
}

static void
np2srv_module_install_clb(const char *module_name, const char *revision, sr_module_state_t state, void *UNUSED(private_ctx))
{
    int rc;
    char *data = NULL;
    const struct lys_module *mod;
    const struct lys_node *snode, *next, *top;
    sr_schema_t *schemas = NULL;
    size_t count, i, j;

    if (state == SR_MS_IMPLEMENTED) {
        /* adding another module into the current libyang context */
        rc = sr_get_schema(np2srv.sr_sess.srs, module_name, revision, NULL, SR_SCHEMA_YIN, &data);
        if (rc != SR_ERR_OK) {
            ERR("Unable to get installed module %s%s%s from sysrepo (%s), schema won't be available.", module_name,
                revision ? "@" : "", revision ? revision : "", sr_strerror(rc));
            return;
        }

        /* lock for modifying libyang context */
        pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);
        VRB("Loading added schema \"%s%s%s\" from sysrepo.", module_name, revision ? "@" : "",
            revision ? revision : "");
        mod = lys_parse_mem(np2srv.ly_ctx, data, LYS_IN_YIN);
        free(data);

        if (!mod) {
            ERR("Unable to parse installed module %s%s%s from sysrepo (%s), schema won't be available.", module_name,
                revision ? "@" : "", revision ? revision : "", sr_strerror(rc));
        } else {
            /* get module's features */
            rc = sr_list_schemas(np2srv.sr_sess.srs, &schemas, &count);
            if (rc != SR_ERR_OK) {
                ERR("Unable to get list of sysrepo schemas for %s%s%s module feature (%s).", module_name,
                    revision ? "@" : "", revision ? revision : "", sr_strerror(rc));
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

            /* set RPC callbacks */
            LY_TREE_FOR(mod->data, top) {
                LY_TREE_DFS_BEGIN(top, next, snode) {
                    if (snode->nodetype & (LYS_RPC | LYS_ACTION)) {
                        nc_set_rpc_callback(snode, op_generic);
                    }
                    LY_TREE_DFS_END(top, next, snode);
                }
            }
        }
    } else if (state == SR_MS_IMPORTED) {
        /* TODO nothing to do, it will either be loaded when parsing an imported module or it should not be needed, right? */
    } else {
        VRB("Removing schema \"%s%s%s\" according to changes in sysrepo.", module_name, revision ? "@" : "",
            revision ? revision : "");

        /* lock for modifying libyang context */
        pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);

        /* remove the specified module from the context */
        mod = ly_ctx_get_module(np2srv.ly_ctx, module_name, revision);
        ly_ctx_remove_module(mod, NULL);
        /* ignore return value, the function can fail in case the module was already removed
         * because of dependency in some of the previous call */
    }

    /* unlock libyang context */
    pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
}
static void
np2srv_feature_change_clb(const char *module_name, const char *feature_name, bool enabled, void *UNUSED(private_ctx))
{
    const struct lys_module *mod;

    /* lock for modifying libyang context */
    pthread_rwlock_wrlock(&np2srv.ly_ctx_lock);

    mod = ly_ctx_get_module(np2srv.ly_ctx, module_name, NULL);
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
    pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
}

void
np2srv_new_ch_session_clb(const char *UNUSED(client_name), struct nc_session *new_session)
{
    int c;

    ncm_session_add(new_session);

    c = 0;
    while ((c < 3) && nc_ps_add_session(np2srv.nc_ps, new_session)) {
        /* presumably timeout, give it a shot 2 times */
        usleep(10000);
        ++c;
    }

    if (c == 3) {
        /* there is some serious problem in synchronization/system planner */
        EINT;
        ncm_session_del(new_session, 1);
        nc_session_free(new_session, free_ds);
    }
}

static int
np2srv_init_schemas(int first)
{
    int rc;
    char *data = NULL;
    const struct lys_module *mod;
    const struct lys_node *snode, *next, *top;
    sr_schema_t *schemas = NULL;
    size_t count, i, j;

    /* get the list of schemas from sysrepo */
    rc = sr_list_schemas(np2srv.sr_sess.srs, &schemas, &count);
    if (rc != SR_ERR_OK) {
        ERR("Unable to get list of schemas supported by sysrepo (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    if (first) {
        /* subscribe for notifications about new modules */
        rc = sr_module_install_subscribe(np2srv.sr_sess.srs, np2srv_module_install_clb, NULL, 0, &np2srv.sr_subscr);
        if (rc != SR_ERR_OK) {
            ERR("Unable to subscribe for sysrepo module installation notifications (%s)", sr_strerror(rc));
            goto error;
        }
        /* subscribe for changes of features state */
        rc = sr_feature_enable_subscribe(np2srv.sr_sess.srs, np2srv_feature_change_clb, NULL, SR_SUBSCR_CTX_REUSE, &np2srv.sr_subscr);
        if (rc != SR_ERR_OK) {
            ERR("Unable to subscribe for sysrepo module feature change notifications (%s)", sr_strerror(rc));
            goto error;
        }

        /* init rwlock for libyang context */
        rc = pthread_rwlock_init(&np2srv.ly_ctx_lock, NULL);
        if (rc) {
            ERR("Initiating schema context lock failed (%s)", strerror(rc));
            goto error;
        }
    }

    /* build libyang context */
    /* the lock is not supposed to be locked here. In case of first calling, it needn't be used because we are still
     * single-threaded, in other cases the caller (np2srv_module_install_clb()) is supposed to lock it */
    np2srv.ly_ctx = ly_ctx_new(NULL);
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
        if ((mod = ly_ctx_get_module(np2srv.ly_ctx, schemas[i].module_name, schemas[i].revision.revision))) {
            VRB("Module %s%s%s already present in context.", schemas[i].module_name,
                schemas[i].revision.revision ? "@" : "",
                schemas[i].revision.revision ? schemas[i].revision.revision : "");
        } else if (sr_get_schema(np2srv.sr_sess.srs, schemas[i].module_name,
                                 schemas[i].revision.revision, NULL, SR_SCHEMA_YIN, &data) == SR_ERR_OK) {
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

            /* set RPC callbacks (except ietf-netconf, those are set separately later) */
            if (strcmp(mod->name, "ietf-netconf") && strcmp(mod->name, "ietf-netconf-monitoring")) {
                LY_TREE_FOR(mod->data, top) {
                    LY_TREE_DFS_BEGIN(top, next, snode) {
                        if (snode->nodetype & (LYS_RPC | LYS_ACTION)) {
                            nc_set_rpc_callback(snode, op_generic);
                        }
                        LY_TREE_DFS_END(top, next, snode);
                    }
                }
            }
        }
    }
    ly_ctx_set_module_imp_clb(np2srv.ly_ctx, np2srv_ly_import_clb, NULL);
    sr_free_schemas(schemas, count);
    schemas = NULL;

    /* 2) add internally used schemas: ietf-netconf */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf", "2011-06-01");
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

    /* ietf-netconf-monitoring (leave get-schema RPC empty, libnetconf2 will use its callback), */
    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-monitoring", "2010-10-04") &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_monitoring_yin, LYS_IN_YIN)) {
        goto error;
    }

    /* ietf-netconf-with-defaults */
    if (!ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-with-defaults", "2011-06-01") &&
            !lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_with_defaults_2011_06_01_yin, LYS_IN_YIN)) {
        goto error;
    }

    /* debug - list schemas
    struct lyd_node *ylib = ly_ctx_info(np2srv.ly_ctx);
    lyd_print_file(stdout, ylib, LYD_JSON, LYP_WITHSIBLINGS);
    lyd_free(ylib);
    */

    return EXIT_SUCCESS;

error:
    if (schemas) {
        sr_free_schemas(schemas, count);
    }
    ly_ctx_destroy(np2srv.ly_ctx, NULL);
    return EXIT_FAILURE;
}

static int
server_init(void)
{
    int rc;
    const struct lys_node *snode;
    const struct lys_module *mod;

    /* connect to the sysrepo */
    rc = sr_connect("netopeer2", SR_CONN_DAEMON_REQUIRED | SR_CONN_DAEMON_START, &np2srv.sr_conn);
    if (rc != SR_ERR_OK) {
        ERR("Unable to connect to sysrepod (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    VRB("Netopeer2 connected to sysrepod.");

    /* start internal sessions with sysrepo */
    np2srv.sr_sess.ds = SR_DS_STARTUP;
    np2srv.sr_sess.opts = SR_SESS_DEFAULT;
    rc = sr_session_start(np2srv.sr_conn, np2srv.sr_sess.ds, np2srv.sr_sess.opts, &np2srv.sr_sess.srs);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create Netopeer session with sysrepod (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    /* init libyang context with schemas */
    if (np2srv_init_schemas(1)) {
        goto error;
    }

    /* init monitoring */
    ncm_init();

    /* init libnetconf2 */
    if (nc_server_init(np2srv.ly_ctx)) {
        goto error;
    }

    /* set with-defaults capability basic-mode */
    nc_server_set_capab_withdefaults(NC_WD_EXPLICIT, NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT);

    /* prepare poll session structure for libnetconf2 */
    np2srv.nc_ps = nc_ps_new();

    /* set NETCONF operations callbacks */
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get-config");
    nc_set_rpc_callback(snode, op_get);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:edit-config");
    nc_set_rpc_callback(snode, op_editconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:copy-config");
    nc_set_rpc_callback(snode, op_copyconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:delete-config");
    nc_set_rpc_callback(snode, op_deleteconfig);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:lock");
    nc_set_rpc_callback(snode, op_lock);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:unlock");
    nc_set_rpc_callback(snode, op_unlock);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get");
    nc_set_rpc_callback(snode, op_get);

    /* leave close-session RPC empty, libnetconf2 will use its callback */

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:commit");
    nc_set_rpc_callback(snode, op_commit);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:discard-changes");
    nc_set_rpc_callback(snode, op_discardchanges);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:validate");
    nc_set_rpc_callback(snode, op_validate);

    /* TODO
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:kill-session");
    nc_set_rpc_callback(snode, op_kill);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:cancel-commit");
    nc_set_rpc_callback(snode, op_cancel);
     */

    /* set server options */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-netconf-server", NULL);
    if (mod && strcmp(NP2SRV_KEYSTORED_DIR, "none")) {
        nc_server_tls_set_verify_clb(np2srv_verify_clb);
        if (ietf_netconf_server_init(mod)) {
            goto error;
        }

        mod = ly_ctx_get_module(np2srv.ly_ctx, "ietf-system", NULL);
        if (mod) {
            if (ietf_system_init(mod)) {
                goto error;
            }
        } else {
            WRN("Sysrepo does not have the \"ietf-system\" module, SSH publickey authentication will not work.");
        }
    } else {
        WRN("Sysrepo does not have the \"ietf-netconf-server\" module or keystored keys dir unknown, using default NETCONF server options.");
        if (nc_server_add_endpt("main", NC_TI_LIBSSH)) {
            goto error;
        }
        if (nc_server_endpt_set_address("main", "0.0.0.0")) {
            goto error;
        }
        if (nc_server_endpt_set_port("main", 830)) {
            goto error;
        }
        if (nc_server_ssh_endpt_add_hostkey("main", NP2SRV_HOST_KEY)) {
            goto error;
        }
    }

    return EXIT_SUCCESS;

error:
    ERR("Server init failed.");
    return EXIT_FAILURE;
}

static int
connect_ds(struct nc_session *ncs)
{
    struct np2_sessions *s;
    int rc;

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
    s->opts = SR_SESS_DEFAULT;
    rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(ncs), s->ds, s->opts, &s->srs);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create sysrepo session for NETCONF session %d (%s; datastore %d; options %d).",
            nc_session_get_id(ncs), sr_strerror(rc), s->ds, s->opts);
        goto error;
    }

    /* connect sysrepo sessions (datastore) with NETCONF session */
    nc_session_set_data(ncs, s);

    return EXIT_SUCCESS;

error:
    if (s->srs) {
        sr_session_stop(s->srs);
    }
    free(s);
    return EXIT_FAILURE;
}

void *
process_loop(void *arg)
{
    (void)arg; /* UNUSED */

    NC_MSG_TYPE msgtype;
    int rc;
    struct nc_session *ncs;

    nc_libssh_thread_verbosity(np2_verbose_level);

    while (control == LOOP_CONTINUE) {

        /* lock for using libyang context */
        pthread_rwlock_rdlock(&np2srv.ly_ctx_lock);

        /* check context that could be destroyed by np2srv_module_install_clb() */
        if (!np2srv.ly_ctx) {
            pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
            control = LOOP_STOP;
            break;
        }

        /* listen for incomming requests on active NETCONF sessions */
        if (nc_ps_session_count(np2srv.nc_ps) > 0) {
            rc = nc_ps_poll(np2srv.nc_ps, 500, &ncs);
        } else {
            /* if there is no active session or timeout, rest for a while */
            pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
            usleep(100);
            continue;
        }

        /* process the result of nc_ps_poll(), increase counters */
        if (rc & NC_PSPOLL_BAD_RPC) {
            ncm_session_bad_rpc(ncs);
        }
        if (rc & NC_PSPOLL_RPC) {
            ncm_session_rpc(ncs);
        }
        if (rc & NC_PSPOLL_REPLY_ERROR) {
            ncm_session_rpc_reply_error(ncs);
        }
        if (rc & NC_PSPOLL_SESSION_TERM) {
            nc_ps_del_session(np2srv.nc_ps, ncs);
            ncm_session_del(ncs, (rc & NC_PSPOLL_SESSION_ERROR ? 1 : 0));
            nc_session_free(ncs, free_ds);
        } else if (rc & NC_PSPOLL_SSH_CHANNEL) {
            /* a new SSH channel on existing session was created */
            msgtype = nc_session_accept_ssh_channel(ncs, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                nc_ps_add_session(np2srv.nc_ps, ncs);
                ncm_session_add(ncs);
            } else if (msgtype == NC_MSG_BAD_HELLO) {
                ncm_bad_hello();
            }
        }
        pthread_rwlock_unlock(&np2srv.ly_ctx_lock);
    }

    /* cleanup */
    nc_ps_clear(np2srv.nc_ps, 1, free_ds);
    nc_thread_destroy();

    return NULL;
}

int
main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    int c;
    int daemonize = 1;
    int pidfd;
    char pid[8];
    NC_MSG_TYPE msgtype;
    struct sigaction action;
    sigset_t block_mask;
    struct nc_session *ncs;
    pthread_t tid;

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
            c = atoi(optarg);
            /* normalize verbose level */
            np2_verbose_level = (c > NC_VERB_ERROR) ? ((c > NC_VERB_DEBUG) ? NC_VERB_DEBUG : c) : NC_VERB_ERROR;
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
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

        openlog("netopeer2-server", LOG_PID, LOG_DAEMON);
    } else {
        openlog("netopeer2-server", LOG_PID | LOG_PERROR, LOG_DAEMON);
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
    write(pidfd, pid, c);
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

    nc_verbosity(np2_verbose_level);
    nc_libssh_thread_verbosity(np2_verbose_level);

restart:
    /* initiate NETCONF server */
    if (server_init()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* create processing thread for handling requests from active sessions */
    pthread_create(&tid, NULL, process_loop, NULL);

    /* listen for new NETCONF sessions */
    while (control == LOOP_CONTINUE) {
        if (np2srv.nc_max_sessions && (nc_ps_session_count(np2srv.nc_ps) < np2srv.nc_max_sessions)) {
            /* just sleep, no new sessions can connect */
            usleep(500000);
        } else {
            msgtype = nc_accept(500, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                if (connect_ds(ncs)) {
                    /* error */
                    ERR("Terminating session %d due to failure when connecting to sysrepo.",
                        nc_session_get_id(ncs));
                    nc_session_free(ncs, free_ds);
                    continue;
                }
                ncm_session_add(ncs);

                c = 0;
                while ((c < 3) && nc_ps_add_session(np2srv.nc_ps, ncs)) {
                    /* presumably timeout, give it a shot 2 times */
                    usleep(10000);
                    ++c;
                }

                if (c == 3) {
                    /* there is some serious problem in synchronization/system planner */
                    EINT;
                    ncm_session_del(ncs, 1);
                    nc_session_free(ncs, free_ds);
                }
            } else if (msgtype == NC_MSG_WOULDBLOCK) {
                usleep(10000);
            }
        }
    }

    /* wait for finishing processing thread */
    pthread_join(tid, NULL);

cleanup:

    /* disconnect from sysrepo */
    if (np2srv.sr_subscr) {
        sr_unsubscribe(np2srv.sr_sess.srs, np2srv.sr_subscr);
    }
    if (np2srv.sr_sess.srs) {
        sr_session_stop(np2srv.sr_sess.srs);
    }
    sr_disconnect(np2srv.sr_conn);

    /* libnetconf2 cleanup */
    nc_ps_free(np2srv.nc_ps);
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
