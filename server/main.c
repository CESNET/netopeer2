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

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

#include "../modules/ietf-netconf-acm.h"
#include "../modules/ietf-netconf@2011-06-01.h"
#include "../modules/ietf-netconf-monitoring.h"
#include "../modules/ietf-netconf-with-defaults@2011-06-01.h"

struct np2srv np2srv;

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
    default:
        exit(EXIT_FAILURE);
        break;
    }
}
char *
np2srv_ly_module_clb(const char *name, const char *revision, void *user_data, LYS_INFORMAT *format,
                     void (**free_module_data)(void *model_data))
{
    char *data = NULL;

    *free_module_data = NULL;
    *format = LYS_IN_YIN;

    if (sr_get_schema(np2srv.sr_sess.startup, (const char *)user_data, revision, name, SR_SCHEMA_YIN,
                      &data) == SR_ERR_OK) {
        /* include */
        return data;
    } else if (sr_get_schema(np2srv.sr_sess.startup, name, revision, NULL, SR_SCHEMA_YIN,
                             &data) == SR_ERR_OK) {
        /* import */
        return data;
    }
    ERR("Unable to get %s module (as dependency of %s) from sysrepo.", name, (const char *)user_data);

    return NULL;
}

static int
server_init(void)
{
    sr_schema_t *schemas = NULL;
    const struct lys_node *snode;
    const struct lys_module *mod;
    int rc;
    char *data;
    size_t count, i;

    /* connect to the sysrepo */
    rc = sr_connect("netopeer2", false, &np2srv.sr_conn);
    if (rc != SR_ERR_OK) {
        ERR("Unable to connect to sysrepod (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    VRB("Netopeer2 connected to sysrepod.");

    /* start internal sessions with sysrepo */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &np2srv.sr_sess.running);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create Netopeer session to sysrepod (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }
    /* TODO no need for this one probably */
    /*rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, SR_SESS_CONFIG_ONLY, &np2srv.sr_sess.running_config);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create Netopeer session to sysrepod (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }*/
    rc = sr_session_start(np2srv.sr_conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &np2srv.sr_sess.startup);
    if (rc != SR_ERR_OK) {
        VRB("Startup datastore not available in sysrepod (%s).", sr_strerror(rc));
    }
    /* TODO sysrepo does not support candidate
    rc = sr_session_start(np2srv.sr_conn, SR_DS_CANDIDATE, &np2srv.sr_sess.candidate);
    if (rc != SR_ERR_OK) {
        VRB("Candidate datastore not available in sysrepod (%s).", sr_strerror(rc));
    }
    */

    rc = sr_list_schemas(np2srv.sr_sess.startup, &schemas, &count);
    if (rc != SR_ERR_OK) {
        ERR("Unable to get list of schemas supported by sysrepo (%s).", sr_strerror(rc));
        return EXIT_FAILURE;
    }

    /* build libyang context */
    np2srv.ly_ctx = ly_ctx_new(NULL);
    if (!np2srv.ly_ctx) {
        return EXIT_FAILURE;
    }

    /* 1) with modules from sysrepo */
    for (i = 0; i < count; i++) {
        ly_ctx_set_module_clb(np2srv.ly_ctx, np2srv_ly_module_clb, (void*)schemas[i].module_name);
        data = NULL;
        mod = NULL;

        if ((mod = ly_ctx_get_module(np2srv.ly_ctx, schemas[i].module_name, schemas[i].revision.revision))) {
            VRB("Module %s (%s) already present in context.", schemas[i].module_name,
                schemas[i].revision.revision ? schemas[i].revision.revision : "no revision");
        } else if (sr_get_schema(np2srv.sr_sess.running, schemas[i].module_name,
                                 schemas[i].revision.revision, NULL, SR_SCHEMA_YIN, &data) == SR_ERR_OK) {
            mod = lys_parse_mem(np2srv.ly_ctx, data, LYS_IN_YIN);
            free(data);
        }

        if (!mod) {
            WRN("Getting %s (%s) schema from sysrepo failed, data from this module won't be available.",
                schemas[i].module_name,
                schemas[i].revision.revision ? schemas[i].revision.revision : "no revision");
        }
    }
    sr_free_schemas(schemas, count);

    /* 2) add ietf-netconf with ietf-netconf-acm - TODO do it correctly as sysrepo's southbound app */
    lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_acm_yin, LYS_IN_YIN);
    mod = lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_2011_06_01_yin, LYS_IN_YIN);
    lys_features_enable(mod, "writable-running");
    if (np2srv.sr_sess.startup) {
        lys_features_enable(mod, "startup");
    }
    if (np2srv.sr_sess.candidate) {
        lys_features_enable(mod, "candidate");
    }

    /* 3) add ietf-netconf-monitoring */
    lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_monitoring_yin, LYS_IN_YIN);

    /* 4) add ietf-netconf-with-defaults */
    lys_parse_mem(np2srv.ly_ctx, (const char *)ietf_netconf_with_defaults_2011_06_01_yin, LYS_IN_YIN);

    /* debug - list schemas
    struct lyd_node *ylib = ly_ctx_info(np2srv.ly_ctx);
    lyd_print_file(stdout, ylib, LYD_JSON, LYP_WITHSIBLINGS);
    lyd_free(ylib);
    */

    /* init libnetconf2 */
    nc_server_init(np2srv.ly_ctx);

    /* set with-defaults capability basic-mode */
    nc_server_set_capab_withdefaults(NC_WD_EXPLICIT, NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT);

    /* prepare poll session structure for libnetconf2 */
    np2srv.nc_ps = nc_ps_new();

    /* set NETCONF operations callbacks */
    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get");
    lys_set_private(snode, op_get);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:get-config");
    lys_set_private(snode, op_get);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:lock");
    lys_set_private(snode, op_lock);

    snode = ly_ctx_get_node(np2srv.ly_ctx, NULL, "/ietf-netconf:unlock");
    lys_set_private(snode, op_unlock);

    nc_server_ssh_add_endpt_listen("main", "0.0.0.0", 6001);
    nc_server_ssh_endpt_set_hostkey("main", "/etc/ssh/ssh_host_rsa_key");

    return EXIT_SUCCESS;
}

void
free_ds(void *ptr)
{
    struct np2sr_sessions *s;

    if (ptr) {
        s = (struct np2sr_sessions *)ptr;
        if (s->running) {
            sr_session_stop(s->running);
        }
        if (s->running_config) {
            sr_session_stop(s->running_config);
        }
        if (s->startup) {
            sr_session_stop(s->startup);
        }
        /* TODO sysrepo does not support candidate
        if (s->candidate) {
            sr_session_stop(s->candidate);
        }
        */
        np2srv_clean_dslock(s->ncs);
        free(s);
    }
}

static int
connect_ds(struct nc_session *ncs)
{
    struct np2sr_sessions *s;
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

    rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(ncs), SR_DS_RUNNING, SR_SESS_DEFAULT, &s->running);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create sysrepo running session for NETCONF session %d (%s).",
            nc_session_get_id(ncs), sr_strerror(rc));
        goto error;
    }
    rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(ncs), SR_DS_RUNNING, SR_SESS_CONFIG_ONLY, &s->running_config);
    if (rc != SR_ERR_OK) {
        ERR("Unable to create sysrepo running config session for NETCONF session %d (%s).",
            nc_session_get_id(ncs), sr_strerror(rc));
        goto error;
    }
    if (np2srv.sr_sess.startup) {
        rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(ncs), SR_DS_STARTUP, SR_SESS_DEFAULT, &s->startup);
        if (rc != SR_ERR_OK) {
            ERR("Unable to create sysrepo startup session for NETCONF session %d (%s).",
                nc_session_get_id(ncs), sr_strerror(rc));
            goto error;
        }
    }
    /* TODO sysrepo does not support candidate
    if (np2srv.sr_sess.candidate) {
        rc = sr_session_start_user(np2srv.sr_conn, nc_session_get_username(ncs), SR_DS_CANDIDATE, &s->candidate);
        if (rc != SR_ERR_OK) {
            ERR("Unable to create sysrepo candidate session for NETCONF session %d (%s).",
                nc_session_get_id(ncs), sr_strerror(rc));
            goto error;
        }
    }
    */

    /* connect sysrepo sessions (datastore) with NETCONF session */
    nc_session_set_data(ncs, s);

    return EXIT_SUCCESS;

error:
    if (s->running) {
        sr_session_stop(s->running);
    }
    if (s->running_config) {
        sr_session_stop(s->running_config);
    }
    if (s->startup) {
        sr_session_stop(s->startup);
    }
    /* TODO sysrepo does not support candidate
    if (s->candidate) {
        sr_session_stop(s->candidate);
    }
    */

    free(s);
    return EXIT_FAILURE;
}

void *
process_loop(void *arg)
{
    (void)arg; /* UNUSED */

    int rc;
    struct nc_session *ncs;

    while (control == LOOP_CONTINUE) {
        /* listen for incomming requests on active NETCONF sessions */
        if (nc_ps_session_count(np2srv.nc_ps)) {
            rc = nc_ps_poll(np2srv.nc_ps, 500);
        } else {
            /* if there is no active session, rest for a while */
            usleep(100);
            continue;
        }

        /* process the result of nc_ps_poll() */
        if (rc == -1 || rc == 3) {
            /* some session changed its status and should be removed */
            nc_ps_clear(np2srv.nc_ps, 0, free_ds);
            usleep(250);
        } else if (rc == 5) {
            /* a new SSH channel on existing session was created */
            nc_ps_accept_ssh_channel(np2srv.nc_ps, &ncs);
            nc_ps_add_session(np2srv.nc_ps, ncs);
        }
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
    int c, rc;
    int daemonize = 1;
    int pidfd;
    char pid[8];
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
    /* ignore SIGPIPE */
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    /* set printer callbacks for the used libraries and set proper log levels */
    nc_set_print_clb(np2log_clb_nc2); /* libnetconf2 */
    ly_set_log_clb(np2log_clb_ly, 1); /* libyang */
    sr_log_set_cb(np2log_clb_sr); /* sysrepo, log level is checked by callback */

    nc_verbosity(np2_verbose_level);
    ly_verb(np2_verbose_level);

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
        rc = nc_accept(500, &ncs);
        if (rc == 1) {
            if (connect_ds(ncs)) {
                /* error */
                ERR("Terminating session %d due to failure when connecting to sysrepo.",
                    nc_session_get_id(ncs));
                nc_session_free(ncs, free_ds);
                continue;
            }
            nc_ps_add_session(np2srv.nc_ps, ncs);
        }
    }

    /* wait for finishing processing thread */
    pthread_join(tid, NULL);

cleanup:

    /* disconnect from sysrepo */
    if (np2srv.sr_sess.running) {
        sr_session_stop(np2srv.sr_sess.running);
    }
    if (np2srv.sr_sess.startup) {
        sr_session_stop(np2srv.sr_sess.startup);
    }
    /* TODO sysrepo does not support candidate
    if (np2srv.sr_sess.candidate) {
        sr_session_stop(np2srv.sr_sess.candidate);
    }
    */
    sr_disconnect(np2srv.sr_conn);

    /* libnetconf2 cleanup */
    nc_ps_free(np2srv.nc_ps);
    nc_server_destroy();

    /* libyang cleanup */
    ly_ctx_destroy(np2srv.ly_ctx, NULL);

    /* are we requested to stop or just to restart? */
    if (control == LOOP_RESTART) {
        goto restart;
    }

    return ret;
}
