/**
 * @file np2_test.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author Tadeas Vintlik <xvintr04@stud.fit.vutbr.cz>
 * @brief base source for netopeer2 testing
 *
 * @copyright
 * Copyright (c) 2019 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "np2_test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <nc_client.h>
#include <sysrepo/netconf_acm.h>

#include "np2_other_client.h"
#include "np2_test_config.h"

#ifdef NETOPEER2_LIB
# include "netopeer2.h"
#endif

uint8_t debug = 0; /* Global variable to indicate if debugging */

void
parse_arg(int argc, char **argv)
{
    if (argc <= 1) {
        return;
    }

    if (!strcmp(argv[1], "-d") || !strcmp(*argv, "--debug")) {
        puts("Starting in debug mode.");
        debug = 1;
    }
}

static int
mkpath(char *path, mode_t mode)
{
    int rc = 0;
    char *p = NULL;

    /* create each directory in the path */
    for (p = strchr(path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if ((mkdir(path, mode) == -1) && (errno != EEXIST)) {
            rc = -1;
            goto cleanup;
        }

        errno = 0;
        *p = '/';
    }

    /* create the last directory in the path */
    if ((mkdir(path, mode) == -1) && (errno != EEXIST)) {
        rc = -1;
        goto cleanup;
    }
    errno = 0;

cleanup:
    if (p) {
        *p = '/';
    }
    return rc;
}

void
np2_glob_test_setup_test_name(char *buf)
{
    char *ptr;

    ptr = getenv("TEST_NAME");
    if (ptr) {
        strncpy(buf, ptr, 255);
    } else {
        strncpy(buf, __FILE__, 255);
        buf[strlen(buf) - 2] = '\0';
        ptr = strrchr(buf, '/') + 1;
        memmove(buf, ptr, strlen(ptr) + 1);
    }
}

int
np2_glob_test_setup_env(const char *test_name)
{
    int ret = 1;
    char *sr_repo_path = NULL, *sr_shm_prefix = NULL;

    /* set sysrepo environment variables */
    sr_repo_path = malloc(strlen(NP_TEST_DIR) + 1 + strlen(test_name) + 1);
    if (!sr_repo_path) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    sprintf(sr_repo_path, "%s/%s", NP_TEST_DIR, test_name);
    if (setenv("SYSREPO_REPOSITORY_PATH", sr_repo_path, 1)) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    sr_shm_prefix = malloc(strlen(NP_SR_SHM_PREFIX) + strlen(test_name) + 1);
    if (!sr_shm_prefix) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    sprintf(sr_shm_prefix, "%s%s", NP_SR_SHM_PREFIX, test_name);
    if (setenv("SYSREPO_SHM_PREFIX", sr_shm_prefix, 1)) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(sr_repo_path);
    free(sr_shm_prefix);
    return ret;
}

static int
setup_server_file_exists_wait(const char *path)
{
    /* max sleep 10s */
    const uint32_t sleep_count = 200;
    const struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000};
    uint32_t count = 0;

    while (count < sleep_count) {
        if (!access(path, F_OK)) {
            break;
        }

        nanosleep(&ts, NULL);
        ++count;
    }

    if (count == sleep_count) {
        SETUP_FAIL_LOG;
        return 1;
    }
    return 0;
}

static int
np2_glob_test_setup_sess_ctx(struct nc_session *sess, const char **modules)
{
    struct ly_ctx *ctx;
    const char *all_features[] = {"*", NULL};
    const char *sub_ntf_features[] = {"encode-xml", "replay", "subtree", "xpath", NULL};
    uint32_t i;
    char *path;

    ctx = (struct ly_ctx *)nc_session_get_ctx(sess);

    /* server YANG dir searchdir */
    asprintf(&path, "%s/yang", getenv("SYSREPO_REPOSITORY_PATH"));
    ly_ctx_set_searchdir(ctx, path);
    free(path);

    /* base modules */
    if (!ly_ctx_load_module(ctx, "ietf-netconf", "2013-09-29", all_features)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-netconf-with-defaults", "2011-06-01", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-yang-library", "2019-01-04", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-datastores", "2018-02-14", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "notifications", "2008-07-14", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "nc-notifications", "2008-07-14", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-netconf-notifications", "2012-02-06", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-netconf-nmda", "2019-01-07", all_features)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-subscribed-notifications", "2019-09-09", sub_ntf_features)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "ietf-yang-push", "2019-09-09", all_features)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (!ly_ctx_load_module(ctx, "netopeer-notifications", "2025-01-15", NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* test module searchdir */
    ly_ctx_set_searchdir(ctx, NP_TEST_MODULE_DIR);

    /* test modules */
    if (modules) {
        for (i = 0; modules[i]; ++i) {
            if (lys_parse_path(ctx, modules[i], LYS_IN_YANG, NULL)) {
                SETUP_FAIL_LOG;
                return 1;
            }
        }
    }

    /* schema-mount, uses the final context */
    if (nc_client_set_new_session_context_schema_mount(sess)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    return 0;
}

int
np2_glob_test_setup_server(void **state, const char *test_name, const char **modules, uint32_t flags)
{
    struct np2_test *st;
    pid_t pid = 0;
    char server_dir[256], extdata_path[256], sock_path[256], pidfile_path[256];
    int pipefd[2], buf;
    struct ly_ctx *ly_ctx;

#ifndef NETOPEER2_LIB
    char str[256];
    int fd;
#endif

#ifdef NETOPEER2_LIB
    /* lib setup function */
    if (np2_sr_setup(NULL, NULL, 0600)) {
        SETUP_FAIL_LOG;
        return 1;
    }
#else
    /* sysrepo environment variables must be set by NP_GLOB_SETUP_ENV_FUNC prior to install modules */
    if (setenv("NP2_MODULE_DIR", NP_ROOT_DIR "/modules", 1)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (setenv("LN2_MODULE_DIR", LN2_YANG_MODULE_DIR, 1)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (setenv("NP2_MODULE_PERMS", "600", 1)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (system(NP_ROOT_DIR "/scripts/setup.sh")) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (unsetenv("NP2_MODULE_DIR")) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (unsetenv("LN2_MODULE_DIR")) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (unsetenv("NP2_MODULE_PERMS")) {
        SETUP_FAIL_LOG;
        return 1;
    }
#endif

    if (setenv("CMOCKA_TEST_ABORT", "1", 0)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* create pipe for synchronisation if debugging */
    if (debug) {
        if (pipe(pipefd)) {
            SETUP_FAIL_LOG;
            return 1;
        }
    }

    /* generate path to the server's pidfile */
    sprintf(pidfile_path, "%s/%s/%s", NP_TEST_DIR, test_name, NP_PID_FILE);

    /* generate path to socket */
    sprintf(sock_path, "%s/%s/%s", NP_TEST_DIR, test_name, NP_SOCKET_FILE);

    /* generate path to server-files */
    sprintf(server_dir, "%s/%s", NP_TEST_DIR, test_name);

    /* generate path to the schema-mount ext data */
    sprintf(extdata_path, "%s/%s", NP_TEST_MODULE_DIR, NP_EXT_DATA_FILE);

    /* create the test server dir */
    if (mkpath(server_dir, 00700) == -1) {
        SETUP_FAIL_LOG;
        return 1;
    }

#ifdef NETOPEER2_LIB
    if (np2_server_test_start(pidfile_path, sock_path, server_dir, extdata_path)) {
        SETUP_FAIL_LOG;
        return 1;
    }
#else
    /* fork and start the server */
    if (!(pid = fork())) {
        /* open log file */
        sprintf(str, "%s/%s/%s", NP_TEST_DIR, test_name, NP_LOG_FILE);
        fd = open(str, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        if (fd == -1) {
            SETUP_FAIL_LOG;
            goto child_error;
        }

        if (debug) {
            printf("pid of netopeer server is: %ld\n", (long) getpid());
            puts("Press return to continue the tests...");
            buf = getc(stdin);
            if (write(pipefd[1], &buf, sizeof buf) != sizeof buf) {
                SETUP_FAIL_LOG;
                exit(1);
            }
            close(pipefd[1]);
        }

        /* redirect stdout and stderr */
        dup2(fd, 1);
        dup2(fd, 2);

        close(fd);

        /* exec the server */
        execl(NP_BINARY_DIR "/netopeer2-server", NP_BINARY_DIR "/netopeer2-server", "-d", "-v3", "-t10", "-p", pidfile_path,
                "-U", sock_path, "-m 600", "-f", server_dir, "-x", extdata_path, NULL);

child_error:
        printf("Child execution failed\n");
        exit(1);
    } else if (pid == -1) {
        SETUP_FAIL_LOG;
        return 1;
    }
#endif

    if (debug) {
        if (read(pipefd[0], &buf, sizeof buf) != sizeof buf) {
            SETUP_FAIL_LOG;
            return 1;
        }
        close(pipefd[0]);
    }

    /* wait until the server creates a pidfile */
    if (setup_server_file_exists_wait(pidfile_path)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* create test state structure, up to teardown now to free it */
    st = calloc(1, sizeof *st);
    if (!st) {
        SETUP_FAIL_LOG;
        return 1;
    }
    *state = st;
    st->server_pid = pid;
    memcpy(st->socket_path, sock_path, sizeof st->socket_path);
    memcpy(st->test_name, test_name, sizeof st->test_name);

    /* create connection and install modules */
    if (sr_connect(SR_CONN_DEFAULT, &st->conn)) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (modules && sr_install_modules(st->conn, modules, NULL, NULL)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* start session */
    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* acquire context */
    if (!(st->ctx = sr_acquire_context(st->conn))) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* init LNC2 */
    if (nc_client_init()) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* disable automatic YANG retrieval */
    nc_client_set_new_session_context_autofill(0);

    if (flags & NP_GLOB_SETUP_OTHER_CLIENT) {
        st->oc_sess = oc_connect_unix(st->socket_path);
        if (!st->oc_sess) {
            SETUP_FAIL_LOG;
            return 1;
        }
    } else {
        /* create NETCONF sessions, with a single context */
        st->nc_sess2 = nc_connect_unix(st->socket_path, NULL);
        if (!st->nc_sess2) {
            SETUP_FAIL_LOG;
            return 1;
        }
        if (np2_glob_test_setup_sess_ctx(st->nc_sess2, modules)) {
            SETUP_FAIL_LOG;
            return 1;
        }

        ly_ctx = (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2);
        st->nc_sess = nc_connect_unix(st->socket_path, ly_ctx);
        if (!st->nc_sess) {
            SETUP_FAIL_LOG;
            return 1;
        }
    }

    return 0;
}

int
np2_glob_test_teardown_notif(const char *test_name)
{
    char *path;
    DIR *dir;
    struct dirent *ent;

    /* open notification dir */
    if (asprintf(&path, "%s/%s/data/notif", NP_TEST_DIR, test_name) == -1) {
        return 1;
    }
    dir = opendir(path);
    free(path);
    if (!dir) {
        return 1;
    }

    /* remove all notif1 notifications */
    while ((ent = readdir(dir))) {
        if (!strncmp(ent->d_name, "notif1.notif", 12)) {
            if (asprintf(&path, "%s/%s/data/notif/%s", NP_TEST_DIR, test_name, ent->d_name) == -1) {
                closedir(dir);
                return 1;
            }
            unlink(path);
            free(path);
        }
    }

    closedir(dir);
    return 0;
}

int
np2_glob_test_teardown(void **state, const char **modules)
{
    struct np2_test *st = *state;
    int ret = 0, rc;

#ifndef NETOPEER2_LIB
    int wstatus;
#endif

    if (!st) {
        return 0;
    }

    /* stop NETCONF sessions */
    nc_session_free(st->nc_sess, NULL);
    nc_session_free(st->nc_sess2, NULL);

    /* destroy LNC2 */
    nc_client_destroy();

    /* release context */
    sr_release_context(st->conn);

    oc_session_free(st->oc_sess);

#ifdef NETOPEER2_LIB
    if (np2_server_test_stop()) {
        printf("np2_server_test_stop() failed\n");
        ret = 1;
    }
#else
    /* terminate the server */
    if (kill(st->server_pid, SIGTERM)) {
        printf("kill() failed (%s)\n", strerror(errno));
        ret = 1;
    }

    /* wait for it */
    if (waitpid(st->server_pid, &wstatus, 0) != st->server_pid) {
        printf("waitpid() failed (%s)\n", strerror(errno));
        ret = 1;
    } else if (!WIFEXITED(wstatus)) {
        if (WIFSIGNALED(wstatus)) {
            printf("Unexpected server exit (by signal %s)\n", strsignal(WTERMSIG(wstatus)));
        } else {
            printf("Unexpected server exit (unknown reason)\n");
        }
        ret = 1;
    } else if (WEXITSTATUS(wstatus)) {
        printf("Unexpected server exit status (%d)\n", WEXITSTATUS(wstatus));
        ret = 1;
    }
#endif

    /* uninstall modules */
    if (modules && (rc = sr_remove_modules(st->conn, modules, 0))) {
        printf("sr_remove_modules() failed (%s)\n", sr_strerror(rc));
        ret = 1;
    }

    /* disconnect */
    if ((rc = sr_disconnect(st->conn))) {
        printf("sr_disconnect() failed (%s)\n", sr_strerror(rc));
        ret = 1;
    }

    /* unset sysrepo environment variables */
    if (unsetenv("SYSREPO_REPOSITORY_PATH")) {
        SETUP_FAIL_LOG;
        ret = 1;
    }
    if (unsetenv("SYSREPO_SHM_PREFIX")) {
        SETUP_FAIL_LOG;
        ret = 1;
    }

    if (unsetenv("CMOCKA_TEST_ABORT")) {
        SETUP_FAIL_LOG;
        return 1;
    }

    free(st);
    return ret;
}

const char *
np2_get_user(void)
{
    struct passwd *pw;

    pw = getpwuid(geteuid());

    return pw ? pw->pw_name : NULL;
}

int
np2_is_nacm_recovery(void)
{
    return !strcmp(sr_nacm_get_recovery_user(), np2_get_user());
}

int
np2_glob_test_setup_nacm(void **state)
{
    struct np2_test *st = *state;
    char *data;
    const char *template =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <write-default>permit</write-default>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>%s</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "</nacm>\n";

    /* Put user and message id into error template */
    if (asprintf(&data, template, np2_get_user()) == -1) {
        return 1;
    }

    /* Parse and merge the config */
    if (lyd_parse_data_mem(st->ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &st->node)) {
        return 1;
    }
    free(data);
    if (!st->node) {
        return 1;
    }
    if (sr_edit_batch(st->sr_sess, st->node, "merge")) {
        return 1;
    }
    if (sr_apply_changes(st->sr_sess, 0)) {
        return 1;
    }

    FREE_TEST_VARS(st);

    return 0;
}
