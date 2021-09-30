/**
 * @file np_test.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author Tadeas Vintlik <xvintr04@stud.fit.vutbr.cz>
 * @brief base source for netopeer2 testing
 *
 * @copyright
 * Copyright 2021 Deutsche Telekom AG.
 * Copyright 2021 CESNET, z.s.p.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include "np_test.h"

#include <errno.h>
#include <fcntl.h>
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

#include "np_test_config.h"

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
setup_server_socket_wait(const char *socket_path)
{
    /* max sleep 10s */
    const uint32_t sleep_count = 400;
    const struct timespec ts = {.tv_sec = 0, .tv_nsec = 25000000};
    uint32_t count = 0;

    while (count < sleep_count) {
        if (!access(socket_path, F_OK)) {
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

void
np_glob_setup_test_name(char *buf)
{
    char *ptr;

    ptr = getenv("TEST_NAME");
    if (ptr) {
        strcpy(buf, ptr);
    } else {
        strcpy(buf, __FILE__);
        buf[strlen(buf) - 2] = '\0';
        ptr = strrchr(buf, '/') + 1;
        memmove(buf, ptr, strlen(ptr) + 1);
    }
}

int
np_glob_setup_env(const char *test_name)
{
    int ret = 1;
    char *sr_repo_path = NULL, *sr_shm_prefix = NULL;

    /* set sysrepo environment variables */
    sr_repo_path = malloc(strlen(NP_SR_REPOS_DIR) + 1 + strlen(test_name) + 1);
    if (!sr_repo_path) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    sprintf(sr_repo_path, "%s/%s", NP_SR_REPOS_DIR, test_name);
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

int
np_glob_setup_np2(void **state, const char *test_name)
{
    struct np_test *st;
    pid_t pid;
    char str[1024], sockparam[1024];
    int fd, pipefd[2], buf;

    /* sysrepo environment variables must be set by NP_GLOB_SETUP_ENV_FUNC prior */
    /* install modules */
    if (setenv("NP2_MODULE_DIR", NP_ROOT_DIR "/modules", 1)) {
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
    if (unsetenv("NP2_MODULE_PERMS")) {
        SETUP_FAIL_LOG;
        return 1;
    }
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

    /* generate path to socket */
    sprintf(sockparam, "-U./repositories/%s/%s", test_name, NP_SOCKET_FILE);
    printf("%s\n", sockparam);

    /* fork and start the server */
    if (!(pid = fork())) {
        /* open log file */
        sprintf(str, "./repositories/%s/%s", test_name, NP_LOG_FILE);
        fd = open(str, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        if (fd == -1) {
            SETUP_FAIL_LOG;
            goto child_error;
        }

        if (debug) {
            printf("pid of netopeer server is: %ld\n", (long) getpid());
            puts("Press return to continue the tests...");
            buf = getc(stdin);
            write(pipefd[1], &buf, sizeof buf);
            close(pipefd[1]);
        }

        /* redirect stdout and stderr */
        dup2(fd, 1);
        dup2(fd, 2);

        close(fd);

        /* exec server listening on a unix socket */
        sprintf(str, "-p./repositories/%s/%s", test_name, NP_PID_FILE);
        execl(NP_BINARY_DIR "/netopeer2-server", NP_BINARY_DIR "/netopeer2-server", "-d", "-v3", str, sockparam,
                "-m 600", (char *)NULL);

child_error:
        printf("Child execution failed\n");
        exit(1);
    } else if (pid == -1) {
        SETUP_FAIL_LOG;
        return 1;
    }

    if (debug) {
        if (read(pipefd[0], &buf, sizeof buf) != sizeof buf) {
            SETUP_FAIL_LOG;
            return 1;
        }
        close(pipefd[0]);
    }

    /* wait for the server, until it creates its socket */
    if (setup_server_socket_wait(sockparam + 2)) {
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
    strcpy(st->socket_path, sockparam + 2);
    strcpy(st->test_name, test_name);

    /* create NETCONF sessions */
    st->nc_sess = nc_connect_unix(st->socket_path, NULL);
    if (!st->nc_sess) {
        SETUP_FAIL_LOG;
        return 1;
    }

    st->nc_sess2 = nc_connect_unix(st->socket_path, NULL);
    if (!st->nc_sess2) {
        SETUP_FAIL_LOG;
        return 1;
    }

    return 0;
}

int
np_glob_teardown(void **state)
{
    struct np_test *st = *state;
    int ret = 0, wstatus;

    if (!st) {
        return 0;
    }

    /* stop the NETCONF session */
    nc_session_free(st->nc_sess, NULL);
    nc_session_free(st->nc_sess2, NULL);

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

int
get_username(char **name)
{
    FILE *file;

    *name = NULL;
    size_t size = 0;

    /* Get user name */
    file = popen("whoami", "r");
    if (!file) {
        return 1;
    }
    if (getline(name, &size, file) == -1) {
        return 1;
    }
    (*name)[strlen(*name) - 1] = '\0'; /* Remove the newline */
    pclose(file);
    return 0;
}

int
setup_nacm(void **state)
{
    struct np_test *st = *state;
    char *user, *data;
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

    if (get_username(&user)) {
        return 1;
    }

    /* Put user and message id into error template */
    if (asprintf(&data, template, user) == -1) {
        return 1;
    }
    free(user);

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

int
is_nacm_rec_uid()
{
    uid_t uid;
    char streuid[10];

    /* Get UID */
    uid = geteuid();
    sprintf(streuid, "%d", (int) uid);
    if (!strcmp(streuid, NACM_RECOVERY_UID)) {
        return 1;
    }
    return 0;
}
