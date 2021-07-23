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

#define _POSIX_C_SOURCE 200809L

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
setup_server_socket_wait(void)
{
    /* max sleep 5s */
    const uint32_t sleep_count = 200;
    const struct timespec ts = {.tv_sec = 0, .tv_nsec = 25000000};
    uint32_t count = 0;

    while (count < sleep_count) {
        if (!access(NP_SOCKET_PATH, F_OK)) {
            break;
        }

        nanosleep(&ts, NULL);
        ++count;
    }

    if (count == sleep_count) {
        return 1;
    }
    return 0;
}

int
setup_setenv_sysrepo(const char *test_name)
{
    int ret = 1;
    char *sr_repo_path = NULL, *sr_shm_prefix = NULL;

    /* set sysrepo environment variables */
    sr_repo_path = malloc(strlen(NP_SR_REPOS_DIR) + 1 + strlen(test_name) + 1);
    if (!sr_repo_path) {
        goto cleanup;
    }
    sprintf(sr_repo_path, "%s/%s", NP_SR_REPOS_DIR, test_name);
    if (setenv("SYSREPO_REPOSITORY_PATH", sr_repo_path, 1)) {
        goto cleanup;
    }

    sr_shm_prefix = malloc(strlen(NP_SR_SHM_PREFIX) + strlen(test_name) + 1);
    if (!sr_shm_prefix) {
        goto cleanup;
    }
    sprintf(sr_shm_prefix, "%s%s", NP_SR_SHM_PREFIX, test_name);
    if (setenv("SYSREPO_SHM_PREFIX", sr_shm_prefix, 1)) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(sr_repo_path);
    free(sr_shm_prefix);
    return ret;
}

int
np_glob_setup_np2(void **state)
{
    struct np_test *st;
    pid_t pid;
    int fd, pipefd[2], buf;

    /* sysrepo environment variables must be set by NP_GLOB_SETUP_ENV_FUNC prior */
    /* install modules */
    if (setenv("NP2_MODULE_DIR", NP_ROOT_DIR "/modules", 1)) {
        return 1;
    }
    if (setenv("NP2_MODULE_PERMS", "600", 1)) {
        return 1;
    }
    if (system(NP_ROOT_DIR "/scripts/setup.sh")) {
        return 1;
    }
    if (unsetenv("NP2_MODULE_DIR")) {
        return 1;
    }
    if (unsetenv("NP2_MODULE_PERMS")) {
        return 1;
    }
    if (setenv("CMOCKA_TEST_ABORT", "1", 0)) {
        return 1;
    }

    /* create pipe for synchronisation if debugging */
    if (debug) {
        if (pipe(pipefd)) {
            return 1;
        }
    }

    /* fork and start the server */
    if (!(pid = fork())) {
        /* open log file */
        fd = open(NP_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        if (fd == -1) {
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
        execl(NP_BINARY_DIR "/netopeer2-server", NP_BINARY_DIR "/netopeer2-server", "-d", "-v3", "-p" NP_PID_PATH,
                "-U" NP_SOCKET_PATH, "-m 600", (char *)NULL);

child_error:
        printf("Child execution failed\n");
        exit(1);
    } else if (pid == -1) {
        return 1;
    }

    if (debug) {
        if (read(pipefd[0], &buf, sizeof buf) != sizeof buf) {
            return 1;
        }
        close(pipefd[0]);
    }

    /* wait for the server, until it creates its socket */
    if (setup_server_socket_wait()) {
        return 1;
    }

    /* create test state structure, up to teardown now to free it */
    st = calloc(1, sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;
    st->server_pid = pid;

    /* create NETCONF sessions */
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    if (!st->nc_sess) {
        return 1;
    }

    st->nc_sess2 = nc_connect_unix(NP_SOCKET_PATH, NULL);
    if (!st->nc_sess2) {
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
        ret = 1;
    }
    if (unsetenv("SYSREPO_SHM_PREFIX")) {
        ret = 1;
    }

    if (unsetenv("CMOCKA_TEST_ABORT")) {
        return 1;
    }

    free(st);
    return ret;
}
