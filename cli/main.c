/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli tool
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#include "commands.h"
#include "compat.h"
#include "completion.h"
#include "configuration.h"
#include "linenoise/linenoise.h"
#include "linenoise/utf8.h"

int done;
extern struct nc_session *session;
extern int monitor;

static void
lnc2_print_clb(const struct nc_session *UNUSED(session), NC_VERB_LEVEL level, const char *msg)
{
    linenoiseBackgroundPrintStart();

    switch (level) {
    case NC_VERB_ERROR:
        fprintf(stderr, "nc ERROR: %s\n", msg);
        break;
    case NC_VERB_WARNING:
        fprintf(stderr, "nc WARNING: %s\n", msg);
        break;
    case NC_VERB_VERBOSE:
        fprintf(stderr, "nc VERBOSE: %s\n", msg);
        break;
    case NC_VERB_DEBUG:
    case NC_VERB_DEBUG_LOWLVL:
        fprintf(stderr, "nc DEBUG: %s\n", msg);
        break;
    }

    linenoiseBackgroundPrintEnd();
}

static void
ly_print_clb(LY_LOG_LEVEL level, const char *msg, const char *data_path, const char *schema_path, uint64_t UNUSED(line))
{
    linenoiseBackgroundPrintStart();

    switch (level) {
    case LY_LLERR:
        if (data_path || schema_path) {
            fprintf(stderr, "ly ERROR: %s (%s)\n", msg, data_path ? data_path : schema_path);
        } else {
            fprintf(stderr, "ly ERROR: %s\n", msg);
        }
        break;
    case LY_LLWRN:
        if (data_path || schema_path) {
            fprintf(stderr, "ly WARNING: %s (%s)\n", msg, data_path ? data_path : schema_path);
        } else {
            fprintf(stderr, "ly WARNING: %s\n", msg);
        }
        break;
    case LY_LLVRB:
        if (data_path || schema_path) {
            fprintf(stderr, "ly VERBOSE: %s (%s)\n", msg, data_path ? data_path : schema_path);
        } else {
            fprintf(stderr, "ly VERBOSE: %s\n", msg);
        }
        break;
    case LY_LLDBG:
        if (data_path || schema_path) {
            fprintf(stderr, "ly DEBUG: %s (%s)\n", msg, data_path ? data_path : schema_path);
        } else {
            fprintf(stderr, "ly DEBUG: %s\n", msg);
        }
        break;
    default:
        /* silent, just to cover enum, shouldn't be here in real world */
        return;
    }

    linenoiseBackgroundPrintEnd();
}

int
main(void)
{
    char *cmd, *cmdline, *cmdstart, *tmp_config_file = NULL;
    int i, j;
    struct sigaction action;

    nc_client_init();

    /* ignore SIGPIPE */
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    nc_set_print_clb_session(lnc2_print_clb);
    ly_set_log_clb(ly_print_clb);
    linenoiseSetCompletionCallback(complete_cmd);
    linenoiseHistoryDataFree(free);
    linenoiseSetEncodingFunctions(linenoiseUtf8PrevCharLen, linenoiseUtf8NextCharLen, linenoiseUtf8ReadCode);
    linenoiseSetMultiLine(1);

    load_history();
    load_config();

    if (!opts.config_editor) {
        opts.config_editor = getenv("EDITOR");
        if (opts.config_editor) {
            opts.config_editor = strdup(opts.config_editor);
        }
    }
    if (!opts.config_editor) {
        opts.config_editor = strdup("vi");
    }

    while (!done) {
        /* get the command from user */
        cmdline = linenoise(NC_CLI_PROMPT);

        /* EOF -> exit */
        if (cmdline == NULL) {
            done = 1;
            cmdline = strdup("quit");
        }

        /* empty line -> wait for another command */
        if (*cmdline == '\0') {
            free(cmdline);
            continue;
        }

        /* isolate the command word. */
        for (i = 0; cmdline[i] && (cmdline[i] == ' '); i++) {}
        cmdstart = cmdline + i;
        for (j = 0; cmdline[i] && (cmdline[i] != ' '); i++, j++) {}
        cmd = strndup(cmdstart, j);

        /* parse the command line */
        for (i = 0; commands[i].name; i++) {
            if (strcmp(cmd, commands[i].name) == 0) {
                break;
            }
        }

        /* execute the command if any valid specified */
        if (commands[i].name) {
            /* display help */
            if ((strchr(cmdstart, ' ') != NULL) && ((strncmp(strchr(cmdstart, ' ') + 1, "-h", 2) == 0) ||
                    (strncmp(strchr(cmdstart, ' ') + 1, "--help", 6) == 0))) {
                if (commands[i].help_func != NULL) {
                    commands[i].help_func();
                } else {
                    printf("%s\n", commands[i].helpstring);
                }
            } else {
                tmp_config_file = linenoiseHistoryDataGet();
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        if (!done) {
            linenoiseHistoryAdd(cmdline, tmp_config_file);
        }

        tmp_config_file = NULL;
        free(cmd);
        free(cmdline);
    }

    store_history();
    free(opts.config_editor);

    if (session) {
        nc_session_free(session, NULL);
    }
    if (monitor) {
        nc_client_monitoring_thread_stop();
    }
    nc_client_destroy();

    return 0;
}
