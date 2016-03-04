/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli tool
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/times.h>
#include <string.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#include "commands.h"
#include "completion.h"
#include "configuration.h"
#include "linenoise/linenoise.h"

int done;
char *search_path;

struct history_file {
    int *hist_idx;
    char **file;
    int count;
} hist_file;

extern char *config_editor;
extern struct nc_session *session;
extern pthread_t ntf_tid;
extern struct ly_ctx *ctx;

static const char *
get_hist_file(int hist_idx)
{
    int i;

    if (!hist_idx) {
        return NULL;
    }

    for (i = 0; i < hist_file.count; ++i) {
        if (hist_file.hist_idx[i] == hist_idx) {
            return hist_file.file[i];
        }
    }

    return NULL;
}

static void
set_hist_file(int hist_idx, const char *file)
{
    int i;

    for (i = 0; i < hist_file.count; ++i) {
        if (hist_file.hist_idx[i] == hist_idx) {
            free(hist_file.file[i]);
            hist_file.file[i] = strdup(file);
            return;
        }
    }

    ++hist_file.count;
    hist_file.hist_idx = realloc(hist_file.hist_idx, hist_file.count * sizeof *hist_file.hist_idx);
    hist_file.file = realloc(hist_file.file, hist_file.count * sizeof *hist_file.file);

    hist_file.hist_idx[hist_file.count - 1] = hist_idx;
    hist_file.file[hist_file.count - 1] = strdup(file);
}

static void
free_hist_file(void)
{
    int i;

    for (i = 0; i < hist_file.count; ++i) {
        free(hist_file.file[i]);
    }
    free(hist_file.hist_idx);
    free(hist_file.file);
}

void
lnc2_print_clb(NC_VERB_LEVEL level, const char *msg)
{
    int was_rawmode = 0;

    if (ls.rawmode) {
        was_rawmode = 1;
        linenoiseDisableRawMode(ls.ifd);
        printf("\n");
    }

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
        fprintf(stderr, "nc DEBUG: %s\n", msg);
        break;
    }

    if (was_rawmode) {
        linenoiseEnableRawMode(ls.ifd);
        linenoiseRefreshLine();
    }
}

void
ly_print_clb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    int was_rawmode = 0;

    if (ls.rawmode) {
        was_rawmode = 1;
        linenoiseDisableRawMode(ls.ifd);
        printf("\n");
    }

    switch (level) {
    case LY_LLERR:
        if (path) {
            fprintf(stderr, "ly ERROR: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly ERROR: %s\n", msg);
        }
        break;
    case LY_LLWRN:
        if (path) {
            fprintf(stderr, "ly WARNING: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly WARNING: %s\n", msg);
        }
        break;
    case LY_LLVRB:
        if (path) {
            fprintf(stderr, "ly VERBOSE: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly VERBOSE: %s\n", msg);
        }
        break;
    case LY_LLDBG:
        if (path) {
            fprintf(stderr, "ly DEBUG: %s (%s)\n", msg, path);
        } else {
            fprintf(stderr, "ly DEBUG: %s\n", msg);
        }
        break;
    }

    if (was_rawmode) {
        linenoiseEnableRawMode(ls.ifd);
        linenoiseRefreshLine();
    }
}

int
main(void)
{
    char *cmd, *cmdline, *cmdstart, *tmp_config_file;
    int i, j;

    nc_client_init();

    nc_set_print_clb(lnc2_print_clb);
    ly_set_log_clb(ly_print_clb, 1);
    linenoiseSetCompletionCallback(complete_cmd);

    load_config();

    if (!config_editor) {
        config_editor = getenv("EDITOR");
        if (config_editor) {
            config_editor = strdup(config_editor);
        }
    }
    if (!config_editor) {
        config_editor = strdup("vi");
    }

    while (!done) {
        /* get the command from user */
        cmdline = linenoise(PROMPT);

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
        for (i = 0; cmdline[i] && (cmdline[i] == ' '); i++);
        cmdstart = cmdline + i;
        for (j = 0; cmdline[i] && (cmdline[i] != ' '); i++, j++);
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
            if ((strchr(cmdstart, ' ') != NULL) && ((strncmp(strchr(cmdstart, ' ') + 1, "-h", 2) == 0)
                    || (strncmp(strchr(cmdstart, ' ') + 1, "--help", 6) == 0))) {
                if (commands[i].help_func != NULL) {
                    commands[i].help_func();
                } else {
                    printf("%s\n", commands[i].helpstring);
                }
            } else {
                tmp_config_file = (char *)get_hist_file(ls.history_len - ls.history_index);
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        i = linenoiseHistoryAdd(cmdline);
        if (tmp_config_file) {
            set_hist_file(ls.history_len - 1 - i, tmp_config_file);
            free(tmp_config_file);
        }

        free(cmd);
        free(cmdline);
    }

    store_config();

    free(search_path);
    free(config_editor);
    free_hist_file();

    ntf_tid = 0;
    if (session) {
        nc_session_free(session, NULL);
        session = NULL;
        ctx = NULL;
    }

    nc_client_destroy();

    return 0;
}
