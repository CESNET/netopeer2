/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli tool
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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

#if !defined(ENABLE_SSH) && !defined(ENABLE_TLS)
#   error "Included libnetconf2 headers were compiled without SSH and TLS support, netopeer2-cli requires at least one of them."
#endif

int done;
char *search_path;

extern char *config_editor;
extern struct nc_session *session;
extern pthread_t ntf_tid;
extern struct ly_ctx *ctx;

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
ly_print_clb(LY_LOG_LEVEL level, const char *msg)
{
    int was_rawmode = 0;

    if (ls.rawmode) {
        was_rawmode = 1;
        linenoiseDisableRawMode(ls.ifd);
        printf("\n");
    }

    switch (level) {
    case LY_LLERR:
        fprintf(stderr, "ly ERROR: %s\n", msg);
        break;
    case LY_LLWRN:
        fprintf(stderr, "ly WARNING: %s\n", msg);
        break;
    case LY_LLVRB:
        fprintf(stderr, "ly VERBOSE: %s\n", msg);
        break;
    case LY_LLDBG:
        fprintf(stderr, "ly DEBUG: %s\n", msg);
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

#ifdef ENABLE_TLS
    nc_tls_init();
#endif
#ifdef ENABLE_SSH
    nc_ssh_init();
#endif

    nc_set_print_clb(lnc2_print_clb);
    ly_set_log_clb(ly_print_clb);
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
                tmp_config_file = NULL;
                commands[i].func((const char *)cmdstart, &tmp_config_file);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        linenoiseHistoryAdd(cmdline);
        if (tmp_config_file) {
            set_hist_file(ls.history_len - 1, tmp_config_file);
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
        nc_session_free(session);
    }
    if (ctx) {
        ly_ctx_destroy(ctx);
    }

#ifdef ENABLE_TLS
    /* must be before SSH */
    nc_client_tls_destroy();
    nc_tls_destroy();
#endif

#ifdef ENABLE_SSH
    nc_client_tls_destroy();
    nc_ssh_destroy();
#endif

    return 0;
}
