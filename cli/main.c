/**
 * @file main.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libyang's yanglint tool
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
#include "linenoise/linenoise.h"

#if !defined(ENABLE_SSH) && !defined(ENABLE_TLS)
#   error "Included libnetconf2 headers were compiled without SSH and TLS support, netopeer2-cli requires at least one of them."
#endif

int done;
char *search_path;

extern char *config_editor;
extern struct nc_session *session;
extern struct ly_ctx *ctx;

void
lnc2_print_clb(NC_VERB_LEVEL level, const char *msg)
{
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
}

void
ly_print_clb(LY_LOG_LEVEL level, const char *msg)
{
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
}

int
main(int argc, char **argv)
{
    char *cmd, *cmdline, *cmdstart;
    int i, j;

#ifdef ENABLE_SSH
    nc_ssh_client_init();
#endif

    nc_set_print_clb(lnc2_print_clb);
    ly_set_log_clb(ly_print_clb);
    linenoiseSetCompletionCallback(complete_cmd);

    config_editor = strdup("vim");

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
                commands[i].func((const char *)cmdstart);
            }
        } else {
            /* if unknown command specified, tell it to user */
            fprintf(stderr, "%s: No such command, type 'help' for more information.\n", cmd);
        }
        linenoiseHistoryAdd(cmdline);

        free(cmd);
        free(cmdline);
    }

    free(search_path);
    free(config_editor);

    if (session) {
        nc_session_free(session);
    }
    if (ctx) {
        ly_ctx_destroy(ctx);
    }

#ifdef ENABLE_SSH
    nc_ssh_client_destroy();
#endif

#ifdef ENABLE_TLS
    nc_tls_client_destroy();
#endif

    return 0;
}
