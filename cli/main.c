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

#include <nc_client.h>

#include "commands.h"
#include "completion.h"
#include "linenoise/linenoise.h"

int done;
char *search_path;
extern struct nc_session *session;

void
usage(const char *progname)
{
    fprintf(stdout, "Usage: %s [[-h] [-v level] [-p dir] file.yin]\n\n", progname);
    fprintf(stdout, "  -h, --help             Print this text.\n");
    fprintf(stdout, "  -v, --verbose level    Set verbosity level (0-3).\n");
    fprintf(stdout, "  -p, --path dir         Search path for data models.\n");
    fprintf(stdout, "  file.yin               Input file in YIN format.\n\n");
    fprintf(stdout, "The specified model is only loaded and validated.\n");
    fprintf(stdout, "Executing without arguments starts the full interactive version.\n\n");
}

int
main(int argc, char **argv)
{
    char *cmd, *cmdline, *cmdstart;
    int i, j;

#ifdef ENABLE_SSH
    nc_client_init_ssh();
#endif

    linenoiseSetCompletionCallback(complete_cmd);

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
            fprintf(stderr, "%s: no such command, type 'help' for more information.\n", cmd);
        }
        linenoiseHistoryAdd(cmdline);

        free(cmd);
        free(cmdline);
    }

    free(search_path);

    if (session) {
        nc_session_free(session);
    }

#ifdef ENABLE_SSH
    nc_client_destroy_ssh();
#endif

    return 0;
}
