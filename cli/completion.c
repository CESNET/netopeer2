/**
 * @file completion.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libyang's yanglint tool auto completion
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "commands.h"
#include "linenoise/linenoise.h"

extern struct ly_ctx *ctx;

static void
get_cmd_completion(const char *hint, char ***matches, unsigned int *match_count)
{
    int i;

    *match_count = 0;
    *matches = NULL;

    for (i = 0; commands[i].name; i++) {
        if (!strncmp(hint, commands[i].name, strlen(hint))) {
            ++(*match_count);
            *matches = realloc(*matches, *match_count * sizeof **matches);
            (*matches)[*match_count-1] = strdup(commands[i].name);
        }
    }
}

static int
last_opt(const char *buf, const char *hint, const char *opt)
{
    do {
        --hint;
    } while (hint[0] == ' ');

    if (hint - buf < strlen(opt) - 1) {
        return 0;
    }

    hint -= strlen(opt);

    if (!strncmp(hint, opt, strlen(opt))) {
        return 1;
    }

    return 0;
}

void
complete_cmd(const char *buf, const char *hint, linenoiseCompletions *lc)
{
    char **matches = NULL;
    unsigned int match_count = 0, i;

    if (
#ifdef ENABLE_SSH
        !strncmp(buf, "auth keys add ", 14)
#endif
#if defined(ENABLE_SSH) && defined(ENABLE_TLS)
        ||
#endif
#ifdef ENABLE_TLS
        !strncmp(buf, "cert add ", 9) || !strncmp(buf, "cert remove ", 12) || !strncmp(buf, "cert replaceown ", 16)
        || !strncmp(buf, "crl add ", 8) || !strncmp(buf, "crl remove ", 11)
#endif
            ) {
        linenoisePathCompletion(buf, hint, lc);
    } else if ((!strncmp(buf, "copy-config ", 12) || !strncmp(buf, "validate ", 9)) && last_opt(buf, hint, "--src-config")) {
        linenoisePathCompletion(buf, hint, lc);
    } else if (!strncmp(buf, "edit-config ", 12) && last_opt(buf, hint, "--config")) {
        linenoisePathCompletion(buf, hint, lc);
    } else if ((!strncmp(buf, "get ", 4) || !strncmp(buf, "get-config ", 11) || !strncmp(buf, "subscribe ", 10))
            && (last_opt(buf, hint, "--filter-subtree") || last_opt(buf, hint, "--out"))) {
        linenoisePathCompletion(buf, hint, lc);
    } else if (!strncmp(buf, "get-schema ", 11) && last_opt(buf, hint, "--out")) {
        linenoisePathCompletion(buf, hint, lc);
    } else if (!strncmp(buf, "user-rpc ", 9) && last_opt(buf, hint, "--content")) {
        linenoisePathCompletion(buf, hint, lc);
    } else if (!strchr(buf, ' ') && hint[0]) {
        get_cmd_completion(hint, &matches, &match_count);

        for (i = 0; i < match_count; ++i) {
            linenoiseAddCompletion(lc, matches[i]);
            free(matches[i]);
        }
        free(matches);
    }
}

char *
readinput(const char *instruction)
{
    /* TODO */
    (void)instruction;
    return NULL;
}
