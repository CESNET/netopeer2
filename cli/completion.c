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

/* can end with multiple paths if !long_opt, otherwise it must end with that option and some partial path */
static void
get_path_completion(const char *hint, const char *long_opt, char ***matches, unsigned int *match_count)
{
    const char *ptr, *path, *opt;
    DIR *dir;
    struct dirent *ent;

    *match_count = 0;
    *matches = NULL;

    ptr = strrchr(hint, ' ') + 1;

    /* check long_opt */
    if (long_opt) {
        opt = ptr - 1;
        while (opt[0] == ' ') {
            --opt;
        }

        /* is the word long enough? */
        if ((opt - hint) + 1 < strlen(long_opt)) {
            return;
        }

        /* not the option we want */
        if (strncmp(opt - (strlen(long_opt) - 1), long_opt, strlen(long_opt))) {
            return;
        }
    }

    path = ptr;
    ptr = strrchr(path, '/');

    /* new relative path */
    if (ptr == NULL) {
        ptr = path;
        dir = opendir(".");
    } else {
        char buf[FILENAME_MAX];

        ++ptr;
        sprintf(buf, "%.*s", (int)(ptr - path), path);

        dir = opendir(buf);
    }

    if (dir == NULL) {
        return;
    }

    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.') {
            continue;
        }

        /* some serious pointer fun */
        if (!strncmp(ptr, ent->d_name, strlen(ptr))) {
            ++(*match_count);
            *matches = realloc(*matches, *match_count * sizeof **matches);
            //asprintf(&(*matches)[*match_count-1], "%.*s%s", (int)(ptr-hint), hint, ent->d_name);
            (*matches)[*match_count-1] = malloc((ptr-hint)+strlen(ent->d_name)+1);
            strncpy((*matches)[*match_count-1], hint, ptr-hint);
            strcpy((*matches)[*match_count-1]+(ptr-hint), ent->d_name);
        }
    }

    closedir(dir);
}

void
complete_cmd(const char *buf, linenoiseCompletions *lc)
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
        get_path_completion(buf, NULL, &matches, &match_count);
    } else if (!strncmp(buf, "copy-config ", 12)) {
        get_path_completion(buf, "--src-config", &matches, &match_count);
    } else if (!strncmp(buf, "edit-config ", 12)) {
        get_path_completion(buf, "--config", &matches, &match_count);
    } else if (!strncmp(buf, "get ", 4) || !strncmp(buf, "get-config ", 11)) {
        get_path_completion(buf, "--filter-subtree", &matches, &match_count);
        if (!match_count) {
            get_path_completion(buf, "--out", &matches, &match_count);
        }
    } else {
        get_cmd_completion(buf, &matches, &match_count);
    }

    for (i = 0; i < match_count; ++i) {
        linenoiseAddCompletion(lc, matches[i]);
        free(matches[i]);
    }
    free(matches);
}

char *
readinput(const char *instruction)
{
    /* TODO */
    (void)instruction;
    return NULL;
}
