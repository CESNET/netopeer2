/**
 * @file completion.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli auto completion
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include <nc_client.h>

#ifndef HAVE_EACCESS
#define eaccess access
#endif

#include "commands.h"
#include "linenoise/linenoise.h"

extern struct ly_ctx *ctx;
extern char *config_editor;

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

    if ((unsigned)(hint - buf) < strlen(opt) - 1) {
        return 0;
    }

    hint -= strlen(opt) - 1;

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

    if (!strncmp(buf, "searchpath ", 11)
#ifdef NC_ENABLED_SSH
        || !strncmp(buf, "auth keys add ", 14)
#endif
#ifdef NC_ENABLED_TLS
        || !strncmp(buf, "cert add ", 9) || !strncmp(buf, "cert remove ", 12) || !strncmp(buf, "cert replaceown ", 16)
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
readinput(const char *instruction, const char *old_tmp, char **new_tmp)
{
    int tmpfd = -1, ret, size, oldfd;
    pid_t pid, wait_pid;
    char* tmpname = NULL, *input = NULL, *old_content = NULL, *ptr, *ptr2;

    /* Create a unique temporary file */
#ifdef HAVE_MKSTEMPS
    if (asprintf(&tmpname, "/tmp/tmpXXXXXX.xml") == -1) {
        ERROR(__func__, "asprintf() failed (%s).", strerror(errno));
        goto fail;
    }
    tmpfd = mkstemps(tmpname, 4);
    if (tmpfd == -1) {
        ERROR(__func__, "Failed to create a temporary file (%s).", strerror(errno));
        goto fail;
    }
#else
    if (asprintf(&tmpname, "/tmp/tmpXXXXXX") == -1) {
        ERROR(__func__, "asprintf() failed (%s).", strerror(errno));
        goto fail;
    }
    /* cannot fail */
    mktemp(tmpname);
    if (asprintf(&tmpname, ".xml") == -1) {
        ERROR(__func__, "asprintf() failed (%s).", strerror(errno));
        goto fail;
    }
    tmpfd = open(tmpname, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (tmpfd == -1) {
        ERROR(__func__, "Failed to create a temporary file (%s).", strerror(errno));
        goto fail;
    }
#endif /* #ifdef HAVE_MKSTEMPS */

    /* Read the old content, if any */
    if (old_tmp != NULL) {
        oldfd = open(old_tmp, O_RDONLY);
        if (oldfd != -1) {
            size = lseek(oldfd, 0, SEEK_END);
            lseek(oldfd, 0, SEEK_SET);
            if (size > 0) {
                old_content = malloc(size+1);
                ret = read(oldfd, old_content, size);
                if (ret != size) {
                    free(old_content);
                    old_content = NULL;
                } else {
                    old_content[size] = '\0';
                }
            }
            close(oldfd);
        }
    }


    if (old_content) {
        ret = write(tmpfd, old_content, strlen(old_content));
        if ((unsigned)ret < strlen(old_content)) {
            ERROR(__func__, "Failed to write the previous content (%s).", strerror(errno));
            goto fail;
        }

    } else if (instruction) {
        ret = write(tmpfd, "\n<!--#\n", 7);
        ret += write(tmpfd, instruction, strlen(instruction));
        ret += write(tmpfd, "\n-->\n", 5);
        if ((unsigned)ret < 6+strlen(instruction)+5) {
            ERROR(__func__, "Failed to write the instruction (%s).", strerror(errno));
            goto fail;
        }

        ret = lseek(tmpfd, 0, SEEK_SET);
        if (ret == -1) {
            ERROR(__func__, "Rewinding the temporary file failed (%s).", strerror(errno));
            goto fail;
        }
    }

    if ((pid = vfork()) == -1) {
        ERROR(__func__, "Fork failed (%s).", strerror(errno));
        goto fail;
    } else if (pid == 0) {
        /* child */
        execlp(config_editor, config_editor, tmpname, (char *)NULL);

        ERROR(__func__, "Exec failed (%s).", strerror(errno));
        exit(1);
    } else {
        /* parent */
        wait_pid = wait(&ret);
        if (wait_pid != pid) {
            ERROR(__func__, "Child process other than the editor exited, weird.");
            goto fail;
        }
        if (!WIFEXITED(ret)) {
            ERROR(__func__, "Editor exited in a non-standard way.");
            goto fail;
        }
    }

    /* Get the size of the input */
    size = lseek(tmpfd, 0, SEEK_END);
    if (size == -1) {
        ERROR(__func__, "Failed to get the size of the temporary file (%s).", strerror(errno));
        goto fail;
    } else if (size == 0) {
        /* not a fail, just no input */
        goto fail;
    }
    lseek(tmpfd, 0, SEEK_SET);

    /* Read the input */
    input = malloc(size+1);
    ret = read(tmpfd, input, size);
    if (ret < size) {
        ERROR(__func__, "Failed to read from the temporary file (%s).", strerror(errno));
        goto fail;
    }
    input[size] = '\0';

    /* Remove the instruction comment */
    if (!old_content && instruction) {
        ptr = strstr(input, "\n<!--#\n");
        if (!ptr) {
            goto cleanup;
        }
        ptr2 = strstr(ptr, "\n-->\n");
        /* The user could have deleted or modified the comment, ignore it then */
        if (ptr2) {
            ptr2 += 5;
            memmove(ptr, ptr2, strlen(ptr2)+1);

            /* Save the modified content */
            if (ftruncate(tmpfd, 0) == -1) {
                ERROR(__func__, "Failed to truncate the temporary file (%s).", strerror(errno));
                goto fail;
            }
            lseek(tmpfd, 0, SEEK_SET);
            ret = write(tmpfd, input, strlen(input));
            if ((unsigned)ret < strlen(input)) {
                ERROR(__func__, "Failed to write to the temporary file (%s).", strerror(errno));
                goto fail;
            }
        }
    }

    if (new_tmp) {
        *new_tmp = tmpname;
    } else {
        unlink(tmpname);
        free(tmpname);
    }

cleanup:

    close(tmpfd);
    free(old_content);

    return input;

fail:
    if (tmpfd > -1) {
        close(tmpfd);
    }
    if (tmpname != NULL) {
        unlink(tmpname);
    }
    free(tmpname);
    free(old_content);
    free(input);

    return NULL;
}
