/**
 * @file log.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server log functions
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <nc_server.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "config.h"

volatile uint8_t np2_verbose_level;
uint8_t np2_libssh_verbose_level;
uint8_t np2_sr_verbose_level;
uint8_t np2_stderr_log;

static void
np2log(int priority, const char *fmt, ...)
{
    char *format;
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);

    if (np2_stderr_log) {
        format = malloc(11 + strlen(fmt) + 2);
        if (!format) {
            fprintf(stderr, "ERROR: Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        switch (priority) {
        case LOG_ERR:
            sprintf(format, "[ERR]: %s\n", fmt);
            break;
        case LOG_WARNING:
            sprintf(format, "[WRN]: %s\n", fmt);
            break;
        case LOG_INFO:
            sprintf(format, "[INF]: %s\n", fmt);
            break;
        case LOG_DEBUG:
            sprintf(format, "[DBG]: %s\n", fmt);
            break;
        default:
            sprintf(format, "[UNKNOWN]: %s\n", fmt);
            break;
        }

        va_start(ap, fmt);
        vfprintf(stderr, format, ap);
        va_end(ap);

        free(format);
    }
}

/**
 * @brief printer callback for libnetconf2
 */
void
np2log_clb_nc2(NC_VERB_LEVEL level, const char *msg)
{
    int priority = LOG_ERR;

    switch (level) {
    case NC_VERB_ERROR:
        priority = LOG_ERR;;
        break;
    case NC_VERB_WARNING:
        priority = LOG_WARNING;
        break;
    case NC_VERB_VERBOSE:
        priority = LOG_INFO;
        break;
    case NC_VERB_DEBUG:
        priority = LOG_DEBUG;
        break;
    }

    np2log(priority, msg);
}

/**
 * @brief printer callback for libyang
 */
void
np2log_clb_ly(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    int priority;

    switch (level) {
    case LY_LLERR:
        priority = LOG_ERR;
        break;
    case LY_LLWRN:
        priority = LOG_WARNING;
        break;
    case LY_LLVRB:
        priority = LOG_INFO;
        break;
    case LY_LLDBG:
        priority = LOG_DEBUG;
        break;
    default:
        /* silent, just to cover enum, shouldn't be here in real world */
        return;
    }

    if (path) {
        np2log(priority, "%s (%s)", msg, path);
    } else {
        np2log(priority, msg);
    }
}

void
np2log_clb_sr(sr_log_level_t level, const char *msg)
{
    if (np2_sr_verbose_level >= level) {
        np2log_clb_nc2((NC_VERB_LEVEL)(level - 1), msg);
    }
}

/**
 * @brief Internal printing function, follows the levels from libnetconf2
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void
np2log_printf(NC_VERB_LEVEL level, const char *format, ...)
{
    va_list ap, ap2;
    ssize_t msg_len = NP2SRV_MSG_LEN_START, req_len;
    char *msg, *mem;

    if (np2_verbose_level < level) {
        return;
    }

    /* initial length */
    msg = malloc(msg_len);
    if (!msg) {
        goto cleanup;
    }

    /* learn how much bytes are needed */
    req_len = vsnprintf(msg, msg_len, format, ap);
    if (req_len == -1) {
        goto cleanup;
    } else if (req_len >= NP2SRV_MSG_LEN_START) {
        /* the intial size was not enough */
        msg_len = req_len + 1;
        mem = realloc(msg, msg_len);
        if (!mem) {
            free(msg);
            goto cleanup;
        }
        msg = mem;

        /* now print the full message */
        req_len = vsnprintf(msg, msg_len, format, ap2);
        if (req_len == -1) {
            goto cleanup;
        }
    }

    np2log_clb_nc2(level, msg);

cleanup:
    free(msg);
    va_end(ap);
    va_end(ap2);
}
