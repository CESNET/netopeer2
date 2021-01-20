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

#include "common.h"
#include "log.h"

volatile uint8_t np2_verbose_level;
uint8_t np2_libssh_verbose_level;
uint8_t np2_sr_verbose_level;
uint8_t np2_stderr_log;

static void
np2log(int priority, const char *src, const char *fmt, ...)
{
    char *format;
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);

    if (np2_stderr_log) {
        format = malloc(11 + strlen(fmt) + 2);
        if (!format) {
            fprintf(stderr, "[ERR]: Memory allocation failed (%s:%d), src: %s, fmt: %s\n", __FILE__, __LINE__, src, fmt);
            return;
        }

        switch (priority) {
        case LOG_ERR:
            sprintf(format, "[ERR]: %s: %s\n", src, fmt);
            break;
        case LOG_WARNING:
            sprintf(format, "[WRN]: %s: %s\n", src, fmt);
            break;
        case LOG_INFO:
            sprintf(format, "[INF]: %s: %s\n", src, fmt);
            break;
        case LOG_DEBUG:
            sprintf(format, "[DBG]: %s: %s\n", src, fmt);
            break;
        default:
            sprintf(format, "[UNK]: %s: %s\n", src, fmt);
            break;
        }

        va_start(ap, fmt);
        vfprintf(stderr, format, ap);
        va_end(ap);

        free(format);
    }
}

/**
 * @brief Encode message characters (% -> %%) to avoid printf arg problems.
 */
static const char *
np2log_encode(const char *msg, char **buf)
{
    const char *ptr1, *ptr2;
    size_t buf_len, buf_size = 1;
    void *mem;

    *buf = NULL;
    if ((ptr2 = strchr(msg, '%'))) {
        /* something to encode */
        ptr1 = msg;
        do {
            /* enlarge buffer */
            buf_len = buf_size - 1;
            buf_size += (ptr2 - ptr1) + 2;
            mem = realloc(*buf, buf_size * sizeof **buf);
            if (!mem) {
                EMEM;
                return "";
            }
            *buf = mem;

            /* copy preceding message */
            strncpy(*buf + buf_len, ptr1, ptr2 - ptr1);
            buf_len += ptr2 - ptr1;

            /* copy % */
            strcpy(*buf + buf_len, "%%");

            /* next iter */
            ptr1 = ptr2 + 1;
        } while ((ptr2 = strchr(ptr1, '%')));

        /* copy remaining message */
        buf_len = buf_size - 1;
        buf_size += strlen(ptr1);
        mem = realloc(*buf, buf_size * sizeof **buf);
        if (!mem) {
            EMEM;
            return "";
        }
        *buf = mem;
        strcpy(*buf + buf_len, ptr1);
    }

    return (*buf ? *buf : msg);
}

/**
 * @brief printer callback for libnetconf2
 */
void
np2log_cb_nc2(NC_VERB_LEVEL level, const char *msg)
{
    int priority = LOG_ERR;
    const char *log_msg;
    char *buf;

    if (level > np2_verbose_level) {
        return;
    }

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
    case NC_VERB_DEBUG_LOWLVL:
        priority = LOG_DEBUG;
        break;
    }

    log_msg = np2log_encode(msg, &buf);
    np2log(priority, "LN", log_msg);
    free(buf);
}

/**
 * @brief printer callback for libyang
 */
void
np2log_cb_ly(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    int priority;
    const char *log_msg;
    char *buf;

    if (level > np2_verbose_level) {
        return;
    }

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
        np2log(priority, "LY", "%s (%s)", msg, path);
    } else {
        log_msg = np2log_encode(msg, &buf);
        np2log(priority, "LY", log_msg);
        free(buf);
    }
}

void
np2log_cb_sr(sr_log_level_t level, const char *msg)
{
    int priority = LOG_ERR;
    const char *log_msg;
    char *buf;

    if (level > np2_sr_verbose_level) {
        return;
    }

    switch (level) {
    case SR_LL_ERR:
        priority = LOG_ERR;
        break;
    case SR_LL_WRN:
        priority = LOG_WARNING;
        break;
    case SR_LL_INF:
        priority = LOG_INFO;
        break;
    case SR_LL_DBG:
        priority = LOG_DEBUG;
        break;
    case SR_LL_NONE:
        return;
    }

    log_msg = np2log_encode(msg, &buf);
    np2log(priority, "SR", log_msg);
    free(buf);
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
    int priority = LOG_ERR;

    if (level > np2_verbose_level) {
        return;
    }

    va_start(ap, format);
    va_copy(ap2, ap);

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
    case NC_VERB_DEBUG_LOWLVL:
        priority = LOG_DEBUG;
        break;
    }
    /* no need to encode in this case */
    np2log(priority, "NP", msg);

cleanup:
    free(msg);
    va_end(ap);
    va_end(ap2);
}
