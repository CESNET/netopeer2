/**
 * @file log.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief netopeer2-server log functions
 *
 * Copyright (c) 2016 - 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _DEFAULT_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

volatile uint8_t np2_verbose_level;
uint8_t np2_libssh_verbose_level;
uint8_t np2_sr_verbose_level;
uint8_t np2_stderr_log;

enum ERR_SOURCE {
    ERRS_NETOPEER,
    ERRS_LIBYANG,
    ERRS_LIBNETCONF2,
    ERRS_SYSREPO,
    ERRS_DONOTREPLACE
};
#define NP2ERR_MSG_SIZE 1024
struct np2err {
    enum ERR_SOURCE source;
    char msg[NP2ERR_MSG_SIZE];
};
struct np2err np2_err_main = {ERRS_NETOPEER, {0}};
static pthread_once_t np2_err_once = PTHREAD_ONCE_INIT;
static pthread_key_t np2_err_key;

static void
np2_err_free(void *ptr)
{
#ifdef __linux__
    /* in __linux__ we use static memory in the main thread,
     * so this check is for programs terminating the main()
     * function by pthread_exit() :)
     */
    if (ptr != &np2_err_main) {
#else
    {
#endif
        free(ptr);
    }
}

static void
np2_err_createkey(void)
{
    int r;

    /* initiate */
    while ((r = pthread_key_create(&np2_err_key, np2_err_free)) == EAGAIN);
    pthread_setspecific(np2_err_key, NULL);
}

struct np2err *
np2_err_location(void)
{
    struct np2err *e;

    pthread_once(&np2_err_once, np2_err_createkey);
    e = pthread_getspecific(np2_err_key);
    if (!e) {
        /* prepare ly_err storage */
#ifdef __linux__
        if (getpid() == syscall(SYS_gettid)) {
            /* main thread - use global variable instead of thread-specific variable. */
            e = &np2_err_main;
        } else {
#else
            {
#endif /* __linux__ */
            e = calloc(1, sizeof *e);
        }
        pthread_setspecific(np2_err_key, e);
    }

    return e;
}

static void
np2log(int priority, const char *fmt, ...)
{
    char *format;
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);

    if (np2_stderr_log) {
        format = malloc(9 + strlen(fmt) + 2);
        if (!format) {
            fprintf(stderr, "ERROR: Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        switch (priority) {
        case LOG_ERR:
            sprintf(format, "ERROR: %s\n", fmt);
            break;
        case LOG_WARNING:
            sprintf(format, "WARNING: %s\n", fmt);
            break;
        case LOG_INFO:
            sprintf(format, "VERBOSE: %s\n", fmt);
            break;
        case LOG_DEBUG:
            sprintf(format, "DEBUG: %s\n", fmt);
            break;
        default:
            sprintf(format, "UNKNOWN: %s\n", fmt);
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
    struct np2err *e;
    int priority;

    if (level == NC_VERB_ERROR) {
        e = np2_err_location();
        if (e && e->source != ERRS_DONOTREPLACE) {
            e->source = ERRS_LIBNETCONF2;
            strncpy(e->msg, msg, NP2ERR_MSG_SIZE - 1);
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
    struct np2err *e;

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

    if (level == LY_LLERR) {
        e = np2_err_location();
        if (e) {
            e->source = ERRS_LIBYANG;
        }
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
    struct np2err *e = NULL;

    if (np2_sr_verbose_level >= level) {

        if (level == SR_LL_ERR) {
            e = np2_err_location();
            if (e) {
                e->source = ERRS_DONOTREPLACE;
                strncpy(e->msg, msg, NP2ERR_MSG_SIZE - 1);
            }
        }

        np2log_clb_nc2((NC_VERB_LEVEL)(level - 1), msg);

        if (e) {
            e->source = ERRS_SYSREPO;
        }
    }
}

/**
 * @brief internal printing function, follows the levels from libnetconf2
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void
np2log_printf(NC_VERB_LEVEL level, const char *format, ...)
{
    va_list ap;
    char prv_msg[NP2ERR_MSG_SIZE];
    char *msg = prv_msg;
    struct np2err *e = NULL;

    if (level == NC_VERB_ERROR) {
        e = np2_err_location();
        if (e) {
            e->source = ERRS_DONOTREPLACE;
            msg = e->msg;
        }
    }

    va_start(ap, format);
    vsnprintf(msg, NP2ERR_MSG_SIZE - 1, format, ap);
    msg[NP2ERR_MSG_SIZE - 1] = '\0';
    np2log_clb_nc2(level, msg);
    va_end(ap);

    if (e) {
        e->source = ERRS_NETOPEER;
    }
}

const char *
np2log_lasterr(struct ly_ctx *ctx)
{
    struct np2err *e;

    e = np2_err_location();
    if (!e) {
        return NULL;
    }

    if (e->source == ERRS_LIBYANG) {
        return ly_errmsg(ctx);
    } else {
        return e->msg;
    }
}
