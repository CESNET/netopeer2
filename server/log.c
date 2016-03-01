/**
 * @file log.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief netopeer2-server log functions
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdarg.h>
#include <syslog.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

/**
 * @brief libnetconf verbose level variable
 */
volatile uint8_t verbose_level = 0;

/**
 * @brief printer callback for libnetconf2
 */
void
print_clb_nc2(NC_VERB_LEVEL level, const char *msg)
{
    switch (level) {
    case NC_VERB_ERROR:
        syslog(LOG_ERR, msg);
        break;
    case NC_VERB_WARNING:
        syslog(LOG_WARNING, msg);
        break;
    case NC_VERB_VERBOSE:
        syslog(LOG_INFO, msg);
        break;
    case NC_VERB_DEBUG:
        syslog(LOG_DEBUG, msg);
        break;
    }
}

/**
 * @brief printer callback for libyang
 */
void
print_clb_ly(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    int facility;

    switch (level) {
    case LY_LLERR:
        facility = LOG_ERR;
        break;
    case LY_LLWRN:
        facility = LOG_WARNING;
        break;
    case LY_LLVRB:
        facility = LOG_INFO;
        break;
    case LY_LLDBG:
        facility = LOG_DEBUG;
        break;
    }

    if (path) {
        syslog(facility, "%s (%s)", msg, path);
    } else {
        syslog(facility, msg);
    }
}

void
print_clb_sr(sr_log_level_t level, const char *msg)
{
    if (verbose_level >= level - 1) {
        print_clb_nc2((NC_VERB_LEVEL)(level - 1), msg);
    }
}

/**
 * @brief internal printing function, follows the levels from libnetconf2
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void
prv_printf(NC_VERB_LEVEL level, const char *format, ...)
{
#define PRV_MSG_SIZE 4096
    char prv_msg[PRV_MSG_SIZE];
    va_list ap;

    va_start(ap, format);
    vsnprintf(prv_msg, PRV_MSG_SIZE - 1, format, ap);
    prv_msg[PRV_MSG_SIZE - 1] = '\0';
    print_clb_nc2(level, prv_msg);
    va_end(ap);

#undef PRV_MSG_SIZE
}
