/**
 * @file log.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server log functions
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_LOG_H_
#define NP2SRV_LOG_H_

#include <nc_server.h>
#include <sysrepo.h>

/**
 * @brief Verbose level variable
 */
extern volatile uint8_t np2_verbose_level;

/**
 * @brief libssh verbose level variable
 */
extern uint8_t np2_libssh_verbose_level;

/**
 * @brief libsysrepo verbose level variable
 */
extern uint8_t np2_sr_verbose_level;

/**
 * @brief netopeer2 flag whether to print messages to stderr (only if not daemon).
 */
extern uint8_t np2_stderr_log;

/**
 * @brief internal printing function, follows the levels from libnetconf2
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void np2log_printf(NC_VERB_LEVEL level, const char *format, ...);

/*
 * Verbose printing macros
 */
#define ERR(format, args ...) np2log_printf(NC_VERB_ERROR,format,##args)
#define WRN(format, args ...) np2log_printf(NC_VERB_WARNING,format,##args)
#define VRB(format, args ...) np2log_printf(NC_VERB_VERBOSE,format,##args)
#define DBG(format, args ...) np2log_printf(NC_VERB_DEBUG,format,##args)

#define EMEM ERR("Memory allocation failed (%s:%d)", __FILE__, __LINE__)
#define EINT ERR("Internal error (%s:%d)", __FILE__, __LINE__)
#define EUNLOCK(rc) ERR("Failed to unlock a lock (%s) (%s:%d)", strerror(rc), __FILE__, __LINE__)
#define ELOCK(rc) ERR("Failed to lock a lock (%s) (%s:%d)", strerror(rc), __FILE__, __LINE__)

/**
 * @brief printer callback for libnetconf2
 */
void np2log_cb_nc2(const struct nc_session *session, NC_VERB_LEVEL level, const char *msg);

/**
 * @brief printer callback for libyang
 */
void np2log_cb_ly(LY_LOG_LEVEL level, const char *msg, const char *data_path, const char *schema_path, uint64_t line);

/**
 * @brief printer callback for sysrepo
 */
void np2log_cb_sr(sr_log_level_t level, const char *msg);

#endif /* NP2SRV_LOG_H_ */
