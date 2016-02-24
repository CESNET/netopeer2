/**
 * @file log.h
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

#ifndef NP2SRV_LOG_H_
#define NP2SRV_LOG_H_

#include <libyang/libyang.h>
#include <nc_server.h>

/* TODO own logging functionality */

/**
 * @brief printer callback for libnetconf2
 */
void print_clb_nc2(NC_VERB_LEVEL level, const char *msg);

/**
 * @brief printer callback for libyang
 */
void print_clb_ly(LY_LOG_LEVEL level, const char *msg, const char *path);

#endif /* NP2SRV_LOG_H_ */
