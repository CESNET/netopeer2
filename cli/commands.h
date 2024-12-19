/**
 * @file commands.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli commands header
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef COMMANDS_H_
#define COMMANDS_H_

#include "cli_config.h"

#include <stdio.h>

extern char some_msg[];
#define INSTRUCTION(format, args ...) {snprintf(some_msg,4095,format,##args);printf("\n  %s",some_msg);}
#define ERROR(function, format, args ...) {snprintf(some_msg,4095,format,##args);fprintf(stderr,"%s: %s\n",function,some_msg);}

typedef struct {
    char *name; /* User printable name of the function. */

    int (*func)(const char *, char **); /* Function to call to do the command. */
    void (*help_func)(void); /* Display command help. */
    char *helpstring; /* Documentation for this function. */
} COMMAND;

extern COMMAND commands[];

#endif /* COMMANDS_H_ */
