/**
 * @file commands.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli commands header
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

#ifndef COMMANDS_H_
#define COMMANDS_H_

#include "version.h"

char some_msg[4096];
#define INSTRUCTION(format,args...) {snprintf(some_msg,4095,format,##args);printf("\n  %s",some_msg);}
#define ERROR(function,format,args...) {snprintf(some_msg,4095,format,##args);fprintf(stderr,"%s: %s\n",function,some_msg);}

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

#include <stdlib.h>

#define PROMPT "> "

typedef struct {
    char *name; /* User printable name of the function. */
    int (*func)(const char *, char **); /* Function to call to do the command. */
    void (*help_func)(void); /* Display command help. */
    char *helpstring; /* Documentation for this function. */
} COMMAND;

extern COMMAND commands[];

void set_hist_file(int hist_idx, char *file);

void free_hist_file(void);

#endif /* COMMANDS_H_ */
