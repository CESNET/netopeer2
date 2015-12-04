#
# Copyright (c) 2011-2013 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, including, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.
#

NAME = netopeer2-cli
VERSION = 0.0.0
RELEASE = 1

IDGIT = "built from git $(shell git show --pretty=oneline | head -1 | cut -c -20)"
IDNOGIT = "released as version $(VERSION)"

srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
datarootdir = ${prefix}/share

CC = gcc
LIBS = -lyang -lnetconf2
CFLAGS = -Wall -g -O0 -pthread
CPPFLAGS = -DRCSID=\"$(IDGIT)\" -DENABLE_TLS -DVERSION=\"$(VERSION)\"
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

OBJDIR= .obj

SRCS =  main.c \
	commands.c \
	completion.c \
	linenoise/linenoise.c

OBJS = $(SRCS:%.c=$(OBJDIR)/%.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OBJS) $(LIBS) -o $(NAME)

$(OBJDIR)/%.o: %.c
	@[ -d $$(dirname $@) ] || \
		(mkdir -p $$(dirname $@))
	$(CC) $(CFLAGS) $(INCLUDES) $(CPPFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(NAME) .obj $(OBJS);
