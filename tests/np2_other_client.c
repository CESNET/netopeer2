/**
 * @file np2_other_client.c
 * @author Adam Piecek <piecek@cesnet.cz>
 * @brief An alternative test interface for communicating with the NETCONF server.
 *
 * @copyright
 * Copyright (c) 2019 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "libnetconf2/netconf.h"
#include "np2_other_client.h"

#define OC_FAIL_LOG \
    fprintf(stderr, "Netconf client fail in %s:%d.\n", __FILE__, __LINE__)

/**
 * Full timeout of read or write in seconds.
 */
#define OC_TIMEOUT_SEC 60

/**
 * Microseconds after which tasks are repeated until the full timeout elapses.
 */
#define OC_TIMEOUT_STEP 100

/**
 * Check if the timeout has expired.
 */
#define OC_TIMEOUT(START_TIME) \
    (((double)(time(NULL) - START_TIME)) > OC_TIMEOUT_SEC)

/**
 * @brief Write message to socket.
 *
 * @param[in] oc_sess Client session.
 * @param[in] msg Message to send.
 * @param[in] msglen Length of @p msg.
 * @return 0 on success.
 * @return negative number on error.
 */
static int
oc_write(struct np_other_client *oc_sess, const char *msg, uint64_t msglen)
{
    uint64_t written = 0;
    int64_t cnt;
    int interrupted;

    msglen = msglen ? msglen : strlen(msg);
    do {
        cnt = write(oc_sess->unixsock, msg + written, msglen - written);
        written += cnt;
        if ((cnt < 0) && (errno == EAGAIN)) {
            cnt = 0;
        } else if ((cnt < 0) && (errno == EINTR)) {
            cnt = 0;
            interrupted = 1;
        } else if (cnt < 0) {
            fprintf(stderr, "Socket error (%s).\n", strerror(errno));
            return -1;
        }
        if ((cnt == 0) && !interrupted) {
            /* we must wait */
            usleep(OC_TIMEOUT_STEP);
        }
    } while (written < msglen);

    return 0;
}

/**
 * @brief Reallocation of internal buffer in the struct np_other_client.
 *
 * @param[in] oc_sess Client session.
 * @return 0 on success.
 * @return negative number on error.
 */
static int
oc_realloc(struct np_other_client *oc_sess)
{
    void *tmp;

    tmp = realloc(oc_sess->buf, oc_sess->bufsize * 2);
    if (!tmp) {
        fprintf(stderr, "Memory allocation error.\n");
        return -1;
    }
    oc_sess->buf = tmp;
    oc_sess->bufsize *= 2;

    return 0;
}

/**
 * @defgroup ocreadflags Flags for oc_read().
 * @{
 */
#define OC_READ_HELLO_MSG 0x1   /**< read the response to the hello message from the server */
/** @} ocreadflags */

/**
 * @brief Read message from socket.
 *
 * @param[in] oc_sess Client session.
 * @param[in] flags Option for function (@ref ocreadflags).
 * @return positive number representing number of characters written into @p oc_sess buffer.
 * @return negative number on error.
 */
static int64_t
oc_read(struct np_other_client *oc_sess, uint32_t flags)
{
    int64_t rd, rdall = 0;
    time_t tm;
    int interrupted;
    const char *endtag;

    tm = time(NULL);
    oc_sess->buf[0] = 0;

    do {
        interrupted = 0;
        rd = read(oc_sess->unixsock, oc_sess->buf + rdall, oc_sess->bufsize - rdall);
        if (rd < 0) {
            if (errno == EAGAIN) {
                /* endtag not found */
                rd = 0;
            } else if (errno == EINTR) {
                rd = 0;
                interrupted = 1;
                break;
            } else {
                fprintf(stderr, "Reading from file descriptor (%d) failed (%s).\n", oc_sess->unixsock, strerror(errno));
                return -1;
            }
        } else if (rd == 0) {
            fprintf(stderr, "Communication file descriptor (%d) unexpectedly closed.\n", oc_sess->unixsock);
            return -1;
        }
        if (rd == 0) {
            /* nothing read */
            if (!interrupted) {
                usleep(OC_TIMEOUT_STEP);
            }
            if (OC_TIMEOUT(tm)) {
                /* waiting too long */
                fprintf(stderr, "Message took too long to read\n");
                return -1;
            }
        } else {
            /* something read */
            rdall += rd;
        }

        if ((flags & OC_READ_HELLO_MSG) && (rdall > 5)) {
            /* check hello end tag, (strlen("]]>]]>") == 6) */
            endtag = (oc_sess->buf + rdall) - 6;
            if (!strncmp(endtag, "]]>]]>", 6)) {
                /* success */
                break;
            }
        } else if (rdall > 3) {
            /* check classic end tag, (strlen(\n##\n) == 4) */
            endtag = (oc_sess->buf + rdall) - 4;
            if (!strncmp(endtag, "\n##\n", 4)) {
                /* success */
                break;
            }
        }

        if ((oc_sess->bufsize - rdall) == 0) {
            if (oc_realloc(oc_sess)) {
                return -1;
            }
        }
    } while (1);

    return rdall;
}

/**
 * @brief Establish NETCONF session.
 *
 * @param[in] oc_sess Client session.
 * @return 0 on success.
 */
static int
oc_hello_handshake(struct np_other_client *oc_sess)
{
    int rc;

    const char *msg =
            "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability>"
            "<capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>";

    rc = oc_write(oc_sess, msg, 0);
    if (rc) {
        return rc;
    }

    return (oc_read(oc_sess, OC_READ_HELLO_MSG) >= 0) ? 0 : -1;
}

struct np_other_client *
oc_connect_unix(const char *address)
{
    struct sockaddr_un sun;
    struct np_other_client *oc_sess = NULL;
    int rc;

    oc_sess = calloc(1, sizeof *oc_sess);
    if (!oc_sess) {
        OC_FAIL_LOG;
        return NULL;
    }

    oc_sess->unixsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (oc_sess->unixsock < 0) {
        OC_FAIL_LOG;
        return NULL;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", address);

    if (connect(oc_sess->unixsock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        OC_FAIL_LOG;
        return NULL;
    }

    if (fcntl(oc_sess->unixsock, F_SETFL, O_NONBLOCK) < 0) {
        OC_FAIL_LOG;
        return NULL;
    }

    oc_sess->buf = malloc(2048);
    if (!oc_sess->buf) {
        return NULL;
    }
    oc_sess->bufsize = 2048;

    rc = oc_hello_handshake(oc_sess);
    if (rc) {
        return NULL;
    }

    oc_sess->msgid = 1;

    return oc_sess;
}

int
oc_send_msg(struct np_other_client *oc_sess, const char *msg)
{
    int rc;
    char *starttag = NULL;
    uint64_t msglen;

    /* increment message-id but do not increment after initial handshake */
    oc_sess->msgid = (oc_sess->msgid != 1) ? oc_sess->msgid + 1 : oc_sess->msgid;

    msglen = strlen(msg);
    asprintf(&starttag, "\n#%" PRIu64 "\n", msglen);
    if (!starttag) {
        OC_FAIL_LOG;
        return -1;
        goto cleanup;
    }

    rc = oc_write(oc_sess, starttag, 0);
    if (rc) {
        OC_FAIL_LOG;
        goto cleanup;
    }
    rc = oc_write(oc_sess, msg, msglen);
    if (rc) {
        OC_FAIL_LOG;
        goto cleanup;
    }
    rc = oc_write(oc_sess, "\n##\n", 0);
    if (rc) {
        OC_FAIL_LOG;
        goto cleanup;
    }

cleanup:
    free(starttag);
    return rc;
}

int
oc_recv_msg(struct np_other_client *oc_sess, char **msg)
{
    int64_t len;
    char *endtag;

    len = oc_read(oc_sess, 0);

    if (len < 0) {
        return -1;
    } else if (len == (int64_t)oc_sess->bufsize) {
        /* unlikely, though no space for zero character */
        if (oc_realloc(oc_sess)) {
            return -1;
        }
    }

    /* Delete end tag: \n##\n */
    endtag = (oc_sess->buf + len) - 4;
    *endtag = '\0';

    /* Skip first start tag: \n##number\n */
    *msg = strchr(oc_sess->buf + 1, '\n');
    if (**msg == '\0') {
        return -1;
    }
    *msg = *msg + 1;

    return 0;
}

void
oc_session_free(struct np_other_client *oc_sess)
{
    if (!oc_sess) {
        return;
    }
    if (oc_sess->unixsock > 0) {
        close(oc_sess->unixsock);
    }
    free(oc_sess->buf);
    free(oc_sess);
}
