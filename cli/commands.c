/**
 * @file commands.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli commands
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

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#ifdef NC_ENABLED_TLS
#   include <openssl/pem.h>
#   include <openssl/x509v3.h>
#endif

#ifndef HAVE_EACCESS
#define eaccess access
#endif

#include "commands.h"
#include "compat.h"
#include "completion.h"
#include "configuration.h"

#define CLI_CH_TIMEOUT 60 /* 1 minute */
#define CLI_RPC_REPLY_TIMEOUT 5 /* 5 seconds */

#define NC_CAP_WRITABLERUNNING_ID "urn:ietf:params:netconf:capability:writable-running"
#define NC_CAP_CANDIDATE_ID       "urn:ietf:params:netconf:capability:candidate"
#define NC_CAP_CONFIRMEDCOMMIT_ID "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
#define NC_CAP_ROLLBACK_ID        "urn:ietf:params:netconf:capability:rollback-on-error"
#define NC_CAP_VALIDATE10_ID      "urn:ietf:params:netconf:capability:validate:1.0"
#define NC_CAP_VALIDATE11_ID      "urn:ietf:params:netconf:capability:validate:1.1"
#define NC_CAP_STARTUP_ID         "urn:ietf:params:netconf:capability:startup"
#define NC_CAP_URL_ID             "urn:ietf:params:netconf:capability:url"
#define NC_CAP_XPATH_ID           "urn:ietf:params:netconf:capability:xpath"
#define NC_CAP_WITHDEFAULTS_ID    "urn:ietf:params:netconf:capability:with-defaults"
#define NC_CAP_NOTIFICATION_ID    "urn:ietf:params:netconf:capability:notification"
#define NC_CAP_INTERLEAVE_ID      "urn:ietf:params:netconf:capability:interleave"

char some_msg[4096];

COMMAND commands[];
extern int done;
LYD_FORMAT output_format = LYD_XML;
uint32_t output_flag;
char *config_editor;
struct nc_session *session;
volatile int interleave;
int timed;

static int cmd_disconnect(const char *arg, char **tmp_config_file);

struct arglist {
    char **list;
    int count;
    int size;
};

static void
init_arglist(struct arglist *args)
{
    if (args != NULL) {
        args->list = NULL;
        args->count = 0;
        args->size = 0;
    }
}

static void
clear_arglist(struct arglist *args)
{
    int i = 0;

    if (args && args->list) {
        for (i = 0; i < args->count; i++) {
            if (args->list[i]) {
                free(args->list[i]);
            }
        }
        free(args->list);
    }

    init_arglist(args);
}

static int
addargs(struct arglist *args, char *format, ...)
{
    va_list arguments;
    char *aux = NULL, *aux1 = NULL, *prev_aux, quot;
    int spaces;

    if (args == NULL) {
        return EXIT_FAILURE;
    }

    /* store arguments to aux string */
    va_start(arguments, format);
    if (vasprintf(&aux, format, arguments) == -1) {
        va_end(arguments);
        ERROR(__func__, "vasprintf() failed (%s)", strerror(errno));
        return EXIT_FAILURE;
    }
    va_end(arguments);

    /* remember the begining of the aux string to free it after operations */
    aux1 = aux;

    /*
     * get word by word from given string and store words separately into
     * the arglist
     */
    prev_aux = NULL;
    quot = 0;
    for (aux = strtok(aux, " \n\t"); aux; prev_aux = aux, aux = strtok(NULL, " \n\t")) {
        if (!strcmp(aux, "")) {
            continue;
        }

        if (!args->list) { /* initial memory allocation */
            if ((args->list = (char **)malloc(8 * sizeof(char *))) == NULL) {
                ERROR(__func__, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return EXIT_FAILURE;
            }
            args->size = 8;
            args->count = 0;
        } else if (!quot && (args->count + 2 >= args->size)) {
            /*
             * list is too short to add next to word so we have to
             * extend it
             */
            args->size += 8;
            args->list = realloc(args->list, args->size * sizeof(char *));
        }

        if (!quot) {
            /* add word at the end of the list */
            if ((args->list[args->count] = malloc((strlen(aux) + 1) * sizeof(char))) == NULL) {
                ERROR(__func__, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return EXIT_FAILURE;
            }

            /* quoted argument */
            if ((aux[0] == '\'') || (aux[0] == '\"')) {
                quot = aux[0];
                ++aux;
                /* ...but without spaces */
                if (aux[strlen(aux) - 1] == quot) {
                    quot = 0;
                    aux[strlen(aux) - 1] = '\0';
                }
            }

            strcpy(args->list[args->count], aux);
            args->list[++args->count] = NULL; /* last argument */
        } else {
            /* append another part of the argument */
            spaces = aux - (prev_aux + strlen(prev_aux));
            args->list[args->count - 1] = realloc(args->list[args->count - 1],
                    strlen(args->list[args->count - 1]) + spaces + strlen(aux) + 1);

            /* end of quoted argument */
            if (aux[strlen(aux) - 1] == quot) {
                quot = 0;
                aux[strlen(aux) - 1] = '\0';
            }

            sprintf(args->list[args->count - 1] + strlen(args->list[args->count - 1]), "%*s%s", spaces, " ", aux);
        }
    }

    /* clean up */
    free(aux1);

    return EXIT_SUCCESS;
}

static void
cli_ntf_free_data(void *user_data)
{
    FILE *output = user_data;

    if (output != stdout) {
        fclose(output);
    }
}

static void
cli_ntf_clb(struct nc_session *UNUSED(session), const struct lyd_node *envp, const struct lyd_node *op, void *user_data)
{
    FILE *output = user_data;
    int was_rawmode = 0;
    const struct lyd_node *top;

    if (output == stdout) {
        if (lss.rawmode) {
            was_rawmode = 1;
            linenoiseDisableRawMode(lss.ifd);
            printf("\n");
        } else {
            was_rawmode = 0;
        }
    }

    for (top = op; top->parent; top = lyd_parent(top)) {}

    fprintf(output, "notification (%s)\n", ((struct lyd_node_opaq *)lyd_child(envp))->value);
    lyd_print_file(output, top, output_format, LYD_PRINT_WITHSIBLINGS | output_flag);
    fprintf(output, "\n");
    fflush(output);

    if ((output == stdout) && was_rawmode) {
        linenoiseEnableRawMode(lss.ifd);
        linenoiseRefreshLine();
    }

    if (!strcmp(op->schema->name, "notificationComplete") && !strcmp(op->schema->module->name, "nc-notifications")) {
        interleave = 1;
    }
}

static int
cli_gettimespec(struct timespec *ts, int *mono)
{
    errno = 0;

#ifdef CLOCK_MONOTONIC_RAW
    *mono = 1;
    return clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#elif defined (CLOCK_MONOTONIC)
    *mono = 1;
    return clock_gettime(CLOCK_MONOTONIC, ts);
#elif defined (CLOCK_REALTIME)
    /* no monotonic clock available, return realtime */
    *mono = 0;
    return clock_gettime(CLOCK_REALTIME, ts);
#else
    *mono = 0;

    int rc;
    struct timeval tv;

    rc = gettimeofday(&tv, NULL);
    if (!rc) {
        ts->tv_sec = (time_t)tv.tv_sec;
        ts->tv_nsec = 1000L * (long)tv.tv_usec;
    }
    return rc;
#endif
}

/* returns milliseconds */
static int32_t
cli_difftimespec(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts2->tv_sec) - ((int64_t)ts1->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts2->tv_nsec) - ((int64_t)ts1->tv_nsec);

    return nsec_diff ? nsec_diff / 1000000L : 0;
}

static int
cli_send_recv(struct nc_rpc *rpc, FILE *output, NC_WD_MODE wd_mode, int timeout_s)
{
    char *model_data;
    int ret = 0, mono;
    int32_t msec;
    uint32_t ly_wd;
    uint64_t msgid;
    struct lyd_node *envp, *op, *err, *node, *info;
    struct lyd_node_any *any;
    NC_MSG_TYPE msgtype;
    struct timespec ts_start, ts_stop;

    if (timed) {
        ret = cli_gettimespec(&ts_start, &mono);
        if (ret) {
            ERROR(__func__, "Getting current time failed (%s).", strerror(errno));
            return ret;
        }
    }

    msgtype = nc_send_rpc(session, rpc, 1000, &msgid);
    if (msgtype == NC_MSG_ERROR) {
        ERROR(__func__, "Failed to send the RPC.");
        if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
            cmd_disconnect(NULL, NULL);
        }
        return -1;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        ERROR(__func__, "Timeout for sending the RPC expired.");
        return -1;
    }

recv_reply:
    msgtype = nc_recv_reply(session, rpc, msgid, timeout_s * 1000, &envp, &op);
    if (msgtype == NC_MSG_ERROR) {
        ERROR(__func__, "Failed to receive a reply.");
        if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
            cmd_disconnect(NULL, NULL);
        }
        return -1;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        ERROR(__func__, "Timeout for receiving a reply expired.");
        return -1;
    } else if (msgtype == NC_MSG_NOTIF) {
        /* read again */
        goto recv_reply;
    } else if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        /* unexpected message, try reading again to get the correct reply */
        ERROR(__func__, "Unexpected reply received - ignoring and waiting for the correct reply.");
        lyd_free_tree(envp);
        lyd_free_tree(op);
        goto recv_reply;
    }

    if (timed) {
        ret = cli_gettimespec(&ts_stop, &mono);
        if (ret) {
            ERROR(__func__, "Getting current time failed (%s).", strerror(errno));
            goto cleanup;
        }
    }

    if (op) {
        /* data reply */
        if (nc_rpc_get_type(rpc) == NC_RPC_GETSCHEMA) {
            /* special case */
            if (!lyd_child(op) || (lyd_child(op)->schema->nodetype != LYS_ANYXML)) {
                ERROR(__func__, "Unexpected data reply to <get-schema> RPC.");
                ret = -1;
                goto cleanup;
            }
            if (output == stdout) {
                fprintf(output, "MODULE\n");
            }
            any = (struct lyd_node_any *)lyd_child(op);
            switch (any->value_type) {
            case LYD_ANYDATA_STRING:
            case LYD_ANYDATA_XML:
                fputs(any->value.str, output);
                break;
            case LYD_ANYDATA_DATATREE:
                lyd_print_mem(&model_data, any->value.tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
                fputs(model_data, output);
                free(model_data);
                break;
            default:
                /* none of the others can appear here */
                ERROR(__func__, "Unexpected anydata value format.");
                ret = -1;
                goto cleanup;
            }

            if (output == stdout) {
                fprintf(output, "\n");
            }
        } else {
            /* generic data */
            if (output == stdout) {
                fprintf(output, "DATA\n");
            }

            switch (wd_mode) {
            case NC_WD_ALL:
                ly_wd = LYD_PRINT_WD_ALL;
                break;
            case NC_WD_ALL_TAG:
                ly_wd = LYD_PRINT_WD_ALL_TAG;
                break;
            case NC_WD_TRIM:
                ly_wd = LYD_PRINT_WD_TRIM;
                break;
            case NC_WD_EXPLICIT:
                ly_wd = LYD_PRINT_WD_EXPLICIT;
                break;
            default:
                ly_wd = 0;
                break;
            }

            lyd_print_file(output, lyd_child(op), output_format, LYD_PRINT_WITHSIBLINGS | ly_wd | output_flag);
            if (output == stdout) {
                fprintf(output, "\n");
            }
        }
    } else if (!strcmp(LYD_NAME(lyd_child(envp)), "ok")) {
        /* ok reply */
        fprintf(output, "OK\n");
    } else {
        assert(!strcmp(LYD_NAME(lyd_child(envp)), "rpc-error"));

        fprintf(output, "ERROR\n");
        LY_LIST_FOR(lyd_child(envp), err) {
            lyd_find_sibling_opaq_next(lyd_child(err), "error-type", &node);
            if (node) {
                fprintf(output, "\ttype:     %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-tag", &node);
            if (node) {
                fprintf(output, "\ttag:      %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-severity", &node);
            if (node) {
                fprintf(output, "\tseverity: %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-app-tag", &node);
            if (node) {
                fprintf(output, "\tapp-tag:  %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-path", &node);
            if (node) {
                fprintf(output, "\tpath:     %s\n", ((struct lyd_node_opaq *)node)->value);
            }
            lyd_find_sibling_opaq_next(lyd_child(err), "error-message", &node);
            if (node) {
                fprintf(output, "\tmessage:  %s\n", ((struct lyd_node_opaq *)node)->value);
            }

            info = lyd_child(err);
            while (!lyd_find_sibling_opaq_next(info, "error-info", &info)) {
                fprintf(output, "\tinfo:\n");
                lyd_print_file(stdout, lyd_child(info), LYD_XML, LYD_PRINT_WITHSIBLINGS);

                info = info->next;
            }
            fprintf(output, "\n");
        }
        ret = 1;
    }

    if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        ERROR(__func__, "Trying to receive another message...\n");
        lyd_free_tree(envp);
        lyd_free_tree(op);
        goto recv_reply;
    }

    if (timed) {
        msec = cli_difftimespec(&ts_start, &ts_stop);
        fprintf(output, "%s %2dm%d.%03ds\n", mono ? "mono" : "real", msec / 60000, (msec % 60000) / 1000, msec % 1000);
    }

cleanup:
    lyd_free_tree(envp);
    lyd_free_tree(op);
    return ret;
}

static char *
trim_top_elem(char *data, const char *top_elem, const char *top_elem_ns)
{
    char *ptr, *prefix = NULL, *buf;
    int pref_len = 0, state = 0, quote, rc;

    /* state: -2 - syntax error,
     *        -1 - top_elem not found,
     *        0 - start,
     *        1 - parsing prefix,
     *        2 - prefix just parsed,
     *        3 - top-elem found and parsed, looking for namespace,
     *        4 - top_elem and top_elem_ns found (success)
     */

    if (!data) {
        return NULL;
    }

    while (isspace(data[0])) {
        ++data;
    }

    if (data[0] != '<') {
        return data;
    }

    for (ptr = data + 1; (ptr[0] != '\0') && (ptr[0] != '>'); ++ptr) {
        switch (state) {
        case 0:
            if (!strncmp(ptr, top_elem, strlen(top_elem))) {
                state = 3;
                ptr += strlen(top_elem);
            } else if ((ptr[0] != ':') && !isdigit(ptr[0])) {
                state = 1;
                prefix = ptr;
                pref_len = 1;
            } else {
                state = -1;
            }
            break;
        case 1:
            if (ptr[0] == ':') {
                /* prefix parsed */
                state = 2;
            } else if (ptr[0] != ' ') {
                ++pref_len;
            } else {
                state = -1;
            }
            break;
        case 2:
            if (!strncmp(ptr, top_elem, strlen(top_elem))) {
                state = 3;
                ptr += strlen(top_elem);
            } else {
                state = -1;
            }
            break;
        case 3:
            if (!strncmp(ptr, "xmlns", 5)) {
                ptr += 5;
                if (prefix) {
                    if ((ptr[0] != ':') || strncmp(ptr + 1, prefix, pref_len) || (ptr[1 + pref_len] != '=')) {
                        /* it's not the right prefix, look further */
                        break;
                    }
                    /* we found our prefix, does the namespace match? */
                    ptr += 1 + pref_len;
                }

                if (ptr[0] != '=') {
                    if (prefix) {
                        /* fail for sure */
                        state = -1;
                    } else {
                        /* it may not be xmlns attribute, but something longer... */
                    }
                    break;
                }
                ++ptr;

                if ((ptr[0] != '\"') && (ptr[0] != '\'')) {
                    state = -2;
                    break;
                }
                quote = ptr[0];
                ++ptr;

                if (strncmp(ptr, top_elem_ns, strlen(top_elem_ns))) {
                    if (prefix) {
                        state = -1;
                    }
                    break;
                }
                ptr += strlen(top_elem_ns);

                if (ptr[0] != quote) {
                    if (prefix) {
                        state = -1;
                    }
                    break;
                }

                /* success */
                ptr = strchrnul(ptr, '>');
                state = 4;
            }
            break;
        }

        if ((state < 0) || (state == 4)) {
            break;
        }
    }

    if ((state == -2) || (ptr[0] == '\0')) {
        return NULL;
    } else if (state != 4) {
        return data;
    }

    /* skip the first elem, ... */
    ++ptr;
    while (isspace(ptr[0])) {
        ++ptr;
    }
    data = ptr;

    /* ... but also its ending tag */
    if (prefix) {
        rc = asprintf(&buf, "</%.*s:%s>", pref_len, prefix, top_elem);
    } else {
        rc = asprintf(&buf, "</%s>", top_elem);
    }
    if (rc == -1) {
        return NULL;
    }

    ptr = strstr(data, buf);

    if (!ptr) {
        /* syntax error */
        free(buf);
        return NULL;
    } else {
        /* reuse it */
        prefix = ptr;
    }
    ptr += strlen(buf);
    free(buf);

    while (isspace(ptr[0])) {
        ++ptr;
    }
    if (ptr[0] != '\0') {
        /* there should be nothing more */
        return NULL;
    }

    /* ending tag and all syntax seems fine, so cut off the ending tag */
    while (isspace(prefix[-1]) && (prefix > data)) {
        --prefix;
    }
    prefix[0] = '\0';

    return data;
}

static void
cmd_searchpath_help(void)
{
    printf("searchpath [<model-dir-path>]\n");
}

static void
cmd_outputformat_help(void)
{
    printf("outputformat (xml | xml_noformat | json | json_noformat)\n");
}

static void
cmd_verb_help(void)
{
    printf("verb (error/0 | warning/1 | verbose/2 | debug/3)\n");
}

static void
cmd_connect_help(void)
{
#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)
    printf("connect [--help] [--ssh] [--host <hostname>] [--port <num>] [--login <username>]\n");
    printf("connect [--help] --tls [--host <hostname>] [--port <num>] [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#elif defined (NC_ENABLED_SSH)
    printf("connect [--help] [--ssh] [--host <hostname>] [--port <num>] [--login <username>]\n");
#elif defined (NC_ENABLED_TLS)
    printf("connect [--help] [--tls] [--host <hostname>] [--port <num>] [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#endif
    printf("connect [--help] --unix [--socket <path>]\n");
}

static void
cmd_listen_help(void)
{
#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)
    printf("listen [--help] [--timeout <sec>] [--host <ip-address>] [--port <num>]\n");
    printf("   SSH [--ssh] [--login <username>]\n");
    printf("   TLS  --tls  [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>] [--peername <server-hostname>]\n");
#elif defined (NC_ENABLED_SSH)
    printf("listen [--help] [--ssh] [--timeout <sec>] [--host <hostname>] [--port <num>] [--login <username>]\n");
#elif defined (NC_ENABLED_TLS)
    printf("listen [--help] [--tls] [--timeout <sec>] [--host <hostname>] [--port <num>]"
            " [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>] [--peername <server-hostname>]\n");
#endif
}

static void
cmd_editor_help(void)
{
    printf("editor [--help] [<path/name-of-the-editor>]\n");
}

static void
cmd_cancelcommit_help(void)
{
    if (session && !nc_session_cpblt(session, NC_CAP_CONFIRMEDCOMMIT_ID)) {
        printf("cancel-commit is not supported by the current session.\n");
    } else {
        printf("cancel-commit [--help] [--persist-id <commit-id>] [--rpc-timeout <seconds>]\n");
    }
}

static void
cmd_commit_help(void)
{
    const char *confirmed;

    if (session && !nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        printf("commit is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_CONFIRMEDCOMMIT_ID)) {
        confirmed = " [--confirmed] [--confirm-timeout <sec>] [--persist <new-commit-id>] [--persist-id <commit-id>]";
    } else {
        confirmed = "";
    }
    printf("commit [--help]%s [--rpc-timeout <seconds>]\n", confirmed);
}

static void
cmd_copyconfig_help(void)
{
    int ds = 0;
    const char *running, *startup, *candidate, *url, *defaults;

    if (!session) {
        /* if session not established, print complete help for all capabilities */
        running = "running";
        startup = "|startup";
        candidate = "|candidate";
        url = "|url:<url>";
        defaults = " [--defaults report-all|report-all-tagged|trim|explicit]";
    } else {
        if (nc_session_cpblt(session, NC_CAP_WRITABLERUNNING_ID)) {
            running = "running";
            ds = 1;
        } else {
            running = "";
        }
        if (nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
            if (ds) {
                startup = "|startup";
            } else {
                startup = "startup";
                ds = 1;
            }
        } else {
            startup = "";
        }
        if (nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
            if (ds) {
                candidate = "|candidate";
            } else {
                candidate = "candidate";
                ds = 1;
            }
        } else {
            candidate = "";
        }
        if (nc_session_cpblt(session, NC_CAP_URL_ID)) {
            if (ds) {
                url = "|url:<url>";
            } else {
                url = "url:<url>";
                ds = 1;
            }
        } else {
            url = "";
        }

        if (!ds) {
            printf("copy-config is not supported by the current session.\n");
            return;
        }

        if (nc_session_cpblt(session, NC_CAP_WITHDEFAULTS_ID)) {
            defaults = " [--defaults report-all|report-all-tagged|trim|explicit]";
        } else {
            defaults = "";
        }
    }

    printf("copy-config [--help] --target %s%s%s%s (--source %s%s%s%s | --src-config[=<file>])%s [--rpc-timeout <seconds>]\n",
            running, startup, candidate, url,
            running, startup, candidate, url, defaults);
}

static void
cmd_deleteconfig_help(void)
{
    const char *startup, *url;

    if (!session) {
        startup = "startup";
        url = "|url:<url>";
    } else {
        if (nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
            startup = "startup";
        } else {
            startup = "";
        }

        if (nc_session_cpblt(session, NC_CAP_URL_ID)) {
            url = strlen(startup) ? "|url:<url>" : "url:<url>";
        } else {
            url = "";
        }
    }

    if ((strlen(startup) + strlen(url)) == 0) {
        printf("delete-config is not supported by the current session.\n");
        return;
    }

    printf("delete-config [--help] --target %s%s [--rpc-timeout <seconds>]\n", startup, url);
}

static void
cmd_discardchanges_help(void)
{
    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        printf("discard-changes [--help] [--rpc-timeout <seconds>]\n");
    } else {
        printf("discard-changes is not supported by the current session.\n");
    }
}

static void
cmd_editconfig_help(void)
{
    const char *rollback, *validate, *running, *candidate, *url, *bracket;

    if (!session || nc_session_cpblt(session, NC_CAP_WRITABLERUNNING_ID)) {
        running = "running";
    } else {
        running = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        if (running[0]) {
            candidate = "|candidate";
        } else {
            candidate = "candidate";
        }
    } else {
        candidate = "";
    }

    if (!running[0] && !candidate[0]) {
        printf("edit-config is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_ROLLBACK_ID)) {
        rollback = "|rollback";
    } else {
        rollback = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_VALIDATE11_ID)) {
        validate = "[--test set|test-only|test-then-set] ";
    } else if (!session || nc_session_cpblt(session, NC_CAP_VALIDATE10_ID)) {
        validate = "[--test set|test-then-set] ";
    } else {
        validate = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_URL_ID)) {
        url = " | --url <url>)";
        bracket = "(";
    } else {
        url = "";
        bracket = "";
    }

    printf("edit-config [--help] --target %s%s %s--config[=<file>]%s [--defop merge|replace|none] "
            "%s[--error stop|continue%s] [--rpc-timeout <seconds>]\n", running, candidate, bracket, url, validate, rollback);
}

static void
cmd_get_help(void)
{
    const char *defaults, *xpath;

    if (!session || nc_session_cpblt(session, NC_CAP_WITHDEFAULTS_ID)) {
        defaults = "[--defaults report-all|report-all-tagged|trim|explicit] ";
    } else {
        defaults = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    fprintf(stdout, "get [--help] [--filter-subtree[=<file>]%s] %s[--out <file>] [--rpc-timeout <seconds>]\n", xpath, defaults);
}

static void
cmd_getconfig_help(void)
{
    const char *defaults, *xpath, *candidate, *startup;

    /* if session not established, print complete help for all capabilities */
    if (!session || nc_session_cpblt(session, NC_CAP_WITHDEFAULTS_ID)) {
        defaults = "[--defaults report-all|report-all-tagged|trim|explicit] ";
    } else {
        defaults = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
        startup = "|startup";
    } else {
        startup = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        candidate = "|candidate";
    } else {
        candidate = "";
    }

    printf("get-config [--help] --source running%s%s [--filter-subtree[=<file>]%s] %s[--out <file>] [--rpc-timeout <seconds>]\n",
            startup, candidate, xpath, defaults);
}

static void
cmd_killsession_help(void)
{
    printf("killsession [--help] --sid <sesion-ID> [--rpc-timeout <seconds>]\n");
}

static void
cmd_lock_help(void)
{
    const char *candidate, *startup;

    if (!session || nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
        startup = "|startup";
    } else {
        startup = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        candidate = "|candidate";
    } else {
        candidate = "";
    }

    printf("lock [--help] --target running%s%s [--rpc-timeout <seconds>]\n", startup, candidate);
}

static void
cmd_unlock_help(void)
{
    const char *candidate, *startup;

    if (!session || nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
        startup = "|startup";
    } else {
        startup = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        candidate = "|candidate";
    } else {
        candidate = "";
    }

    printf("unlock [--help] --target running%s%s [--rpc-timeout <seconds>]\n", startup, candidate);
}

static void
cmd_validate_help(void)
{
    const char *startup, *candidate, *url;

    if (session && !nc_session_cpblt(session, NC_CAP_VALIDATE10_ID) &&
            !nc_session_cpblt(session, NC_CAP_VALIDATE11_ID)) {
        printf("validate is not supported by the current session.\n");
        return;
    }

    if (!session) {
        /* if session not established, print complete help for all capabilities */
        startup = "|startup";
        candidate = "|candidate";
        url = "|url:<url>";
    } else {
        if (nc_session_cpblt(session, NC_CAP_STARTUP_ID)) {
            startup = "|startup";
        } else {
            startup = "";
        }
        if (nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
            candidate = "|candidate";
        } else {
            candidate = "";
        }
        if (nc_session_cpblt(session, NC_CAP_URL_ID)) {
            url = "|url:<dsturl>";
        } else {
            url = "";
        }
    }
    printf("validate [--help] (--source running%s%s%s | --src-config[=<file>]) [--rpc-timeout <seconds>]\n",
            startup, candidate, url);
}

static void
cmd_subscribe_help(void)
{
    const char *xpath;

    if (session && !nc_session_cpblt(session, NC_CAP_NOTIFICATION_ID)) {
        printf("subscribe not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    printf("subscribe [--help] [--filter-subtree[=<file>]%s] [--begin <time>] [--end <time>] [--stream <stream>] [--out <file>]"
            " [--rpc-timeout <seconds>]\n", xpath);
    printf("\t<time> has following format:\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
}

static void
cmd_getschema_help(void)
{
    if (session && !ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-netconf-monitoring")) {
        printf("get-schema is not supported by the current session.\n");
        return;
    }

    printf("get-schema [--help] --model <identifier> [--version <version>] [--format <format>] [--out <file>] [--rpc-timeout <seconds>]\n");
}

static void
cmd_getdata_help(void)
{
    const struct lys_module *mod = NULL;
    const char *defaults, *xpath;
    int origin;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-netconf-nmda"))) {
        printf("get-data is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_WITHDEFAULTS_ID)) {
        defaults = " [--defaults report-all|report-all-tagged|trim|explicit]";
    } else {
        defaults = "";
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    if (mod && (lys_feature_value(mod, "origin") == LY_ENOT)) {
        origin = 0;
    } else {
        origin = 1;
    }

    fprintf(stdout, "get-data [--help] --datastore running|startup|candidate|operational [--filter-subtree[=<file>]%s]"
            " [--config true|false]%s [--depth <subtree-depth>]%s%s [--out <file>] [--rpc-timeout <seconds>]\n",
            xpath, origin ? " [--origin <origin>]* [--negated-origin]" : "", origin ? " [--with-origin]" : "", defaults);
}

static void
cmd_editdata_help(void)
{
    const struct lys_module *mod;
    const char *url, *bracket;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-netconf-nmda"))) {
        printf("edit-data is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_URL_ID)) {
        url = " | --url <url>)";
        bracket = "(";
    } else {
        url = "";
        bracket = "";
    }

    fprintf(stdout, "edit-data [--help] --datastore running|startup|candidate %s--config[=<file>]%s"
            " [--defop merge|replace|none] [--rpc-timeout <seconds>]\n", bracket, url);
}

static void
cmd_establishsub_help(void)
{
    const struct lys_module *mod = NULL;
    const char *xpath;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications"))) {
        printf("establish-sub is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    printf("establish-sub [--help] --stream <stream> [--filter-subtree[=<file>]%s | --filter-ref <name>] [--begin <time>]"
            " [--end <time>] [--encoding <encoding>] [--out <file>] [--rpc-timeout <seconds>]\n", xpath);
    printf("\t<time> has following format:\n\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
}

static void
cmd_modifysub_help(void)
{
    const struct lys_module *mod = NULL;
    const char *xpath;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications"))) {
        printf("modify-sub is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    printf("modify-sub [--help] --id <sub-ID> [--filter-subtree[=<file>]%s | --filter-ref <name>] [--end <time>]"
            " [--out <file>] [--rpc-timeout <seconds>]\n", xpath);
    printf("\t<time> has following format:\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
}

static void
cmd_deletesub_help(void)
{
    const struct lys_module *mod = NULL;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications"))) {
        printf("delete-sub is not supported by the current session.\n");
        return;
    }

    printf("delete-sub [--help] --id <sub-ID> [--out <file>] [--rpc-timeout <seconds>]\n");
}

static void
cmd_killsub_help(void)
{
    const struct lys_module *mod = NULL;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications"))) {
        printf("kill-sub is not supported by the current session.\n");
        return;
    }

    printf("kill-sub [--help] --id <sub-ID> [--out <file>] [--rpc-timeout <seconds>]\n");
}

static void
cmd_establishpush_help(void)
{
    const struct lys_module *mod = NULL;
    const char *xpath;

    if (session && (!ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications") ||
            !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-yang-push")))) {
        printf("establish-push is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    printf("establish-push [--help] --datastore running|startup|candidate|operational"
            " [--filter-subtree[=<file>]%s | --filter-ref <name>] [--end <time>] [--encoding <encoding>]"
            " (--periodic --period <period> [--anchor-time <time>] | --on-change [--dampening-period <period>]"
            " [--no-sync-on-start] [--excluded-change <change>]*) [--out <file>] [--rpc-timeout <seconds>]\n\n", xpath);
    printf("\t<time> has following format:\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
    printf("\t<period> is in centiseconds (0.01s).\n");
    printf("\t<change> can be create, delete, insert, move, or replace.\n");
}

static void
cmd_modifypush_help(void)
{
    const struct lys_module *mod = NULL;
    const char *xpath;

    if (session && (!ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-subscribed-notifications") ||
            !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-yang-push")))) {
        printf("modify-push is not supported by the current session.\n");
        return;
    }

    if (!session || nc_session_cpblt(session, NC_CAP_XPATH_ID)) {
        xpath = " | --filter-xpath <XPath>";
    } else {
        xpath = "";
    }

    printf("modify-push [--help] --id <sub-ID> --datastore running|startup|candidate|operational"
            " [--filter-subtree[=<file>]%s | --filter-ref <name>] [--end <time>]"
            " (--periodic --period <period> [--anchor-time <time>] |--on-change [--dampening-period <period>])"
            " [--out <file>] [--rpc-timeout <seconds>]\n\n", xpath);
    printf("\t<time> has following format:\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
    printf("\t<period> is in centiseconds (0.01s).\n");
}

static void
cmd_resyncsub_help(void)
{
    const struct lys_module *mod = NULL;

    if (session && !(mod = ly_ctx_get_module_implemented(nc_session_get_ctx(session), "ietf-yang-push"))) {
        printf("resync-sub is not supported by the current session.\n");
        return;
    }

    printf("resync-sub [--help] --id <sub-ID> [--out <file>] [--rpc-timeout <seconds>]\n");
}

static void
cmd_userrpc_help(void)
{
    printf("user-rpc [--help] [--content <file>] [--out <file>] [--rpc-timeout <seconds>]\n");
}

static void
cmd_timed_help(void)
{
    printf("timed [--help] [on | off]\n");
}

#ifdef NC_ENABLED_SSH

static void
cmd_auth_help(void)
{
    printf("auth (--help | pref [(publickey | interactive | password) <preference>] | keys [add <public_key_path> <private_key_path>] [remove <key_index>])\n");
}

static void
cmd_knownhosts_help(void)
{
    printf("knownhosts [--help] [--del <key_index>]\n");
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static void
cmd_cert_help(void)
{
    printf("cert [--help | display | add <cert_path> | remove <cert_name> | displayown | replaceown (<cert_path.pem> | <cert_path.crt> <key_path.key>)]\n");
}

static void
cmd_crl_help(void)
{
    printf("crl [--help | display | add <crl_path> | remove <crl_name>]\n");
}

#endif /* NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

static int
cmd_auth(const char *arg, char **UNUSED(tmp_config_file))
{
    int i;
    short int pref;
    char *args = strdupa(arg);
    char *cmd = NULL, *ptr = NULL, *str;
    const char *pub_key, *priv_key;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if ((cmd == NULL) || (strcmp(cmd, "--help") == 0) || (strcmp(cmd, "-h") == 0)) {
        cmd_auth_help();

    } else if (strcmp(cmd, "pref") == 0) {
        cmd = strtok_r(NULL, " ", &ptr);
        if (cmd == NULL) {
            printf("The SSH authentication method preferences:\n");
            if ((pref = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY)) < 0) {
                printf("\t'publickey':   disabled\n");
            } else {
                printf("\t'publickey':   %d\n", pref);
            }
            if ((pref = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD)) < 0) {
                printf("\t'password':    disabled\n");
            } else {
                printf("\t'password':    %d\n", pref);
            }
            if ((pref = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE)) < 0) {
                printf("\t'interactive': disabled\n");
            } else {
                printf("\t'interactive': %d\n", pref);
            }

        } else if (strcmp(cmd, "publickey") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth pref publickey", "Missing the preference argument");
                return EXIT_FAILURE;
            } else {
                nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, atoi(cmd));
            }
        } else if (strcmp(cmd, "interactive") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth pref interactive", "Missing the preference argument");
                return EXIT_FAILURE;
            } else {
                nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, atoi(cmd));
            }
        } else if (strcmp(cmd, "password") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth pref password", "Missing the preference argument");
                return EXIT_FAILURE;
            } else {
                nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, atoi(cmd));
            }
        } else {
            ERROR("auth pref", "Unknown authentication method (%s)", cmd);
            return EXIT_FAILURE;
        }

    } else if (strcmp(cmd, "keys") == 0) {
        cmd = strtok_r(NULL, " ", &ptr);
        if (cmd == NULL) {
            printf("The keys used for SSH authentication:\n");
            if (nc_client_ssh_get_keypair_count() == 0) {
                printf("(none)\n");
            } else {
                for (i = 0; i < nc_client_ssh_get_keypair_count(); ++i) {
                    nc_client_ssh_get_keypair(i, &pub_key, &priv_key);
                    printf("#%d: %s (private %s)\n", i, pub_key, priv_key);
                }
            }
        } else if (strcmp(cmd, "add") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth keys add", "Missing the private key path");
                return EXIT_FAILURE;
            }
            str = cmd;

            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth keys add", "Missing the public key path");
                return EXIT_FAILURE;
            }

            if ((nc_client_ssh_ch_add_keypair(str, cmd) != EXIT_SUCCESS) ||
                    (nc_client_ssh_add_keypair(str, cmd) != EXIT_SUCCESS)) {
                ERROR("auth keys add", "Failed to add keys");
                return EXIT_FAILURE;
            }

            if (eaccess(cmd, R_OK) != 0) {
                ERROR("auth keys add", "The new private key is not accessible (%s), but added anyway", strerror(errno));
            }
            if (eaccess(str, R_OK) != 0) {
                ERROR("auth keys add", "The public key for the new private key is not accessible (%s), but added anyway", strerror(errno));
            }

        } else if (strcmp(cmd, "remove") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth keys remove", "Missing the key index");
                return EXIT_FAILURE;
            }

            i = strtol(cmd, &ptr, 10);
            if (ptr[0] || nc_client_ssh_ch_del_keypair(i) || nc_client_ssh_del_keypair(i)) {
                ERROR("auth keys remove", "Wrong index");
                return EXIT_FAILURE;
            }
        } else {
            ERROR("auth keys", "Unknown argument %s", cmd);
            return EXIT_FAILURE;
        }

    } else {
        ERROR("auth", "Unknown argument %s", cmd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
cmd_knownhosts(const char *arg, char **UNUSED(tmp_config_file))
{
    char *ptr, *kh_file, *line = NULL, **pkeys = NULL, *text;
    int del_idx = -1, i, j, pkey_len = 0, written, text_len;
    size_t line_len;
    FILE *file;
    struct passwd *pwd;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"del", 1, 0, 'd'},
        {0, 0, 0, 0}
    };
    int option_index = 0, c;

    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hd:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_knownhosts_help();
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
            break;
        case 'd':
            del_idx = strtol(optarg, &ptr, 10);
            if ((*ptr != '\0') || (del_idx < 0)) {
                ERROR("knownhosts", "Wrong index");
                clear_arglist(&cmd);
                return EXIT_FAILURE;
            }
            break;
        default:
            ERROR("knownhosts", "Unknown option -%c", c);
            cmd_knownhosts_help();
            clear_arglist(&cmd);
            return EXIT_FAILURE;
        }
    }

    clear_arglist(&cmd);

    errno = 0;
    pwd = getpwuid(getuid());
    if (pwd == NULL) {
        if (errno == 0) {
            ERROR("knownhosts", "Failed to get the home directory of UID %d, it does not exist", getuid());
        } else {
            ERROR("knownhosts", "Failed to get a pwd entry (%s)", strerror(errno));
        }
        return EXIT_FAILURE;
    }

    if (asprintf(&kh_file, "%s/.ssh/known_hosts", pwd->pw_dir) == -1) {
        return EXIT_FAILURE;
    }

    if ((file = fopen(kh_file, "r+")) == NULL) {
        ERROR("knownhosts", "Cannot open \"%s\" (%s)", kh_file, strerror(errno));
        free(kh_file);
        return EXIT_FAILURE;
    }
    free(kh_file);

    /* list */
    if (del_idx == -1) {
        printf("ID Hostname Algorithm Key\n\n");

        errno = 0;
        i = 0;
        while (getline(&line, &line_len, file) > 0) {
            /* host number */
            printf("%d: ", i);

            /* host name */
            ptr = strtok(line, " ");
            if (ptr == NULL) {
                printf("INVALID\n");
                ++i;
                continue;
            }
            if ((ptr[0] == '|') && (ptr[2] == '|')) {
                printf("(hashed hostname) ");
            } else {
                printf("%s ", ptr);
            }

            /* host key algorithm */
            ptr = strtok(NULL, " ");
            if (ptr == NULL) {
                printf("INVALID\n");
                ++i;
                continue;
            }
            printf("%s: ", ptr);

            /* host key */
            ptr = strtok(NULL, " ");
            if (ptr == NULL) {
                printf("INVALID\n");
                ++i;
                continue;
            }
            for (j = 0; j < pkey_len; ++j) {
                if (strcmp(ptr, pkeys[j]) == 0) {
                    break;
                }
            }
            if (j == pkey_len) {
                ++pkey_len;
                pkeys = realloc(pkeys, pkey_len * sizeof(char *));
                pkeys[j] = strdup(ptr);
            }
            printf("(key %d)\n", j);

            ++i;
        }

        if (i == 0) {
            printf("(none)\n");
        }
        printf("\n");

        for (j = 0; j < pkey_len; ++j) {
            free(pkeys[j]);
        }
        free(pkeys);
        free(line);

        /* delete */
    } else {
        fseek(file, 0, SEEK_END);
        text_len = ftell(file);
        if (text_len < 0) {
            ERROR("knownhosts", "ftell on the known hosts file failed (%s)", strerror(errno));
            fclose(file);
            return EXIT_FAILURE;
        }
        fseek(file, 0, SEEK_SET);

        text = malloc(text_len + 1);
        if (fread(text, 1, text_len, file) < (unsigned)text_len) {
            ERROR("knownhosts", "Cannot read known hosts file (%s)", strerror(ferror(file)));
            free(text);
            fclose(file);
            return EXIT_FAILURE;
        }
        text[text_len] = '\0';
        fseek(file, 0, SEEK_SET);

        for (i = 0, ptr = text; (i < del_idx) && ptr; ++i, ptr = strchr(ptr + 1, '\n')) {}

        if (!ptr || (strlen(ptr) < 2)) {
            ERROR("knownhosts", "Key index %d does not exist", del_idx);
            free(text);
            fclose(file);
            return EXIT_FAILURE;
        }

        if (ptr[0] == '\n') {
            ++ptr;
        }

        /* write the old beginning */
        written = fwrite(text, 1, ptr - text, file);
        if (written < ptr - text) {
            ERROR("knownhosts", "Failed to write to known hosts file (%s)", strerror(ferror(file)));
            free(text);
            fclose(file);
            return EXIT_FAILURE;
        }

        ptr = strchr(ptr, '\n');
        if (ptr) {
            ++ptr;

            /* write the rest */
            if (fwrite(ptr, 1, strlen(ptr), file) < strlen(ptr)) {
                ERROR("knownhosts", "Failed to write to known hosts file (%s)", strerror(ferror(file)));
                free(text);
                fclose(file);
                return EXIT_FAILURE;
            }
            written += strlen(ptr);
        }
        free(text);

        if (ftruncate(fileno(file), written) < 0) {
            ERROR("knownhosts", "ftruncate() on known hosts file failed (%s)", strerror(ferror(file)));
            fclose(file);
            return EXIT_FAILURE;
        }
    }

    fclose(file);
    return EXIT_SUCCESS;
}

static int
cmd_connect_listen_ssh(struct arglist *cmd, int is_connect)
{
    const char *func_name = (is_connect ? "cmd_connect" : "cmd_listen");
    static unsigned short listening = 0;
    char *host = NULL, *user = NULL;
    struct passwd *pw;
    unsigned short port = 0;
    int c, timeout = 0, ret;
    int option_index = 0;
    struct option long_options[] = {
        {"ssh", 0, 0, 's'},
        {"host", 1, 0, 'o'},
        {"port", 1, 0, 'p'},
        {"login", 1, 0, 'l'},
        {"timeout", 1, 0, 'i'},
        {0, 0, 0, 0}
    };

    if (is_connect) {
        /* remove timeout option for use as connect command */
        memset(&long_options[4], 0, sizeof long_options[4]);
    }

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    while ((c = getopt_long(cmd->count, cmd->list, (is_connect ? "so:p:l:" : "si:o:p:l:"), long_options, &option_index)) != -1) {
        switch (c) {
        case 's':
            /* we know already */
            break;
        case 'o':
            host = optarg;
            break;
        case 'i':
            timeout = atoi(optarg);
            break;
        case 'p':
            port = (unsigned short)atoi(optarg);
            if (!is_connect && listening && (listening != port)) {
                listening = 0;
            }
            break;
        case 'l':
            user = optarg;
            break;
        default:
            ERROR(func_name, "Unknown option -%c.", c);
            if (is_connect) {
                cmd_connect_help();
            } else {
                cmd_listen_help();
            }
            return EXIT_FAILURE;
        }
    }

    /* default user */
    if (!user) {
        pw = getpwuid(getuid());
        if (pw) {
            user = pw->pw_name;
        }
    }

    if (is_connect) {
        /* default port */
        if (!port) {
            port = NC_PORT_SSH;
        }

        /* default hostname */
        if (!host) {
            host = "localhost";
        }

        nc_client_ssh_set_username(user);
        /* create the session */
        session = nc_connect_ssh(host, port, NULL);
        if (session == NULL) {
            ERROR(func_name, "Connecting to the %s:%d as user \"%s\" failed.", host, port, user);
            return EXIT_FAILURE;
        }
    } else {
        /* default port */
        if (!port) {
            port = NC_PORT_CH_SSH;
        }

        /* default hostname */
        if (!host) {
            host = "::0";
        }

        /* default timeout */
        if (!timeout) {
            timeout = CLI_CH_TIMEOUT;
        }

        /* create the session */
        nc_client_ssh_ch_set_username(user);
        nc_client_ssh_ch_add_bind_listen(host, port);
        printf("Waiting %ds for an SSH Call Home connection on port %u...\n", timeout, port);
        ret = nc_accept_callhome(timeout * 1000, NULL, &session);
        nc_client_ssh_ch_del_bind(host, port);
        if (ret != 1) {
            if (ret == 0) {
                ERROR(func_name, "Receiving SSH Call Home on port %d as user \"%s\" timeout elapsed.", port, user);
            } else {
                ERROR(func_name, "Receiving SSH Call Home on port %d as user \"%s\" failed.", port, user);
            }
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static int
cp(const char *to, const char *from)
{
    int fd_to, fd_from;
    struct stat st;
    ssize_t from_len;
    int saved_errno;
    void *buf;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0) {
        return -1;
    }

    fd_to = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_to < 0) {
        goto out_error;
    }

    if (fstat(fd_from, &st) < 0) {
        goto out_error;
    }

    from_len = st.st_size;

    buf = malloc(from_len);

    if (read(fd_from, buf, from_len) < from_len) {
        free(buf);
        goto out_error;
    }

    if (write(fd_to, buf, from_len) < from_len) {
        free(buf);
        goto out_error;
    }

    free(buf);
    close(fd_from);
    close(fd_to);

    return 0;

out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0) {
        close(fd_to);
    }

    errno = saved_errno;
    return -1;
}

static void
parse_cert(const char *name, const char *path)
{
    int i, j, has_san, first_san;
    ASN1_OCTET_STRING *ip;
    ASN1_INTEGER *bs;
    BIO *bio_out;
    FILE *fp;
    X509 *cert;

    STACK_OF(GENERAL_NAME) * san_names = NULL;
    GENERAL_NAME *san_name;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ERROR("parse_cert", "Unable to open: %s", path);
        return;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cert == NULL) {
        ERROR("parse_cert", "Unable to parse certificate: %s", path);
        fclose(fp);
        return;
    }

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    bs = X509_get_serialNumber(cert);
    BIO_printf(bio_out, "-----%s----- serial: ", name);
    for (i = 0; i < bs->length; i++) {
        BIO_printf(bio_out, "%02x", bs->data[i]);
    }
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Subject: ");
    X509_NAME_print(bio_out, X509_get_subject_name(cert), 0);
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Issuer:  ");
    X509_NAME_print(bio_out, X509_get_issuer_name(cert), 0);
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Valid until: ");
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    ASN1_TIME_print(bio_out, X509_get_notAfter(cert));
#else
    ASN1_TIME_print(bio_out, X509_get0_notAfter(cert));
#endif
    BIO_printf(bio_out, "\n");

    has_san = 0;
    first_san = 1;
    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            san_name = sk_GENERAL_NAME_value(san_names, i);
            if ((san_name->type == GEN_EMAIL) || (san_name->type == GEN_DNS) || (san_name->type == GEN_IPADD)) {
                if (!has_san) {
                    BIO_printf(bio_out, "X509v3 Subject Alternative Name:\n\t");
                    has_san = 1;
                }
                if (!first_san) {
                    BIO_printf(bio_out, ", ");
                }
                if (first_san) {
                    first_san = 0;
                }
                if (san_name->type == GEN_EMAIL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
                    BIO_printf(bio_out, "RFC822:%s", (char *) ASN1_STRING_data(san_name->d.rfc822Name));
#else
                    BIO_printf(bio_out, "RFC822:%s", (char *) ASN1_STRING_get0_data(san_name->d.rfc822Name));
#endif
                }
                if (san_name->type == GEN_DNS) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
                    BIO_printf(bio_out, "DNS:%s", (char *) ASN1_STRING_data(san_name->d.dNSName));
#else
                    BIO_printf(bio_out, "DNS:%s", (char *) ASN1_STRING_get0_data(san_name->d.dNSName));
#endif
                }
                if (san_name->type == GEN_IPADD) {
                    BIO_printf(bio_out, "IP:");
                    ip = san_name->d.iPAddress;
                    if (ip->length == 4) {
                        BIO_printf(bio_out, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
                    } else if (ip->length == 16) {
                        for (j = 0; j < ip->length; ++j) {
                            if ((j > 0) && (j < 15) && (j % 2 == 1)) {
                                BIO_printf(bio_out, "%02x:", ip->data[j]);
                            } else {
                                BIO_printf(bio_out, "%02x", ip->data[j]);
                            }
                        }
                    }
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
    if (has_san) {
        BIO_printf(bio_out, "\n");
    }
    BIO_printf(bio_out, "\n");

    X509_free(cert);
    BIO_vfree(bio_out);
    fclose(fp);
}

static void
parse_crl(const char *name, const char *path)
{
    int i;
    BIO *bio_out;
    FILE *fp;
    X509_CRL *crl;
    const ASN1_INTEGER *bs;
    X509_REVOKED *rev;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ERROR("parse_crl", "Unable to open \"%s\": %s", path, strerror(errno));
        return;
    }
    crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
    if (crl == NULL) {
        ERROR("parse_crl", "Unable to parse certificate: %s", path);
        fclose(fp);
        return;
    }

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "-----%s-----\n", name);

    BIO_printf(bio_out, "Issuer: ");
    X509_NAME_print(bio_out, X509_CRL_get_issuer(crl), 0);
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Last update: ");
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    ASN1_TIME_print(bio_out, X509_CRL_get_lastUpdate(crl));
#else
    ASN1_TIME_print(bio_out, X509_CRL_get0_lastUpdate(crl));
#endif
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Next update: ");
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    ASN1_TIME_print(bio_out, X509_CRL_get_nextUpdate(crl));
#else
    ASN1_TIME_print(bio_out, X509_CRL_get0_nextUpdate(crl));
#endif
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "REVOKED:\n");

    if ((rev = sk_X509_REVOKED_pop(X509_CRL_get_REVOKED(crl))) == NULL) {
        BIO_printf(bio_out, "\tNone\n");
    }
    while (rev != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
        bs = rev->serialNumber;
#else
        bs = X509_REVOKED_get0_serialNumber(rev);
#endif
        BIO_printf(bio_out, "\tSerial no.: ");
        for (i = 0; i < bs->length; i++) {
            BIO_printf(bio_out, "%02x", bs->data[i]);
        }

        BIO_printf(bio_out, "  Date: ");
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
        ASN1_TIME_print(bio_out, rev->revocationDate);
#else
        ASN1_TIME_print(bio_out, X509_REVOKED_get0_revocationDate(rev));
#endif
        BIO_printf(bio_out, "\n");

        X509_REVOKED_free(rev);
        rev = sk_X509_REVOKED_pop(X509_CRL_get_REVOKED(crl));
    }

    X509_CRL_free(crl);
    BIO_vfree(bio_out);
    fclose(fp);
}

static int
cmd_cert(const char *arg, char **UNUSED(tmp_config_file))
{
    int ret;
    char *args = strdupa(arg);
    char *cmd = NULL, *ptr = NULL, *path, *path2, *dest = NULL;
    char *trusted_dir = NULL, *netconf_dir = NULL, *c_rehash_cmd = NULL;
    DIR *dir = NULL;
    struct dirent *d;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if (!cmd || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        cmd_cert_help();

    } else if (!strcmp(cmd, "display")) {
        int none = 1;
        char *name;

        if (!(trusted_dir = get_default_trustedCA_dir(NULL))) {
            ERROR("cert display", "Could not get the default trusted CA directory");
            goto error;
        }

        dir = opendir(trusted_dir);
        while ((d = readdir(dir))) {
            if (!strcmp(d->d_name + strlen(d->d_name) - 4, ".pem")) {
                none = 0;
                name = strdup(d->d_name);
                name[strlen(name) - 4] = '\0';
                if (asprintf(&path, "%s/%s", trusted_dir, d->d_name) == -1) {
                    free(name);
                    break;
                }
                parse_cert(name, path);
                free(name);
                free(path);
            }
        }
        closedir(dir);
        if (none) {
            printf("No certificates found in the default trusted CA directory.\n");
        }

    } else if (!strcmp(cmd, "add")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("cert add", "Missing or wrong path to the certificate");
            goto error;
        }
        if (eaccess(path, R_OK)) {
            ERROR("cert add", "Cannot access certificate \"%s\": %s", path, strerror(errno));
            goto error;
        }

        trusted_dir = get_default_trustedCA_dir(NULL);
        if (!trusted_dir) {
            ERROR("cert add", "Could not get the default trusted CA directory");
            goto error;
        }

        if ((asprintf(&dest, "%s/%s", trusted_dir, strrchr(path, '/') + 1) == -1) ||
                (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", trusted_dir) == -1)) {
            ERROR("cert add", "Memory allocation failed");
            goto error;
        }

        if (strcmp(dest + strlen(dest) - 4, ".pem")) {
            ERROR("cert add", "CA certificates are expected to be in *.pem format");
            strcpy(dest + strlen(dest) - 4, ".pem");
        }

        if (cp(dest, path)) {
            ERROR("cert add", "Could not copy the certificate: %s", strerror(errno));
            goto error;
        }

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("cert add", "c_rehash execution failed");
            goto error;
        }

    } else if (!strcmp(cmd, "remove")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path) {
            ERROR("cert remove", "Missing the certificate name");
            goto error;
        }

        /* delete ".pem" if the user unnecessarily included it */
        if ((strlen(path) > 4) && !strcmp(path + strlen(path) - 4, ".pem")) {
            path[strlen(path) - 4] = '\0';
        }

        trusted_dir = get_default_trustedCA_dir(NULL);
        if (!trusted_dir) {
            ERROR("cert remove", "Could not get the default trusted CA directory");
            goto error;
        }

        if ((asprintf(&dest, "%s/%s.pem", trusted_dir, path) == -1) ||
                (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", trusted_dir) == -1)) {
            ERROR("cert remove", "Memory allocation failed");
            goto error;
        }

        if (remove(dest)) {
            ERROR("cert remove", "Cannot remove certificate \"%s\": %s (use the name from \"cert display\" output)",
                    path, strerror(errno));
            goto error;
        }

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("cert remove", "c_rehash execution failed");
            goto error;
        }

    } else if (!strcmp(cmd, "displayown")) {
        int crt = 0, key = 0, pem = 0;

        netconf_dir = get_netconf_dir();
        if (!netconf_dir) {
            ERROR("cert displayown", "Could not get the client home directory");
            goto error;
        }

        if (asprintf(&dest, "%s/client.pem", netconf_dir) == -1) {
            ERROR("cert displayown", "Memory allocation failed");
            goto error;
        }
        if (!eaccess(dest, R_OK)) {
            pem = 1;
        }

        strcpy(dest + strlen(dest) - 4, ".key");
        if (!eaccess(dest, R_OK)) {
            key = 1;
        }

        strcpy(dest + strlen(dest) - 4, ".crt");
        if (!eaccess(dest, R_OK)) {
            crt = 1;
        }

        if (!crt && !key && !pem) {
            printf("FAIL: No client certificate found, use \"cert replaceown\" to set some.\n");
        } else if (crt && !key && !pem) {
            printf("FAIL: Client *.crt certificate found, but is of no use without its private key *.key.\n");
        } else if (!crt && key && !pem) {
            printf("FAIL: Private key *.key found, but is of no use without a certificate.\n");
        } else if (!crt && !key && pem) {
            printf("OK: Using *.pem client certificate with the included private key.\n");
        } else if (crt && key && !pem) {
            printf("OK: Using *.crt certificate with a separate private key.\n");
        } else if (crt && !key && pem) {
            printf("WORKING: Using *.pem client certificate with the included private key (leftover certificate *.crt detected).\n");
        } else if (!crt && key && pem) {
            printf("WORKING: Using *.pem client certificate with the included private key (leftover private key detected).\n");
        } else if (crt && key && pem) {
            printf("WORKING: Using *.crt certificate with a separate private key (lower-priority *.pem certificate with a private key detected).\n");
        }

        if (crt) {
            parse_cert("CRT", dest);
        }
        if (pem) {
            strcpy(dest + strlen(dest) - 4, ".pem");
            parse_cert("PEM", dest);
        }

    } else if (!strcmp(cmd, "replaceown")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("cert replaceown", "Missing the certificate or invalid path.");
            goto error;
        }
        if (eaccess(path, R_OK)) {
            ERROR("cert replaceown", "Cannot access the certificate \"%s\": %s", path, strerror(errno));
            goto error;
        }

        path2 = strtok_r(NULL, " ", &ptr);
        if (path2) {
            if (strlen(path2) < 5) {
                ERROR("cert replaceown", "Invalid private key path.");
                goto error;
            }
            if (eaccess(path2, R_OK)) {
                ERROR("cert replaceown", "Cannot access the private key \"%s\": %s", path2, strerror(errno));
                goto error;
            }
        }

        netconf_dir = get_netconf_dir();
        if (!netconf_dir) {
            ERROR("cert replaceown", "Could not get the client home directory");
            goto error;
        }
        if (asprintf(&dest, "%s/client.XXX", netconf_dir) == -1) {
            ERROR("cert replaceown", "Memory allocation failed");
            goto error;
        }

        if (path2) {
            /* CRT & KEY */
            strcpy(dest + strlen(dest) - 4, ".pem");
            errno = 0;
            if (remove(dest) && (errno == EACCES)) {
                ERROR("cert replaceown", "Could not remove old certificate (*.pem)");
            }

            strcpy(dest + strlen(dest) - 4, ".crt");
            if (cp(dest, path)) {
                ERROR("cert replaceown", "Could not copy the certificate \"%s\": %s", path, strerror(errno));
                goto error;
            }
            strcpy(dest + strlen(dest) - 4, ".key");
            if (cp(dest, path2)) {
                ERROR("cert replaceown", "Could not copy the private key \"%s\": %s", path, strerror(errno));
                goto error;
            }
        } else {
            /* PEM */
            strcpy(dest + strlen(dest) - 4, ".key");
            errno = 0;
            if (remove(dest) && (errno == EACCES)) {
                ERROR("cert replaceown", "Could not remove old private key");
            }
            strcpy(dest + strlen(dest) - 4, ".crt");
            if (remove(dest) && (errno == EACCES)) {
                ERROR("cert replaceown", "Could not remove old certificate (*.crt)");
            }

            strcpy(dest + strlen(dest) - 4, ".pem");
            if (cp(dest, path)) {
                ERROR("cert replaceown", "Could not copy the certificate \"%s\": %s", path, strerror(errno));
                goto error;
            }
        }

    } else {
        ERROR("cert", "Unknown argument %s", cmd);
        goto error;
    }

    free(dest);
    free(trusted_dir);
    free(netconf_dir);
    free(c_rehash_cmd);
    return EXIT_SUCCESS;

error:
    free(dest);
    free(trusted_dir);
    free(netconf_dir);
    free(c_rehash_cmd);
    return EXIT_FAILURE;
}

static int
cmd_crl(const char *arg, char **UNUSED(tmp_config_file))
{
    int ret;
    char *args = strdupa(arg);
    char *cmd = NULL, *ptr = NULL, *path, *dest = NULL;
    char *crl_dir = NULL, *c_rehash_cmd = NULL;
    DIR *dir = NULL;
    struct dirent *d;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if (!cmd || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        cmd_crl_help();

    } else if (!strcmp(cmd, "display")) {
        int none = 1;
        char *name;

        if (!(crl_dir = get_default_CRL_dir(NULL))) {
            ERROR("crl display", "Could not get the default CRL directory");
            goto error;
        }

        dir = opendir(crl_dir);
        while ((d = readdir(dir))) {
            if (!strcmp(d->d_name + strlen(d->d_name) - 4, ".pem")) {
                none = 0;
                name = strdup(d->d_name);
                name[strlen(name) - 4] = '\0';
                if (asprintf(&path, "%s/%s", crl_dir, d->d_name) == -1) {
                    free(name);
                    break;
                }
                parse_crl(name, path);
                free(name);
                free(path);
            }
        }
        closedir(dir);
        if (none) {
            printf("No CRLs found in the default CRL directory.\n");
        }

    } else if (!strcmp(cmd, "add")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("crl add", "Missing or wrong path to the certificate");
            goto error;
        }
        if (eaccess(path, R_OK)) {
            ERROR("crl add", "Cannot access certificate \"%s\": %s", path, strerror(errno));
            goto error;
        }

        crl_dir = get_default_CRL_dir(NULL);
        if (!crl_dir) {
            ERROR("crl add", "Could not get the default CRL directory");
            goto error;
        }

        if ((asprintf(&dest, "%s/%s", crl_dir, strrchr(path, '/') + 1) == -1) ||
                (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", crl_dir) == -1)) {
            ERROR("crl add", "Memory allocation failed");
            goto error;
        }

        if (strcmp(dest + strlen(dest) - 4, ".pem")) {
            ERROR("crl add", "CRLs are expected to be in *.pem format");
            strcpy(dest + strlen(dest) - 4, ".pem");
        }

        if (cp(dest, path)) {
            ERROR("crl add", "Could not copy the CRL \"%s\": %s", path, strerror(errno));
            goto error;
        }

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("crl add", "c_rehash execution failed");
            goto error;
        }

    } else if (!strcmp(cmd, "remove")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path) {
            ERROR("crl remove", "Missing the certificate name");
            goto error;
        }

        // delete ".pem" if the user unnecessarily included it
        if ((strlen(path) > 4) && !strcmp(path + strlen(path) - 4, ".pem")) {
            path[strlen(path) - 4] = '\0';
        }

        crl_dir = get_default_CRL_dir(NULL);
        if (!crl_dir) {
            ERROR("crl remove", "Could not get the default CRL directory");
            goto error;
        }

        if ((asprintf(&dest, "%s/%s.pem", crl_dir, path) == -1) ||
                (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", crl_dir) == -1)) {
            ERROR("crl remove", "Memory allocation failed");
            goto error;
        }

        if (remove(dest)) {
            ERROR("crl remove", "Cannot remove CRL \"%s\": %s (use the name from \"crl display\" output)",
                    path, strerror(errno));
            goto error;
        }

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("crl remove", "c_rehash execution failed");
            goto error;
        }

    } else {
        ERROR("crl", "Unknown argument %s", cmd);
        goto error;
    }

    free(dest);
    free(c_rehash_cmd);
    free(crl_dir);
    return EXIT_SUCCESS;

error:
    free(dest);
    free(c_rehash_cmd);
    free(crl_dir);
    return EXIT_FAILURE;
}

static int
cmd_connect_listen_tls(struct arglist *cmd, int is_connect)
{
    const char *func_name, *optstring, *host = NULL, *trusted_store = NULL, *peername = NULL;
    static unsigned short listening = 0;
    DIR *dir = NULL;
    struct dirent *d;
    int c, n, timeout = 0, ret = EXIT_FAILURE;
    char *cert = NULL, *key = NULL, *trusted_dir = NULL, *crl_dir = NULL;
    unsigned short port = 0;
    int option_index = 0;
    struct option long_options[] = {
        {"tls", 0, 0, 't'},
        {"host", 1, 0, 'o'},
        {"port", 1, 0, 'p'},
        {"cert", 1, 0, 'c'},
        {"key", 1, 0, 'k'},
        {"trusted", 1, 0, 'r'},
        {"peername", 1, 0, 'e'},
        {"timeout", 1, 0, 'i'},
        {0, 0, 0, 0}
    };

    if (is_connect) {
        func_name = "cmd_connect";

        /* remove peername and timeout option for use in connect */
        memset(&long_options[6], 0, sizeof *long_options);
        memset(&long_options[7], 0, sizeof *long_options);
        optstring = "to:p:c:k:r:";
    } else {
        func_name = "cmd_listen";
        optstring = "to:p:c:k:r:e:i:";
    }

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    while ((c = getopt_long(cmd->count, cmd->list, optstring, long_options, &option_index)) != -1) {
        switch (c) {
        case 't':
            /* we know already */
            break;
        case 'o':
            host = optarg;
            break;
        case 'p':
            port = (unsigned short)atoi(optarg);
            if (!is_connect && listening && (listening != port)) {
                listening = 0;
            }
            break;
        case 'c':
            if (asprintf(&cert, "%s", optarg) == -1) {
                goto error_cleanup;
            }
            break;
        case 'k':
            if (asprintf(&key, "%s", optarg) == -1) {
                goto error_cleanup;
            }
            break;
        case 'r':
            trusted_store = optarg;
            break;
        case 'e':
            peername = optarg;
            break;
        case 'i':
            timeout = atoi(optarg);
            break;
        default:
            ERROR(func_name, "Unknown option -%c.", c);
            if (is_connect) {
                cmd_connect_help();
            } else {
                cmd_listen_help();
            }
            goto error_cleanup;
        }
    }

    if (!cert) {
        if (key) {
            ERROR(func_name, "Key specified without a certificate.");
            goto error_cleanup;
        }
        get_default_client_cert(&cert, &key);
        if (!cert) {
            ERROR(func_name, "Could not find the default client certificate, check with \"cert displayown\" command.");
            goto error_cleanup;
        }
    }
    if (!trusted_store) {
        trusted_dir = get_default_trustedCA_dir(NULL);
        if (!(dir = opendir(trusted_dir))) {
            ERROR(func_name, "Could not use the trusted CA directory.");
            goto error_cleanup;
        }

        /* check whether we have any trusted CA, verification should fail otherwise */
        n = 0;
        while ((d = readdir(dir))) {
            if (++n > 2) {
                break;
            }
        }
        closedir(dir);
        if (n <= 2) {
            ERROR(func_name, "Trusted CA directory empty, use \"cert add\" command to add certificates.");
        }
    } else {
        if (eaccess(trusted_store, R_OK)) {
            ERROR(func_name, "Could not access trusted CA store \"%s\": %s", trusted_store, strerror(errno));
            goto error_cleanup;
        }
        if ((strlen(trusted_store) < 5) || strcmp(trusted_store + strlen(trusted_store) - 4, ".pem")) {
            ERROR(func_name, "Trusted CA store in an unknown format.");
            goto error_cleanup;
        }
    }
    if (!(crl_dir = get_default_CRL_dir(NULL))) {
        ERROR(func_name, "Could not use the CRL directory.");
        goto error_cleanup;
    }

    if (is_connect) {
        nc_client_tls_set_cert_key_paths(cert, key);
        nc_client_tls_set_trusted_ca_paths(trusted_store, trusted_dir);
        nc_client_tls_set_crl_paths(NULL, crl_dir);

        /* default port */
        if (!port) {
            port = NC_PORT_TLS;
        }

        /* default host */
        if (!host) {
            host = "localhost";
        }

        /* create the session */
        session = nc_connect_tls(host, port, NULL);
        if (session == NULL) {
            ERROR(func_name, "Connecting to the %s:%d failed.", host, port);
            goto error_cleanup;
        }
    } else {
        nc_client_tls_ch_set_cert_key_paths(cert, key);
        nc_client_tls_ch_set_trusted_ca_paths(trusted_store, trusted_dir);
        nc_client_tls_ch_set_crl_paths(NULL, crl_dir);

        /* default timeout */
        if (!timeout) {
            timeout = CLI_CH_TIMEOUT;
        }

        /* default port */
        if (!port) {
            port = NC_PORT_CH_TLS;
        }

        /* default host */
        if (!host) {
            host = "::0";
        }

        /* create the session */
        nc_client_tls_ch_add_bind_hostname_listen(host, port, peername);
        ERROR(func_name, "Waiting %ds for a TLS Call Home connection on port %u...", timeout, port);
        ret = nc_accept_callhome(timeout * 1000, NULL, &session);
        nc_client_tls_ch_del_bind(host, port);
        if (ret != 1) {
            if (ret == 0) {
                ERROR(func_name, "Receiving TLS Call Home on port %d timeout elapsed.", port);
            } else {
                ERROR(func_name, "Receiving TLS Call Home on port %d failed.", port);
            }
            goto error_cleanup;
        }
    }

    ret = EXIT_SUCCESS;

error_cleanup:
    free(trusted_dir);
    free(crl_dir);
    free(cert);
    free(key);
    return ret;
}

#endif /* NC_ENABLED_TLS */

static int
cmd_connect_listen_unix(struct arglist *cmd, int is_connect)
{
    const char *func_name = (is_connect ? "cmd_connect" : "cmd_listen");
    const char *path = NULL;
    int c, ret = EXIT_FAILURE;
    int option_index = 0;
    struct option long_options[] = {
        {"unix", 0, 0, 'u'},
        {"socket", 1, 0, 'S'},
        {0, 0, 0, 0}
    };

    if (!is_connect) {
        ERROR(func_name, "listen mode not supported for unix socket.");
        return EXIT_FAILURE;
    }

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    while ((c = getopt_long(cmd->count, cmd->list, "uS:",
            long_options, &option_index)) != -1) {
        switch (c) {
        case 'u':
            /* we know already */
            break;
        case 'S':
            path = optarg;
            break;
        default:
            ERROR(func_name, "Unknown option -%c.", c);
            cmd_connect_help();
            return EXIT_FAILURE;
        }
    }

    if (!path) {
        path = "/var/run/netopeer2-server.sock";
    }

    /* create the session */
    session = nc_connect_unix(path, NULL);
    if (session == NULL) {
        ERROR(func_name, "Connecting to %s failed.", path);
        goto error_cleanup;
    }

    ret = EXIT_SUCCESS;

error_cleanup:
    return ret;
}

static int
cmd_searchpath(const char *arg, char **UNUSED(tmp_config_file))
{
    const char *path;

    for (arg += 10; isspace(arg[0]); ++arg) {}

    if (!arg[0]) {
        path = nc_client_get_schema_searchpath();
        fprintf(stdout, "%s\n", path && path[0] ? path : "<none>");
        return 0;
    }

    if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
        cmd_searchpath_help();
        return 0;
    }

    nc_client_set_schema_searchpath(arg);
    return 0;
}

static int
cmd_outputformat(const char *arg, char **UNUSED(tmp_config_file))
{
    const char *format;

    if (strchr(arg, ' ') == NULL) {
        fprintf(stderr, "Missing the output format.\n");
        return 1;
    }

    format = strchr(arg, ' ') + 1;

    if (!strncmp(format, "-h", 2) || !strncmp(format, "--help", 6)) {
        cmd_outputformat_help();
        return 0;
    }

    if (!strncmp(format, "xml", 3) && ((format[3] == '\0') || (format[3] == ' '))) {
        output_format = LYD_XML;
        output_flag = 0;
    } else if (!strncmp(format, "xml_noformat", 12) && ((format[12] == '\0') || (format[12] == ' '))) {
        output_format = LYD_XML;
        output_flag = LYD_PRINT_SHRINK;
    } else if (!strncmp(format, "json", 4) && ((format[4] == '\0') || (format[4] == ' '))) {
        output_format = LYD_JSON;
        output_flag = 0;
    } else if (!strncmp(format, "json_noformat", 13) && ((format[13] == '\0') || (format[13] == ' '))) {
        output_format = LYD_JSON;
        output_flag = LYD_PRINT_SHRINK;
    } else {
        fprintf(stderr, "Unknown output format \"%s\".\n", format);
        return 1;
    }

    return 0;
}

static int
cmd_version(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    fprintf(stdout, "netopeer2-cli %s\n", CLI_VERSION);
    return 0;
}

static int
cmd_verb(const char *arg, char **UNUSED(tmp_config_file))
{
    const char *verb;

    if (strlen(arg) < 5) {
        cmd_verb_help();
        return 1;
    }

    verb = arg + 5;
    if (!strcmp(verb, "error") || !strcmp(verb, "0")) {
        nc_verbosity(0);
#ifdef NC_ENABLED_SSH
        nc_libssh_thread_verbosity(0);
#endif
    } else if (!strcmp(verb, "warning") || !strcmp(verb, "1")) {
        nc_verbosity(1);
#ifdef NC_ENABLED_SSH
        nc_libssh_thread_verbosity(1);
#endif
    } else if (!strcmp(verb, "verbose") || !strcmp(verb, "2")) {
        nc_verbosity(2);
#ifdef NC_ENABLED_SSH
        nc_libssh_thread_verbosity(2);
#endif
    } else if (!strcmp(verb, "debug") || !strcmp(verb, "3")) {
        nc_verbosity(3);
#ifdef NC_ENABLED_SSH
        nc_libssh_thread_verbosity(3);
#endif
    } else {
        fprintf(stderr, "Unknown verbosity \"%s\"\n", verb);
        return 1;
    }

    return 0;
}

static int
cmd_disconnect(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    if (session == NULL) {
        ERROR("disconnect", "Not connected to any NETCONF server.");
    } else {
        nc_session_free(session, NULL);
        session = NULL;
    }

    return EXIT_SUCCESS;
}

static int
cmd_status(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    const char *s;
    const char * const *cpblts;
    NC_TRANSPORT_IMPL transport;
    int i;

    if (!session) {
        printf("Client is not connected to any NETCONF server.\n");
    } else {
        transport = nc_session_get_ti(session);
        printf("Current NETCONF session:\n");
        printf("  ID          : %u\n", nc_session_get_id(session));
        switch (transport) {
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            s = "SSH";
            printf("  Host        : %s\n", nc_session_get_host(session));
            printf("  Port        : %u\n", nc_session_get_port(session));
            break;
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            s = "TLS";
            printf("  Host        : %s\n", nc_session_get_host(session));
            printf("  Port        : %u\n", nc_session_get_port(session));
            break;
#endif
        case NC_TI_FD:
            s = "FD";
            break;
        case NC_TI_UNIX:
            s = "UNIX";
            printf("  Path        : %s\n", nc_session_get_path(session));
            break;
        default:
            s = "Unknown";
            break;
        }
        printf("  Transport   : %s\n", s);
        printf("  Capabilities:\n");
        cpblts = nc_session_get_cpblts(session);
        for (i = 0; cpblts[i]; ++i) {
            printf("\t%s\n", cpblts[i]);
        }
    }

    return EXIT_SUCCESS;
}

static int
cmd_connect_listen(const char *arg, int is_connect)
{
    const char *func_name = (is_connect ? "cmd_connect" : "cmd_listen");
    int c, ret = EXIT_SUCCESS;
    NC_TRANSPORT_IMPL ti = 0;
    const char *optstring;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
#ifdef NC_ENABLED_SSH
        {"ssh", 0, 0, 's'},
        {"timeout", 1, 0, 'i'},
        {"host", 1, 0, 'o'},
        {"port", 1, 0, 'p'},
        {"login", 1, 0, 'l'},
#endif
#ifdef NC_ENABLED_TLS
        {"tls", 0, 0, 't'},
        {"timeout", 1, 0, 'i'},
        {"host", 1, 0, 'o'},
        {"port", 1, 0, 'p'},
        {"cert", 1, 0, 'c'},
        {"key", 1, 0, 'k'},
        {"trusted", 1, 0, 'r'},
        {"peername", 1, 0, 'e'},
#endif
        {"unix", 0, 0, 'u'},
        {"socket", 1, 0, 'S'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    if (session) {
        ERROR(func_name, "Already connected to %s.",
                nc_session_get_host(session) ?: nc_session_get_path(session));
        return EXIT_FAILURE;
    }

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    ret = -1;

#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)
    optstring = "hsti:o:p:l:c:k:r:e:uS:";
#elif defined (NC_ENABLED_SSH)
    optstring = "hsi:o:p:l:uS:";
#elif defined (NC_ENABLED_TLS)
    optstring = "hti:o:p:c:k:r:e:uS:";
#else
    optstring = "hi:o:p:c:k:r:e:uS:";
#endif

    while (!ti && ((c = getopt_long(cmd.count, cmd.list, optstring, long_options, &option_index)) != -1)) {
        switch (c) {
        case 'h':
            ti = NC_TI_FD;
            break;
#ifdef NC_ENABLED_SSH
        case 's':
            ti = NC_TI_LIBSSH;
            break;
#endif
#ifdef NC_ENABLED_TLS
        case 't':
            ti = NC_TI_OPENSSL;
            break;
#endif
        case 'u':
            ti = NC_TI_UNIX;
            break;
        default:
            break;
        }
    }

    if (!ti) {
        /* default transport */
#ifdef NC_ENABLED_SSH
        ti = NC_TI_LIBSSH;
#elif defined (NC_ENABLED_TLS)
        ti = NC_TI_OPENSSL;
#endif
    }

    switch (ti) {
    case NC_TI_FD:
        if (is_connect) {
            cmd_connect_help();
        } else {
            cmd_listen_help();
        }
        break;
    case NC_TI_UNIX:
        ret = cmd_connect_listen_unix(&cmd, is_connect);
        break;
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        ret = cmd_connect_listen_ssh(&cmd, is_connect);
        break;
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        ret = cmd_connect_listen_tls(&cmd, is_connect);
        break;
#endif
    default:
        ERROR(func_name, "Unknown transport.");
        ret = EXIT_FAILURE;
        break;
    }
    if (!ret) {
        interleave = 1;
    }

    clear_arglist(&cmd);
    return ret;
}

static int
cmd_connect(const char *arg, char **UNUSED(tmp_config_file))
{
    return cmd_connect_listen(arg, 1);
}

static int
cmd_listen(const char *arg, char **UNUSED(tmp_config_file))
{
    return cmd_connect_listen(arg, 0);
}

static int
cmd_quit(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    done = 1;
    return 0;
}

static int
cmd_help(const char *arg, char **UNUSED(tmp_config_file))
{
    int i;
    char *args = strdupa(arg);
    char *cmd = NULL;

    strtok(args, " ");
    if ((cmd = strtok(NULL, " ")) == NULL) {

generic_help:
        fprintf(stdout, "Available commands:\n");

        for (i = 0; commands[i].name; i++) {
            if (commands[i].helpstring != NULL) {
                fprintf(stdout, "  %-15s %s\n", commands[i].name, commands[i].helpstring);
            }
        }
    } else {
        /* print specific help for the selected command */

        /* get the command of the specified name */
        for (i = 0; commands[i].name; i++) {
            if (strcmp(cmd, commands[i].name) == 0) {
                break;
            }
        }

        /* execute the command's help if any valid command specified */
        if (commands[i].name) {
            if (commands[i].help_func != NULL) {
                commands[i].help_func();
            } else {
                printf("%s\n", commands[i].helpstring);
            }
        } else {
            /* if unknown command specified, print the list of commands */
            printf("Unknown command \'%s\'\n", cmd);
            goto generic_help;
        }
    }

    return 0;
}

static int
cmd_editor(const char *arg, char **UNUSED(tmp_config_file))
{
    char *cmd, *args = strdupa(arg), *ptr = NULL;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if (cmd == NULL) {
        printf("Current editor: ");
        printf("%s\n", config_editor);
    } else if ((strcmp(cmd, "--help") == 0) || (strcmp(cmd, "-h") == 0)) {
        cmd_editor_help();
    } else {
        free(config_editor);
        config_editor = strdup(cmd);
    }

    return EXIT_SUCCESS;
}

static int
cmd_cancelcommit(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    const char *persist_id = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"persist-id", 1, 0, 'i'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hi:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_cancelcommit_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            persist_id = optarg;
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_cancelcommit_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_cancelcommit_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    rpc = nc_rpc_cancel(persist_id, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_commit(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE, confirmed = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    int32_t confirm_timeout = 0;
    char *persist = NULL, *persist_id = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"confirmed", 0, 0, 'c'},
        {"confirm-timeout", 1, 0, 't'},
        {"persist", 1, 0, 'p'},
        {"persist-id", 1, 0, 'i'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hct:p:i:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_commit_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'c':
            confirmed = 1;
            break;
        case 't':
            confirm_timeout = atoi(optarg);
            break;
        case 'p':
            persist = optarg;
            break;
        case 'i':
            persist_id = optarg;
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_commit_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_commit_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    rpc = nc_rpc_commit(confirmed, confirm_timeout, persist, persist_id, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_copyconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *src = NULL, *config_m = NULL, *src_start = NULL;
    const char *trg = NULL;
    NC_DATASTORE target = NC_DATASTORE_ERROR, source = NC_DATASTORE_ERROR;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"target", 1, 0, 't'},
        {"source", 1, 0, 's'},
        {"src-config", 2, 0, 'c'},
        {"defaults", 1, 0, 'd'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:s:c::d:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_copyconfig_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            /* validate argument */
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else if (!strncmp(optarg, "url:", 4)) {
                target = NC_DATASTORE_URL;
                trg = &(optarg[4]);
            } else {
                ERROR(__func__, "Invalid target datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 's':
            /* check if -c was not used */
            if (source != NC_DATASTORE_ERROR) {
                ERROR(__func__, "Mixing --source, and --src-config parameters is not allowed.");
                goto fail;
            }

            /* validate argument */
            if (!strcmp(optarg, "running")) {
                source = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                source = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                source = NC_DATASTORE_CANDIDATE;
            } else if (!strncmp(optarg, "url:", 4)) {
                source = NC_DATASTORE_URL;
                src = strdup(&(optarg[4]));
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'c':
            /* check if -s was not used */
            if (source != NC_DATASTORE_ERROR) {
                ERROR(__func__, "Mixing --source and --src-config parameters is not allowed.");
                goto fail;
            }

            source = NC_DATASTORE_CONFIG;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                src = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'd':
            if (!strcmp(optarg, "report-all")) {
                wd = NC_WD_ALL;
            } else if (!strcmp(optarg, "report-all-tagged")) {
                wd = NC_WD_ALL_TAG;
            } else if (!strcmp(optarg, "trim")) {
                wd = NC_WD_TRIM;
            } else if (!strcmp(optarg, "explicit")) {
                wd = NC_WD_EXPLICIT;
            } else {
                ERROR(__func__, "Unknown with-defaults mode \"%s\".", optarg);
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_copyconfig_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_copyconfig_help();
        goto fail;
    }

    if (!source || !target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_copyconfig_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if ((source == NC_DATASTORE_CONFIG) && !src) {
        /* let user write edit data interactively */
        src = readinput("Type the content of a configuration datastore.", *tmp_config_file, tmp_config_file);
        if (!src) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    if (src) {
        /* trim top-level element if needed */
        src_start = trim_top_elem(src, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
        if (!src_start) {
            ERROR(__func__, "Provided configuration content is invalid.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_copy(target, trg, source, src_start, wd, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    free(src);
    clear_arglist(&cmd);

    return ret;
}

static int
cmd_deleteconfig(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    const char *trg = NULL;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"target", 1, 0, 't'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_deleteconfig_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strncmp(optarg, "url:", 4)) {
                target = NC_DATASTORE_URL;
                trg = &(optarg[4]);
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_deleteconfig_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_deleteconfig_help();
        goto fail;
    }

    if (!target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_deleteconfig_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_delete(target, trg, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_discardchanges(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hr:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_discardchanges_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_discardchanges_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_discardchanges_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    rpc = nc_rpc_discard();
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);

    return ret;
}

static int
cmd_editconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, content_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *content = NULL, *config_m = NULL, *cont_start;
    NC_DATASTORE target = NC_DATASTORE_ERROR;
    struct nc_rpc *rpc;
    NC_RPC_EDIT_DFLTOP op = NC_RPC_EDIT_DFLTOP_UNKNOWN;
    NC_RPC_EDIT_TESTOPT test = NC_RPC_EDIT_TESTOPT_UNKNOWN;
    NC_RPC_EDIT_ERROPT err = NC_RPC_EDIT_ERROPT_UNKNOWN;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"target", 1, 0, 't'},
        {"defop", 1, 0, 'o'},
        {"test", 1, 0, 'e'},
        {"error", 1, 0, 'E'},
        {"config", 2, 0, 'c'},
        {"url", 1, 0, 'u'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:o:E:r:c::u:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_editconfig_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            /* validate argument */
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid target datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'o':
            if (!strcmp(optarg, "merge")) {
                op = NC_RPC_EDIT_DFLTOP_MERGE;
            } else if (!strcmp(optarg, "replace")) {
                op = NC_RPC_EDIT_DFLTOP_REPLACE;
            } else if (!strcmp(optarg, "none")) {
                op = NC_RPC_EDIT_DFLTOP_NONE;
            } else {
                ERROR(__func__, "Invalid default operation specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'e':
            if (!strcmp(optarg, "set")) {
                test = NC_RPC_EDIT_TESTOPT_SET;
            } else if (!strcmp(optarg, "test-only")) {
                test = NC_RPC_EDIT_TESTOPT_TEST;
            } else if (!strcmp(optarg, "test-then-set")) {
                test = NC_RPC_EDIT_TESTOPT_TESTSET;
            } else {
                ERROR(__func__, "Invalid test option specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'E':
            if (!strcmp(optarg, "stop")) {
                err = NC_RPC_EDIT_ERROPT_STOP;
            } else if (!strcmp(optarg, "continue")) {
                err = NC_RPC_EDIT_ERROPT_CONTINUE;
            } else if (!strcmp(optarg, "rollback")) {
                err = NC_RPC_EDIT_ERROPT_ROLLBACK;
            } else {
                ERROR(__func__, "Invalid error option specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'c':
            /* check if -u was not used */
            if (content_param) {
                ERROR(__func__, "Mixing --url and --config parameters is not allowed.");
                goto fail;
            }

            content_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                content = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'u':
            /* check if -c was not used */
            if (content_param) {
                ERROR(__func__, "Mixing --url and --config parameters is not allowed.");
                goto fail;
            }

            content_param = 1;

            content = strdup(optarg);
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_editconfig_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_editconfig_help();
        goto fail;
    }

    if (!target || !content_param) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_editconfig_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (!content) {
        /* let user write edit data interactively */
        content = readinput("Type the content of the <edit-config>.", *tmp_config_file, tmp_config_file);
        if (!content) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    /* trim top-level element if needed */
    cont_start = trim_top_elem(content, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
    if (!cont_start) {
        ERROR(__func__, "Provided configuration content is invalid.");
        goto fail;
    }

    rpc = nc_rpc_edit(target, op, test, err, cont_start, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    free(content);
    return ret;
}

static int
cmd_get(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"defaults", 1, 0, 'd'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs::x:d:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_get_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 's':
            /* check if -x was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
            /* check if -s was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'd':
            if (!strcmp(optarg, "report-all")) {
                wd = NC_WD_ALL;
            } else if (!strcmp(optarg, "report-all-tagged")) {
                wd = NC_WD_ALL_TAG;
            } else if (!strcmp(optarg, "trim")) {
                wd = NC_WD_TRIM;
            } else if (!strcmp(optarg, "explicit")) {
                wd = NC_WD_EXPLICIT;
            } else {
                ERROR(__func__, "Unknown with-defaults mode \"%s\".", optarg);
                goto fail;
            }
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_get_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_get_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_get_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_get(filter, wd, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    if (output) {
        ret = cli_send_recv(rpc, output, wd, timeout);
    } else {
        ret = cli_send_recv(rpc, stdout, wd, timeout);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    free(filter);
    return ret;
}

static int
cmd_getconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    NC_DATASTORE source = NC_DATASTORE_ERROR;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"source", 1, 0, 'u'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"defaults", 1, 0, 'd'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hu:s::x:d:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_getconfig_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'u':
            if (!strcmp(optarg, "running")) {
                source = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                source = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                source = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 's':
            /* check if -x was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
            /* check if -s was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'd':
            if (!strcmp(optarg, "report-all")) {
                wd = NC_WD_ALL;
            } else if (!strcmp(optarg, "report-all-tagged")) {
                wd = NC_WD_ALL_TAG;
            } else if (!strcmp(optarg, "trim")) {
                wd = NC_WD_TRIM;
            } else if (!strcmp(optarg, "explicit")) {
                wd = NC_WD_EXPLICIT;
            } else {
                ERROR(__func__, "Unknown with-defaults mode \"%s\".", optarg);
                goto fail;
            }
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_getconfig_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_getconfig_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_getconfig_help();
        goto fail;
    }

    if (!source) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_getconfig_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_getconfig(source, filter, wd, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    if (output) {
        ret = cli_send_recv(rpc, output, wd, timeout);
    } else {
        ret = cli_send_recv(rpc, stdout, wd, timeout);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    free(filter);
    return ret;
}

static int
cmd_killsession(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    uint32_t sid = 0;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"sid", 1, 0, 's'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_killsession_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 's':
            sid = atoi(optarg);
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_killsession_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_killsession_help();
        goto fail;
    }

    if (!sid) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_killsession_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    if (!sid) {
        ERROR(__func__, "Session ID was not specififed or not a number.");
        goto fail;
    }

    rpc = nc_rpc_kill(sid);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_lock(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"target", 1, 0, 't'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_lock_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_lock_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_lock_help();
        goto fail;
    }

    if (!target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_lock_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_lock(target);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_unlock(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"target", 1, 0, 't'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_unlock_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_unlock_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_unlock_help();
        goto fail;
    }

    if (!target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_unlock_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_unlock(target);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

static int
cmd_validate(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *src = NULL, *config_m = NULL, *src_start;
    NC_DATASTORE source = NC_DATASTORE_ERROR;
    struct nc_rpc *rpc;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"source", 1, 0, 's'},
        {"src-config", 2, 0, 'c'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs:c::r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_validate_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 's':
            /* check if -c was not used */
            if (source != NC_DATASTORE_ERROR) {
                ERROR(__func__, "Mixing --source, and --src-config parameters is not allowed.");
                goto fail;
            }

            /* validate argument */
            if (!strcmp(optarg, "running")) {
                source = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                source = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                source = NC_DATASTORE_CANDIDATE;
            } else if (!strncmp(optarg, "url:", 4)) {
                source = NC_DATASTORE_URL;
                src = strdup(&(optarg[4]));
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'c':
            /* check if -s was not used */
            if (source != NC_DATASTORE_ERROR) {
                ERROR(__func__, "Mixing --source and --src-config parameters is not allowed.");
                goto fail;
            }

            source = NC_DATASTORE_CONFIG;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                src = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_validate_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_validate_help();
        goto fail;
    }

    if (!source) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_validate_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if ((source == NC_DATASTORE_CONFIG) && !src) {
        /* let user write edit data interactively */
        src = readinput("Type the content of a configuration datastore.", *tmp_config_file, tmp_config_file);
        if (!src) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    /* trim top-level element if needed */
    if (src) {
        src_start = trim_top_elem(src, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
        if (!src_start) {
            ERROR(__func__, "Provided configuration content is invalid.");
            goto fail;
        }
    } else {
        src_start = NULL;
    }

    /* create requests */
    rpc = nc_rpc_validate(source, src_start, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    free(src);
    return ret;
}

static int
cmd_subscribe(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *start = NULL, *stop = NULL;
    const char *stream = NULL;
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"begin", 1, 0, 'b'},
        {"end", 1, 0, 'e'},
        {"stream", 1, 0, 't'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs::x:b:e:t:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_subscribe_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 's':
            /* check if -x was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
            /* check if -s was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'b':
        case 'e':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }

            if (c == 'b') {
                if (t > time(NULL)) {
                    /* begin time is in future */
                    ERROR(__func__, "Begin time cannot be set to future.");
                    goto fail;
                }
                ly_time_time2str(t, NULL, &start);
            } else { /* c == 'e' */
                ly_time_time2str(t, NULL, &stop);
            }
            break;
        case 't':
            stream = optarg;
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_subscribe_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_subscribe_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_subscribe_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_subscribe(stream, filter, start, stop, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    /* create notification thread so that notifications can immediately be received */
    if (!output) {
        output = stdout;
    }
    ret = nc_recv_notif_dispatch_data(session, cli_ntf_clb, output, cli_ntf_free_data);
    if (ret) {
        ERROR(__func__, "Failed to create notification thread.");
        goto fail;
    }
    output = NULL;

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

    if (!nc_session_cpblt(session, NC_CAP_INTERLEAVE_ID)) {
        fprintf(output, "NETCONF server does not support interleave, you\n"
                "cannot issue any RPCs during the subscription.\n"
                "Close the session with \"disconnect\".\n");
        interleave = 0;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(start);
    free(stop);
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_getschema(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    const char *model = NULL, *version = NULL, *format = NULL;
    struct nc_rpc *rpc;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"model", 1, 0, 'm'},
        {"version", 1, 0, 'v'},
        {"format", 1, 0, 'f'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hm:v:f:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_getschema_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'm':
            model = optarg;
            break;
        case 'v':
            version = optarg;
            break;
        case 'f':
            format = optarg;
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_getschema_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_getschema_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_getschema_help();
        goto fail;
    }

    if (!model) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_getschema_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    rpc = nc_rpc_getschema(model, version, format, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    if (output) {
        ret = cli_send_recv(rpc, output, 0, timeout);
    } else {
        ret = cli_send_recv(rpc, stdout, 0, timeout);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    return ret;
}

static int
cmd_getdata(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE;
    int filter_param = 0, origin_count = 0, negated_origin = 0, depth = 0, with_origin = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *datastore = NULL, *config = NULL, **origin = NULL, *ptr;
    struct nc_rpc *rpc;
    NC_WD_MODE wd = NC_WD_UNKNOWN;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"datastore", 1, 0, 'd'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"config", 1, 0, 'c'},
        {"origin", 1, 0, 'O'},
        {"negated-origin", 0, 0, 'n'},
        {"depth", 1, 0, 'e'},
        {"with-origin", 0, 0, 'w'},
        {"defaults", 1, 0, 'f'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hd:s::x:c:O:ne:wf:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_getdata_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'd':
            if (datastore) {
                ERROR(__func__, "Datastore was already specified.");
                goto fail;
            }

            if (!strcmp(optarg, "running")) {
                datastore = "ietf-datastores:running";
            } else if (!strcmp(optarg, "startup")) {
                datastore = "ietf-datastores:startup";
            } else if (!strcmp(optarg, "candidate")) {
                datastore = "ietf-datastores:candidate";
            } else if (!strcmp(optarg, "operational")) {
                datastore = "ietf-datastores:operational";
            } else {
                ERROR(__func__, "Invalid datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 's':
            /* check if -x was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
            /* check if -s was not used */
            if (filter_param) {
                ERROR(__func__, "Mixing --filter-subtree, and --filter-xpath parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'c':
            if (config) {
                ERROR(__func__, "Config filter was already specified.");
                goto fail;
            }

            if (!strcmp(optarg, "true") || !strcmp(optarg, "false")) {
                config = optarg;
            } else {
                ERROR(__func__, "Invalid config filter specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'O':
            origin = realloc(origin, (origin_count + 1) * sizeof *origin);
            if (asprintf(&origin[origin_count], "ietf-origin:%s", optarg) == -1) {
                goto fail;
            }
            ++origin_count;
            break;
        case 'n':
            negated_origin = 1;
            break;
        case 'e':
            depth = strtoul(optarg, &ptr, 10);
            if (ptr[0]) {
                ERROR(__func__, "Invalid depth specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'w':
            with_origin = 1;
            break;
        case 'f':
            if (!strcmp(optarg, "report-all")) {
                wd = NC_WD_ALL;
            } else if (!strcmp(optarg, "report-all-tagged")) {
                wd = NC_WD_ALL_TAG;
            } else if (!strcmp(optarg, "trim")) {
                wd = NC_WD_TRIM;
            } else if (!strcmp(optarg, "explicit")) {
                wd = NC_WD_EXPLICIT;
            } else {
                ERROR(__func__, "Unknown with-defaults mode \"%s\".", optarg);
                goto fail;
            }
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_getconfig_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_getdata_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_getdata_help();
        goto fail;
    }

    if (!datastore) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_getdata_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_getdata(datastore, filter, config, origin, origin_count, negated_origin, depth, with_origin, wd,
            NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    if (output) {
        ret = cli_send_recv(rpc, output, wd, timeout);
    } else {
        ret = cli_send_recv(rpc, stdout, wd, timeout);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    free(filter);
    for (c = 0; c < origin_count; ++c) {
        free(origin[c]);
    }
    free(origin);
    return ret;
}

static int
cmd_editdata(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, content_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *content = NULL, *config_m = NULL, *cont_start;
    const char *datastore = NULL;
    struct nc_rpc *rpc;
    NC_RPC_EDIT_DFLTOP op = NC_RPC_EDIT_DFLTOP_UNKNOWN;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"datastore", 1, 0, 'd'},
        {"defop", 1, 0, 'o'},
        {"config", 2, 0, 'c'},
        {"url", 1, 0, 'u'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hd:o:c::u:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_editdata_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'd':
            if (datastore) {
                ERROR(__func__, "Datastore was already specified.");
                goto fail;
            }

            if (!strcmp(optarg, "running")) {
                datastore = "ietf-datastores:running";
            } else if (!strcmp(optarg, "startup")) {
                datastore = "ietf-datastores:startup";
            } else if (!strcmp(optarg, "candidate")) {
                datastore = "ietf-datastores:candidate";
            } else if (!strcmp(optarg, "operational")) {
                datastore = "ietf-datastores:operational";
            } else {
                ERROR(__func__, "Invalid datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'o':
            if (!strcmp(optarg, "merge")) {
                op = NC_RPC_EDIT_DFLTOP_MERGE;
            } else if (!strcmp(optarg, "replace")) {
                op = NC_RPC_EDIT_DFLTOP_REPLACE;
            } else if (!strcmp(optarg, "none")) {
                op = NC_RPC_EDIT_DFLTOP_NONE;
            } else {
                ERROR(__func__, "Invalid default operation specified (%s).", optarg);
                goto fail;
            }
            break;
        case 'c':
            /* check if -u was not used */
            if (content_param) {
                ERROR(__func__, "Mixing --url and --config parameters is not allowed.");
                goto fail;
            }

            content_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                content = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'u':
            /* check if -c was not used */
            if (content_param) {
                ERROR(__func__, "Mixing --url and --config parameters is not allowed.");
                goto fail;
            }

            content_param = 1;

            content = strdup(optarg);
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_editdata_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_editdata_help();
        goto fail;
    }

    if (!datastore || !content_param) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_editdata_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (!content) {
        /* let user write edit data interactively */
        content = readinput("Type the content of the <edit-data>.", *tmp_config_file, tmp_config_file);
        if (!content) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    /* trim top-level element if needed */
    cont_start = trim_top_elem(content, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
    if (!cont_start) {
        ERROR(__func__, "Provided configuration content is invalid.");
        goto fail;
    }

    rpc = nc_rpc_editdata(datastore, op, cont_start, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    free(content);
    return ret;
}

static int
cmd_establishsub(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *start = NULL, *stop = NULL;
    const char *stream = NULL, *encoding = NULL;
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"stream", 1, 0, 't'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"filter-ref", 1, 0, 'f'},
        {"begin", 1, 0, 'b'},
        {"end", 1, 0, 'e'},
        {"encoding", 1, 0, 'n'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:s::x:f:b:e:n:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_establishsub_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 't':
            stream = optarg;
            break;
        case 's':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
        case 'f':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'b':
        case 'e':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }

            if (c == 'b') {
                if (t > time(NULL)) {
                    /* begin time is in future */
                    ERROR(__func__, "Begin time cannot be set to future.");
                    goto fail;
                }
                ly_time_time2str(t, NULL, &start);
            } else { /* c == 'e' */
                ly_time_time2str(t, NULL, &stop);
            }
            break;
        case 'n':
            encoding = optarg;
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_establishsub_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_establishsub_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_establishsub_help();
        goto fail;
    }

    if (!stream) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_establishsub_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_establishsub(filter, stream, start, stop, encoding, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    /* create notification thread so that notifications can immediately be received */
    if (!output) {
        output = stdout;
    }
    ret = nc_recv_notif_dispatch_data(session, cli_ntf_clb, output, cli_ntf_free_data);
    if (ret) {
        ERROR(__func__, "Failed to create notification thread.");
        goto fail;
    }
    output = NULL;

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(start);
    free(stop);
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_modifysub(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *stop = NULL;
    struct nc_rpc *rpc = NULL;
    time_t t;
    uint32_t id = 0;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"filter-ref", 1, 0, 'f'},
        {"end", 1, 0, 'e'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hi:s::x:f:e:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_modifysub_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            id = atoi(optarg);
            break;
        case 's':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
        case 'f':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'e':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }

            ly_time_time2str(t, NULL, &stop);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_modifysub_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_modifysub_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_modifysub_help();
        goto fail;
    }

    if (!id) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_modifysub_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_modifysub(id, filter, stop, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(stop);
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_deletesub(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct nc_rpc *rpc = NULL;
    uint32_t id = 0;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hi:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_deletesub_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            id = atoi(optarg);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_deletesub_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_deletesub_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_deletesub_help();
        goto fail;
    }

    if (!id) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_deletesub_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_deletesub(id);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_killsub(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct nc_rpc *rpc = NULL;
    uint32_t id = 0;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hi:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_killsub_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            id = atoi(optarg);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_killsub_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_killsub_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_killsub_help();
        goto fail;
    }

    if (!id) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_killsub_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_killsub(id);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_establishpush(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    int periodic = -1, sync_on_start = 1;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *stop = NULL, *anchor = NULL, **excluded_change = NULL;
    const char *encoding = NULL, *datastore = NULL;
    uint32_t i, period = 0, damp_period = 0;
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"datastore", 1, 0, 'd'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"filter-ref", 1, 0, 'f'},
        {"end", 1, 0, 'e'},
        {"encoding", 1, 0, 'n'},
        {"periodic", 0, 0, 'p'},
        {"period", 1, 0, 'i'},
        {"anchor-time", 1, 0, 'a'},
        {"on-change", 0, 0, 'c'},
        {"dampening-period", 1, 0, 'm'},
        {"no-sync-on-start", 0, 0, 'y'},
        {"excluded-change", 1, 0, 'l'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hd:s::x:f:e:n:pi:a:cm:yl:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_establishpush_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'd':
            if (datastore) {
                ERROR(__func__, "Datastore was already specified.");
                goto fail;
            }

            if (!strcmp(optarg, "running")) {
                datastore = "ietf-datastores:running";
            } else if (!strcmp(optarg, "startup")) {
                datastore = "ietf-datastores:startup";
            } else if (!strcmp(optarg, "candidate")) {
                datastore = "ietf-datastores:candidate";
            } else if (!strcmp(optarg, "operational")) {
                datastore = "ietf-datastores:operational";
            } else {
                ERROR(__func__, "Invalid datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 's':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
        case 'f':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'e':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }
            ly_time_time2str(t, NULL, &stop);
            break;
        case 'n':
            encoding = optarg;
            break;
        case 'p':
            if (periodic != -1) {
                ERROR(__func__, "Cannot mix \"periodic\" and \"on-change\" options.");
                cmd_establishpush_help();
                goto fail;
            }
            periodic = 1;
            break;
        case 'i':
            period = atoi(optarg);
            break;
        case 'a':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }
            ly_time_time2str(t, NULL, &anchor);
            break;
        case 'c':
            if (periodic != -1) {
                ERROR(__func__, "Cannot mix \"periodic\" and \"on-change\" options.");
                cmd_establishpush_help();
                goto fail;
            }
            periodic = 0;
            break;
        case 'm':
            damp_period = atoi(optarg);
            break;
        case 'y':
            sync_on_start = 0;
            break;
        case 'l':
            if (excluded_change) {
                for (i = 0; excluded_change[i]; ++i) {}
            } else {
                i = 0;
            }
            excluded_change = realloc(excluded_change, (i + 2) * sizeof *excluded_change);
            excluded_change[i] = optarg;
            excluded_change[i + 1] = NULL;
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_establishpush_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_establishpush_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_establishpush_help();
        goto fail;
    }

    if (!datastore || (periodic == -1) || (periodic && !period)) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_establishpush_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create request */
    if (periodic) {
        rpc = nc_rpc_establishpush_periodic(datastore, filter, stop, encoding, period, anchor, NC_PARAMTYPE_CONST);
    } else {
        rpc = nc_rpc_establishpush_onchange(datastore, filter, stop, encoding, damp_period, sync_on_start,
                (const char **)excluded_change, NC_PARAMTYPE_CONST);
    }
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    /* create notification thread so that notifications can immediately be received */
    if (!nc_session_ntf_thread_running(session)) {
        if (!output) {
            output = stdout;
        }
        nc_session_set_data(session, output);
        ret = nc_recv_notif_dispatch(session, cli_ntf_clb);
        if (ret) {
            ERROR(__func__, "Failed to create notification thread.");
            goto fail;
        }
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(stop);
    free(anchor);
    free(excluded_change);
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_modifypush(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0, timeout = CLI_RPC_REPLY_TIMEOUT;
    int periodic = -1;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *stop = NULL, *anchor = NULL, **excluded_change = NULL;
    const char *datastore = NULL;
    uint32_t id = 0, period = 0, damp_period = 0;
    struct nc_rpc *rpc = NULL;
    time_t t;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'I'},
        {"datastore", 1, 0, 'd'},
        {"filter-subtree", 2, 0, 's'},
        {"filter-xpath", 1, 0, 'x'},
        {"filter-ref", 1, 0, 'f'},
        {"end", 1, 0, 'e'},
        {"periodic", 0, 0, 'p'},
        {"period", 1, 0, 'i'},
        {"anchor-time", 1, 0, 'a'},
        {"on-change", 0, 0, 'c'},
        {"dampening-period", 1, 0, 'm'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hI:d:s::x:f:e:pi:a:cm:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_modifypush_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'I':
            id = atoi(optarg);
            break;
        case 'd':
            if (datastore) {
                ERROR(__func__, "Datastore was already specified.");
                goto fail;
            }

            if (!strcmp(optarg, "running")) {
                datastore = "ietf-datastores:running";
            } else if (!strcmp(optarg, "startup")) {
                datastore = "ietf-datastores:startup";
            } else if (!strcmp(optarg, "candidate")) {
                datastore = "ietf-datastores:candidate";
            } else if (!strcmp(optarg, "operational")) {
                datastore = "ietf-datastores:operational";
            } else {
                ERROR(__func__, "Invalid datastore specified (%s).", optarg);
                goto fail;
            }
            break;
        case 's':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            if (optarg) {
                /* open edit configuration data from the file */
                config_fd = open(optarg, O_RDONLY);
                if (config_fd == -1) {
                    ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                    goto fail;
                }

                /* map content of the file into the memory */
                if (fstat(config_fd, &config_stat) != 0) {
                    ERROR(__func__, "fstat failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }
                config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
                if (config_m == MAP_FAILED) {
                    ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                    close(config_fd);
                    goto fail;
                }

                /* make a copy of the content to allow closing the file */
                filter = strdup(config_m);

                /* unmap local datastore file and close it */
                munmap(config_m, config_stat.st_size);
                close(config_fd);
            }
            break;
        case 'x':
        case 'f':
            if (filter_param) {
                ERROR(__func__, "Mixing filter parameters is not allowed.");
                goto fail;
            }

            filter_param = 1;

            filter = strdup(optarg);
            break;
        case 'e':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }
            ly_time_time2str(t, NULL, &stop);
            break;
        case 'p':
            if (periodic != -1) {
                ERROR(__func__, "Cannot mix \"periodic\" and \"on-change\" options.");
                cmd_modifypush_help();
                goto fail;
            }
            periodic = 1;
            break;
        case 'i':
            period = atoi(optarg);
            break;
        case 'a':
            if ((optarg[0] == '-') || (optarg[0] == '+')) {
                t = time(NULL);
                t += atol(optarg);
            } else {
                t = atol(optarg);
            }
            ly_time_time2str(t, NULL, &anchor);
            break;
        case 'c':
            if (periodic != -1) {
                ERROR(__func__, "Cannot mix \"periodic\" and \"on-change\" options.");
                cmd_modifypush_help();
                goto fail;
            }
            periodic = 0;
            break;
        case 'm':
            damp_period = atoi(optarg);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_modifypush_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_modifypush_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_modifypush_help();
        goto fail;
    }

    if (!id || !datastore || (periodic == -1) || (periodic && !period)) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_modifypush_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (filter_param && !filter) {
        /* let user write edit data interactively */
        filter = readinput("Type the content of the subtree filter.", *tmp_config_file, tmp_config_file);
        if (!filter) {
            ERROR(__func__, "Reading filter data failed.");
            goto fail;
        }
    }

    /* create request */
    if (periodic) {
        rpc = nc_rpc_modifypush_periodic(id, datastore, filter, stop, period, anchor, NC_PARAMTYPE_CONST);
    } else {
        rpc = nc_rpc_modifypush_onchange(id, datastore, filter, stop, damp_period, NC_PARAMTYPE_CONST);
    }
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    /* create notification thread so that notifications can immediately be received */
    if (!nc_session_ntf_thread_running(session)) {
        if (!output) {
            output = stdout;
        }
        nc_session_set_data(session, output);
        ret = nc_recv_notif_dispatch(session, cli_ntf_clb);
        if (ret) {
            ERROR(__func__, "Failed to create notification thread.");
            goto fail;
        }
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    free(filter);
    free(stop);
    free(anchor);
    free(excluded_change);
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_resyncsub(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct nc_rpc *rpc = NULL;
    uint32_t id = 0;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hi:o:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_resyncsub_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            id = atoi(optarg);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_resyncsub_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_resyncsub_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_resyncsub_help();
        goto fail;
    }

    if (!id) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_resyncsub_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    /* create request */
    rpc = nc_rpc_resyncsub(id);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0, timeout);
    if (ret) {
        goto fail;
    }

fail:
    clear_arglist(&cmd);
    if (output && (output != stdout)) {
        fclose(output);
    }
    nc_rpc_free(rpc);

    return ret;
}

static int
cmd_userrpc(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, timeout = CLI_RPC_REPLY_TIMEOUT;
    struct stat config_stat;
    char *content = NULL, *config_m = NULL;
    struct nc_rpc *rpc;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"content", 1, 0, 'c'},
        {"out", 1, 0, 'o'},
        {"rpc-timeout", 1, 0, 'r'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:s:c::d:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_userrpc_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'c':
            if (content) {
                ERROR(__func__, "Duplicated \"content\" option.");
                cmd_userrpc_help();
                goto fail;
            }
            /* open edit configuration data from the file */
            config_fd = open(optarg, O_RDONLY);
            if (config_fd == -1) {
                ERROR(__func__, "Unable to open the local datastore file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }

            /* map content of the file into the memory */
            if (fstat(config_fd, &config_stat) != 0) {
                ERROR(__func__, "fstat failed (%s).", strerror(errno));
                close(config_fd);
                goto fail;
            }
            config_m = mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
            if (config_m == MAP_FAILED) {
                ERROR(__func__, "mmap of the local datastore file failed (%s).", strerror(errno));
                close(config_fd);
                goto fail;
            }

            /* make a copy of the content to allow closing the file */
            content = strdup(config_m);

            /* unmap local datastore file and close it */
            munmap(config_m, config_stat.st_size);
            close(config_fd);
            break;
        case 'o':
            if (output) {
                ERROR(__func__, "Duplicated \"out\" option.");
                cmd_userrpc_help();
                goto fail;
            }
            output = fopen(optarg, "w");
            if (!output) {
                ERROR(__func__, "Failed to open file \"%s\" (%s).", optarg, strerror(errno));
                goto fail;
            }
            break;
        case 'r':
            timeout = atoi(optarg);
            if (!timeout) {
                ERROR(__func__, "Invalid timeout \"%s\".", optarg);
                goto fail;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_userrpc_help();
            goto fail;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_userrpc_help();
        goto fail;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        goto fail;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        goto fail;
    }

    /* check if edit configuration data were specified */
    if (!content) {
        /* let user write edit data interactively */
        content = readinput("Type the content of a configuration datastore.", *tmp_config_file, tmp_config_file);
        if (!content) {
            ERROR(__func__, "Reading configuration data failed.");
            goto fail;
        }
    }

    /* create requests */
    rpc = nc_rpc_act_generic_xml(content, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    if (output) {
        ret = cli_send_recv(rpc, output, 0, timeout);
    } else {
        ret = cli_send_recv(rpc, stdout, 0, timeout);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    free(content);
    return ret;
}

static int
cmd_timed(const char *arg, char **UNUSED(tmp_config_file))
{
    char *args = strdupa(arg);
    char *cmd = NULL;

    strtok(args, " ");
    if ((cmd = strtok(NULL, " ")) == NULL) {
        fprintf(stdout, "All commands will %sbe timed.\n", timed ? "" : "not ");
    } else {
        if (!strcmp(cmd, "on")) {
            timed = 1;
        } else if (!strcmp(cmd, "off")) {
            timed = 0;
        } else {
            ERROR(__func__, "Unknown option %s.", cmd);
            cmd_timed_help();
        }
    }

    return 0;
}

COMMAND commands[] = {
#ifdef NC_ENABLED_SSH
    {"auth", cmd_auth, cmd_auth_help, "Manage SSH authentication options"},
#endif
    {"cancel-commit", cmd_cancelcommit, cmd_cancelcommit_help, "ietf-netconf <cancel-commit> operation"},
#ifdef NC_ENABLED_TLS
    {"cert", cmd_cert, cmd_cert_help, "Manage trusted or your own certificates"},
#endif
    {"commit", cmd_commit, cmd_commit_help, "ietf-netconf <commit> operation"},
    {"connect", cmd_connect, cmd_connect_help, "Connect to a NETCONF server"},
    {"copy-config", cmd_copyconfig, cmd_copyconfig_help, "ietf-netconf <copy-config> operation"},
#ifdef NC_ENABLED_TLS
    {"crl", cmd_crl, cmd_crl_help, "Manage Certificate Revocation List directory"},
#endif
    {"delete-config", cmd_deleteconfig, cmd_deleteconfig_help, "ietf-netconf <delete-config> operation"},
    {"delete-sub", cmd_deletesub, cmd_deletesub_help, "ietf-subscribed-notifications <delete-subscription> operation"},
    {"discard-changes", cmd_discardchanges, cmd_discardchanges_help, "ietf-netconf <discard-changes> operation"},
    {"disconnect", cmd_disconnect, NULL, "Disconnect from a NETCONF server"},
    {"edit-config", cmd_editconfig, cmd_editconfig_help, "ietf-netconf <edit-config> operation"},
    {"edit-data", cmd_editdata, cmd_editdata_help, "ietf-netconf-nmda <edit-data> operation"},
    {"editor", cmd_editor, cmd_editor_help, "Set the text editor for working with XML data"},
    {"establish-push", cmd_establishpush, cmd_establishpush_help,
        "ietf-subscribed-notifications <establish-subscription> operation with ietf-yang-push augments"},
    {"establish-sub", cmd_establishsub, cmd_establishsub_help,
        "ietf-subscribed-notifications <establish-subscription> operation"},
    {"exit", cmd_quit, NULL, "Quit the program"},
    {"get", cmd_get, cmd_get_help, "ietf-netconf <get> operation"},
    {"get-config", cmd_getconfig, cmd_getconfig_help, "ietf-netconf <get-config> operation"},
    {"get-data", cmd_getdata, cmd_getdata_help, "ietf-netconf-nmda <get-data> operation"},
    {"get-schema", cmd_getschema, cmd_getschema_help, "ietf-netconf-monitoring <get-schema> operation"},
    {"help", cmd_help, NULL, "Display commands description"},
    {"kill-session", cmd_killsession, cmd_killsession_help, "ietf-netconf <kill-session> operation"},
    {"kill-sub", cmd_killsub, cmd_killsub_help, "ietf-subscribed-notifications <kill-subscription> operation"},
#ifdef NC_ENABLED_SSH
    {"knownhosts", cmd_knownhosts, cmd_knownhosts_help, "Manage the user knownhosts file"},
#endif
    {"listen", cmd_listen, cmd_listen_help, "Wait for a Call Home connection from a NETCONF server"},
    {"lock", cmd_lock, cmd_lock_help, "ietf-netconf <lock> operation"},
    {"modify-push", cmd_modifypush, cmd_modifypush_help,
        "ietf-subscribed-notifications <modify-subscription> operation with ietf-yang-push augments"},
    {"modify-sub", cmd_modifysub, cmd_modifysub_help, "ietf-subscribed-notifications <modify-subscription> operation"},
    {"outputformat", cmd_outputformat, cmd_outputformat_help, "Set the output format of all the data"},
    {"resync-sub", cmd_resyncsub, cmd_resyncsub_help, "ietf-yang-push <resync-subscription> operation"},
    {"searchpath", cmd_searchpath, cmd_searchpath_help, "Set the search path for models"},
    {"status", cmd_status, NULL, "Display information about the current NETCONF session"},
    {"subscribe", cmd_subscribe, cmd_subscribe_help, "notifications <create-subscription> operation"},
    {"timed", cmd_timed, cmd_timed_help, "Time all the commands (that communicate with a server) from issuing an RPC"
        " to getting a reply"},
    {"unlock", cmd_unlock, cmd_unlock_help, "ietf-netconf <unlock> operation"},
    {"user-rpc", cmd_userrpc, cmd_userrpc_help, "Send your own content in an RPC envelope"},
    {"validate", cmd_validate, cmd_validate_help, "ietf-netconf <validate> operation"},
    {"verb", cmd_verb, cmd_verb_help, "Change verbosity"},
    {"version", cmd_version, NULL, "Print Netopeer2 CLI version"},

    /* synonyms for previous commands */
    {"?", cmd_help, NULL, "Display commands description"},
    {"quit", cmd_quit, NULL, "Quit the program"},
    {NULL, NULL, NULL, NULL}
};
