/**
 * @file commands.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli commands
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <pwd.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>

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
#include "configuration.h"
#include "completion.h"

#define CLI_CH_TIMEOUT 60 /* 1 minute */

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

COMMAND commands[];
extern int done;
LYD_FORMAT output_format = LYD_XML;
int output_flag = LYP_FORMAT;
char *config_editor;
struct nc_session *session;
volatile pthread_t ntf_tid;
volatile int interleave;
int timed;

int cmd_disconnect(const char *arg, char **tmp_config_file);

struct arglist {
    char** list;
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
cli_ntf_clb(struct nc_session *session, const struct nc_notif *notif)
{
    FILE *output = nc_session_get_data(session);
    int was_rawmode;

    if (output == stdout) {
        if (ls.rawmode) {
            was_rawmode = 1;
            linenoiseDisableRawMode(ls.ifd);
            printf("\n");
        } else {
            was_rawmode = 0;
        }
    }

    fprintf(output, "notification (%s)\n", notif->datetime);
    lyd_print_file(output, notif->tree, output_format, LYP_WITHSIBLINGS | output_flag);
    fprintf(output, "\n");
    fflush(output);

    if ((output == stdout) && was_rawmode) {
        linenoiseEnableRawMode(ls.ifd);
        linenoiseRefreshLine();
    }

    if (!strcmp(notif->tree->schema->name, "notificationComplete")
            && !strcmp(notif->tree->schema->module->name, "nc-notifications")) {
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
#elif defined(CLOCK_MONOTONIC)
    *mono = 1;
    return clock_gettime(CLOCK_MONOTONIC, ts);
#elif defined(CLOCK_REALTIME)
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

    return (nsec_diff ? nsec_diff / 1000000L : 0);
}

static int
cli_send_recv(struct nc_rpc *rpc, FILE *output, NC_WD_MODE wd_mode)
{
    char *str, *model_data;
    int ret = 0, ly_wd, mono;
    int32_t msec;
    uint16_t i, j;
    uint64_t msgid;
    struct lyd_node_anydata *any;
    NC_MSG_TYPE msgtype;
    struct nc_reply *reply;
    struct nc_reply_data *data_rpl;
    struct nc_reply_error *error;
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
    msgtype = nc_recv_reply(session, rpc, msgid, 20000,
                            LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS, &reply);
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
        nc_reply_free(reply);
        goto recv_reply;
    }

    if (timed) {
        ret = cli_gettimespec(&ts_stop, &mono);
        if (ret) {
            ERROR(__func__, "Getting current time failed (%s).", strerror(errno));
            nc_reply_free(reply);
            return ret;
        }
    }

    switch (reply->type) {
    case NC_RPL_OK:
        fprintf(output, "OK\n");
        break;
    case NC_RPL_DATA:
        data_rpl = (struct nc_reply_data *)reply;

        /* special case */
        if (nc_rpc_get_type(rpc) == NC_RPC_GETSCHEMA) {
            if ((data_rpl->data->schema->nodetype != LYS_RPC) ||
                (data_rpl->data->child == NULL) ||
                (data_rpl->data->child->schema->nodetype != LYS_ANYXML)) {
                ERROR(__func__, "Unexpected data reply to <get-schema> RPC.");
                ret = -1;
                break;
            }
            if (output == stdout) {
                fprintf(output, "MODULE\n");
            }
            any = (struct lyd_node_anydata *)data_rpl->data->child;
            switch (any->value_type) {
            case LYD_ANYDATA_CONSTSTRING:
            case LYD_ANYDATA_STRING:
                fputs(any->value.str, output);
                break;
            case LYD_ANYDATA_DATATREE:
                lyd_print_mem(&model_data, any->value.tree, LYD_XML, LYP_FORMAT | LYP_WITHSIBLINGS);
                fputs(model_data, output);
                free(model_data);
                break;
            case LYD_ANYDATA_XML:
                lyxml_print_mem(&model_data, any->value.xml, LYXML_PRINT_SIBLINGS);
                fputs(model_data, output);
                free(model_data);
                break;
            default:
                /* none of the others can appear here */
                ERROR(__func__, "Unexpected anydata value format.");
                ret = -1;
                break;
            }
            if (ret == -1) {
                break;
            }

            if (output == stdout) {
                fprintf(output, "\n");
            }
            break;
        }

        if (output == stdout) {
            fprintf(output, "DATA\n");
        } else {
            switch (nc_rpc_get_type(rpc)) {
            case NC_RPC_GETCONFIG:
                fprintf(output, "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n");
                break;
            case NC_RPC_GET:
                fprintf(output, "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n");
                break;
            default:
                break;
            }
        }

        switch (wd_mode) {
        case NC_WD_ALL:
            ly_wd = LYP_WD_ALL;
            break;
        case NC_WD_ALL_TAG:
            ly_wd = LYP_WD_ALL_TAG;
            break;
        case NC_WD_TRIM:
            ly_wd = LYP_WD_TRIM;
            break;
        case NC_WD_EXPLICIT:
            ly_wd = LYP_WD_EXPLICIT;
            break;
        default:
            ly_wd = 0;
            break;
        }

        lyd_print_file(output, data_rpl->data, output_format, LYP_WITHSIBLINGS | ly_wd | output_flag);
        if (output == stdout) {
            fprintf(output, "\n");
        } else {
            switch (nc_rpc_get_type(rpc)) {
            case NC_RPC_GETCONFIG:
                fprintf(output, "</config>\n");
                break;
            case NC_RPC_GET:
                fprintf(output, "</data>\n");
                break;
            default:
                break;
            }
        }
        break;
    case NC_RPL_ERROR:
        fprintf(output, "ERROR\n");
        error = (struct nc_reply_error *)reply;
        for (i = 0; i < error->count; ++i) {
            if (error->err[i].type) {
                fprintf(output, "\ttype:     %s\n", error->err[i].type);
            }
            if (error->err[i].tag) {
                fprintf(output, "\ttag:      %s\n", error->err[i].tag);
            }
            if (error->err[i].severity) {
                fprintf(output, "\tseverity: %s\n", error->err[i].severity);
            }
            if (error->err[i].apptag) {
                fprintf(output, "\tapp-tag:  %s\n", error->err[i].apptag);
            }
            if (error->err[i].path) {
                fprintf(output, "\tpath:     %s\n", error->err[i].path);
            }
            if (error->err[i].message) {
                fprintf(output, "\tmessage:  %s\n", error->err[i].message);
            }
            if (error->err[i].sid) {
                fprintf(output, "\tSID:      %s\n", error->err[i].sid);
            }
            for (j = 0; j < error->err[i].attr_count; ++j) {
                fprintf(output, "\tbad-attr #%d: %s\n", j + 1, error->err[i].attr[j]);
            }
            for (j = 0; j < error->err[i].elem_count; ++j) {
                fprintf(output, "\tbad-elem #%d: %s\n", j + 1, error->err[i].elem[j]);
            }
            for (j = 0; j < error->err[i].ns_count; ++j) {
                fprintf(output, "\tbad-ns #%d:   %s\n", j + 1, error->err[i].ns[j]);
            }
            for (j = 0; j < error->err[i].other_count; ++j) {
                lyxml_print_mem(&str, error->err[i].other[j], 0);
                fprintf(output, "\tother #%d:\n%s\n", j + 1, str);
                free(str);
            }
            fprintf(output, "\n");
        }
        ret = 1;
        break;
    default:
        ERROR(__func__, "Internal error.");
        nc_reply_free(reply);
        return -1;
    }
    nc_reply_free(reply);

    if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        ERROR(__func__, "Trying to receive another message...\n");
        goto recv_reply;
    }

    if (timed) {
        msec = cli_difftimespec(&ts_start, &ts_stop);
        fprintf(output, "%s %2dm%d,%03ds\n", mono ? "mono" : "real", msec / 60000, (msec % 60000) / 1000, msec % 1000);
    }

    return ret;
}

static char *
trim_top_elem(char *data, const char *top_elem, const char *top_elem_ns)
{
    char *ptr, *prefix = NULL, *buf;
    int pref_len, state = 0, quote;

    /* state: -2 - syntax error,
     *        -1 - top_elem not found,
     *        0 - start,
     *        1 - parsing prefix,
     *        2 - prefix just parsed,
     *        3 - top-elem found and parsed, looking for namespace,
     *        4 - top_elem and top_elem_ns found (success)
     */

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
                    if ((ptr[0] != ':') || strncmp(ptr + 1, prefix, pref_len) || (ptr[1 + pref_len] != '='))  {
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
        asprintf(&buf, "</%.*s:%s>", pref_len, prefix, top_elem);
    } else {
        asprintf(&buf, "</%s>", top_elem);
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

void
cmd_searchpath_help(void)
{
    printf("searchpath [<model-dir-path>]\n");
}

void
cmd_outputformat_help(void)
{
    printf("outputformat (xml | xml_noformat | json | json_noformat)\n");
}

void
cmd_verb_help(void)
{
    printf("verb (error/0 | warning/1 | verbose/2 | debug/3)\n");
}

void
cmd_connect_help(void)
{
#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    printf("connect [--help] [--host <hostname>] [--port <num>]\n");
    printf("    SSH [--ssh] [--login <username>]\n");
    printf("    TLS  --tls  [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#elif defined(NC_ENABLED_SSH)
    printf("connect [--help] [--ssh] [--host <hostname>] [--port <num>] [--login <username>]\n");
#elif defined(NC_ENABLED_TLS)
    printf("connect [--help] [--tls] [--host <hostname>] [--port <num>] [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#endif
}

void
cmd_listen_help(void)
{
#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    printf("listen [--help] [--timeout <sec>] [--host <hostname>] [--port <num>]\n");
    printf("   SSH [--ssh] [--login <username>]\n");
    printf("   TLS  --tls  [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#elif defined(NC_ENABLED_SSH)
    printf("listen [--help] [--ssh] [--timeout <sec>] [--host <hostname>] [--port <num>] [--login <username>]\n");
#elif defined(NC_ENABLED_TLS)
    printf("listen [--help] [--tls] [--timeout <sec>] [--host <hostname>] [--port <num>] [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>]\n");
#endif
}

void
cmd_editor_help(void)
{
    printf("editor [--help] [<path/name-of-the-editor>]\n");
}

void
cmd_cancelcommit_help(void)
{
    if (session && !nc_session_cpblt(session, NC_CAP_CONFIRMEDCOMMIT_ID)) {
        printf("cancel-commit is not supported by the current session.\n");
    } else {
        printf("cancel-commit [--help] [--persist-id <commit-id>]\n");
    }
}

void
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
    printf("commit [--help]%s\n", confirmed);
}

void
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

    printf("copy-config [--help] --target %s%s%s%s (--source %s%s%s%s | --src-config[=<file>])%s\n",
           running, startup, candidate, url,
           running, startup, candidate, url, defaults);
}

void
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

    printf("delete-config [--help] --target %s%s\n", startup, url);
}

void
cmd_discardchanges_help(void)
{
    if (!session || nc_session_cpblt(session, NC_CAP_CANDIDATE_ID)) {
        printf("discard-changes [--help]\n");
    } else {
        printf("discard-changes is not supported by the current session.\n");
    }
}

void
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
           "%s[--error stop|continue%s]\n", running, candidate, bracket, url, validate, rollback);
}

void
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

    fprintf(stdout, "get [--help] [--filter-subtree[=<file>]%s] %s[--out <file>]\n", xpath, defaults);
}

void
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

    printf("get-config [--help] --source running%s%s [--filter-subtree[=<file>]%s] %s[--out <file>]\n",
           startup, candidate, xpath, defaults);
}

void
cmd_killsession_help(void)
{
    printf("killsession [--help] --sid <sesion-ID>\n");
}

void
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

    printf("lock [--help] --target running%s%s\n", startup, candidate);
}

void
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

    printf("unlock [--help] --target running%s%s\n", startup, candidate);
}

void
cmd_validate_help(void)
{
    const char *startup, *candidate, *url;

    if (session && !nc_session_cpblt(session, NC_CAP_VALIDATE10_ID)
            && !nc_session_cpblt(session, NC_CAP_VALIDATE11_ID)) {
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
    printf("validate [--help] (--source running%s%s%s | --src-config[=<file>])\n",
           startup, candidate, url);
}

void
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

    printf("subscribe [--help] [--filter-subtree[=<file>]%s] [--begin <time>] [--end <time>] [--stream <stream>] [--out <file>]\n", xpath);
    printf("\t<time> has following format:\n");
    printf("\t\t+<num>  - current time plus the given number of seconds.\n");
    printf("\t\t<num>   - absolute time as number of seconds since 1970-01-01.\n");
    printf("\t\t-<num>  - current time minus the given number of seconds.\n");
}

void
cmd_getschema_help(void)
{
    if (session && !ly_ctx_get_module(nc_session_get_ctx(session), "ietf-netconf-monitoring", NULL, 1)) {
        printf("get-schema is not supported by the current session.\n");
        return;
    }

    printf("get-schema [--help] --model <identifier> [--version <version>] [--format <format>] [--out <file>]\n");
}

void
cmd_userrpc_help(void)
{
    printf("user-rpc [--help] [--content <file>] [--out <file>]\n");
}

void
cmd_timed_help(void)
{
    printf("timed [--help] [on | off]\n");
}

#ifdef NC_ENABLED_SSH

void
cmd_auth_help(void)
{
    printf("auth (--help | pref [(publickey | interactive | password) <preference>] | keys [add <public_key_path> <private_key_path>] [remove <key_index>])\n");
}

void
cmd_knownhosts_help(void)
{
    printf("knownhosts [--help] [--del <key_index>]\n");
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

void
cmd_cert_help(void)
{
    printf("cert [--help | display | add <cert_path> | remove <cert_name> | displayown | replaceown (<cert_path.pem> | <cert_path.crt> <key_path.key>)]\n");
}

void
cmd_crl_help(void)
{
    printf("crl [--help | display | add <crl_path> | remove <crl_name>]\n");
}

#endif /* NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

int
cmd_auth(const char *arg, char **UNUSED(tmp_config_file))
{
    int i;
    short int pref;
    char *args = strdupa(arg);
    char *cmd = NULL, *ptr = NULL, *str;
    const char *pub_key, *priv_key;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if (cmd == NULL || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
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
            if (nc_client_ssh_add_keypair(str, cmd) != EXIT_SUCCESS) {
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
            if (ptr[0] || nc_client_ssh_del_keypair(i)) {
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

int
cmd_knownhosts(const char *arg, char **UNUSED(tmp_config_file))
{
    char* ptr, *kh_file, *line = NULL, **pkeys = NULL, *text;
    int del_idx = -1, i, j, pkey_len = 0, written, text_len;
    size_t line_len;
    FILE* file;
    struct passwd* pwd;
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
            if (*ptr != '\0' || del_idx < 0) {
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

    asprintf(&kh_file, "%s/.ssh/known_hosts", pwd->pw_dir);

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
            if (ptr[0] == '|' && ptr[2] == '|') {
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
                pkeys = realloc(pkeys, pkey_len*sizeof(char*));
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

        for (i = 0, ptr = text; (i < del_idx) && ptr; ++i, ptr = strchr(ptr + 1, '\n'));

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
        if (written < ptr-text) {
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

        ftruncate(fileno(file), written);
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
                //nc_callhome_listen_stop();
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

    if (sendfile(fd_to, fd_from, NULL, from_len) < from_len) {
        goto out_error;
    }

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
    STACK_OF(GENERAL_NAME) *san_names = NULL;
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
    ASN1_TIME_print(bio_out, X509_get_notAfter(cert));
    BIO_printf(bio_out, "\n");

    has_san = 0;
    first_san = 1;
    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            san_name = sk_GENERAL_NAME_value(san_names, i);
            if (san_name->type == GEN_EMAIL || san_name->type == GEN_DNS || san_name->type == GEN_IPADD) {
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
                    BIO_printf(bio_out, "RFC822:%s", (char*) ASN1_STRING_data(san_name->d.rfc822Name));
#else
                    BIO_printf(bio_out, "RFC822:%s", (char*) ASN1_STRING_get0_data(san_name->d.rfc822Name));
#endif
                }
                if (san_name->type == GEN_DNS) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
                    BIO_printf(bio_out, "DNS:%s", (char*) ASN1_STRING_data(san_name->d.dNSName));
#else
                    BIO_printf(bio_out, "DNS:%s", (char*) ASN1_STRING_get0_data(san_name->d.dNSName));
#endif
                }
                if (san_name->type == GEN_IPADD) {
                    BIO_printf(bio_out, "IP:");
                    ip = san_name->d.iPAddress;
                    if (ip->length == 4) {
                        BIO_printf(bio_out, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
                    } else if (ip->length == 16) {
                        for (j = 0; j < ip->length; ++j) {
                            if (j > 0 && j < 15 && j%2 == 1) {
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

void
parse_crl(const char *name, const char *path)
{
    int i;
    BIO *bio_out;
    FILE *fp;
    X509_CRL *crl;
    const ASN1_INTEGER* bs;
    X509_REVOKED* rev;

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

int
cmd_cert(const char *arg, char **UNUSED(tmp_config_file))
{
    int ret;
    char* args = strdupa(arg);
    char* cmd = NULL, *ptr = NULL, *path, *path2, *dest;
    char* trusted_dir, *netconf_dir, *c_rehash_cmd;
    DIR* dir = NULL;
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
            return EXIT_FAILURE;
        }

        dir = opendir(trusted_dir);
        while ((d = readdir(dir))) {
            if (!strcmp(d->d_name + strlen(d->d_name) - 4, ".pem")) {
                none = 0;
                name = strdup(d->d_name);
                name[strlen(name) - 4] = '\0';
                asprintf(&path, "%s/%s", trusted_dir, d->d_name);
                parse_cert(name, path);
                free(name);
                free(path);
            }
        }
        closedir(dir);
        if (none) {
            printf("No certificates found in the default trusted CA directory.\n");
        }
        free(trusted_dir);

    } else if (!strcmp(cmd, "add")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("cert add", "Missing or wrong path to the certificate");
            return EXIT_FAILURE;
        }
        if (eaccess(path, R_OK)) {
            ERROR("cert add", "Cannot access certificate \"%s\": %s", path, strerror(errno));
            return EXIT_FAILURE;
        }

        trusted_dir = get_default_trustedCA_dir(NULL);
        if (!trusted_dir) {
            ERROR("cert add", "Could not get the default trusted CA directory");
            return EXIT_FAILURE;
        }

        if ((asprintf(&dest, "%s/%s", trusted_dir, strrchr(path, '/') + 1) == -1)
                || (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", trusted_dir) == -1)) {
            ERROR("cert add", "Memory allocation failed");
            free(trusted_dir);
            return EXIT_FAILURE;
        }
        free(trusted_dir);

        if (strcmp(dest + strlen(dest) - 4, ".pem")) {
            ERROR("cert add", "CA certificates are expected to be in *.pem format");
            strcpy(dest + strlen(dest) - 4, ".pem");
        }

        if (cp(dest, path)) {
            ERROR("cert add", "Could not copy the certificate: %s", strerror(errno));
            free(dest);
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }
        free(dest);

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("cert add", "c_rehash execution failed");
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }

        free(c_rehash_cmd);

    } else if (!strcmp(cmd, "remove")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path) {
            ERROR("cert remove", "Missing the certificate name");
            return EXIT_FAILURE;
        }

        /* delete ".pem" if the user unnecessarily included it */
        if ((strlen(path) > 4) && !strcmp(path + strlen(path) - 4, ".pem")) {
            path[strlen(path) - 4] = '\0';
        }

        trusted_dir = get_default_trustedCA_dir(NULL);
        if (!trusted_dir) {
            ERROR("cert remove", "Could not get the default trusted CA directory");
            return EXIT_FAILURE;
        }

        if ((asprintf(&dest, "%s/%s.pem", trusted_dir, path) == -1)
                || (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", trusted_dir) == -1)) {
            ERROR("cert remove", "Memory allocation failed");
            free(trusted_dir);
            return EXIT_FAILURE;
        }
        free(trusted_dir);

        if (remove(dest)) {
            ERROR("cert remove", "Cannot remove certificate \"%s\": %s (use the name from \"cert display\" output)",
                  path, strerror(errno));
            free(dest);
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }
        free(dest);

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("cert remove", "c_rehash execution failed");
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }

        free(c_rehash_cmd);

    } else if (!strcmp(cmd, "displayown")) {
        int crt = 0, key = 0, pem = 0;

        netconf_dir = get_netconf_dir();
        if (!netconf_dir) {
            ERROR("cert displayown", "Could not get the client home directory");
            return EXIT_FAILURE;
        }

        if (asprintf(&dest, "%s/client.pem", netconf_dir) == -1) {
            ERROR("cert displayown", "Memory allocation failed");
            free(netconf_dir);
            return EXIT_FAILURE;
        }
        free(netconf_dir);
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
        free(dest);

    } else if (!strcmp(cmd, "replaceown")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("cert replaceown", "Missing the certificate or invalid path.");
            return EXIT_FAILURE;
        }
        if (eaccess(path, R_OK)) {
            ERROR("cert replaceown", "Cannot access the certificate \"%s\": %s", path, strerror(errno));
            return EXIT_FAILURE;
        }

        path2 = strtok_r(NULL, " ", &ptr);
        if (path2) {
            if (strlen(path2) < 5) {
                ERROR("cert replaceown", "Invalid private key path.");
                return EXIT_FAILURE;
            }
            if (eaccess(path2, R_OK)) {
                ERROR("cert replaceown", "Cannot access the private key \"%s\": %s", path2, strerror(errno));
                return EXIT_FAILURE;
            }
        }

        netconf_dir = get_netconf_dir();
        if (!netconf_dir) {
            ERROR("cert replaceown", "Could not get the client home directory");
            return EXIT_FAILURE;
        }
        if (asprintf(&dest, "%s/client.XXX", netconf_dir) == -1) {
            ERROR("cert replaceown", "Memory allocation failed");
            free(netconf_dir);
            return EXIT_FAILURE;
        }
        free(netconf_dir);

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
                free(dest);
                return EXIT_FAILURE;
            }
            strcpy(dest + strlen(dest) - 4, ".key");
            if (cp(dest, path2)) {
                ERROR("cert replaceown", "Could not copy the private key \"%s\": %s", path, strerror(errno));
                free(dest);
                return EXIT_FAILURE;
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
                free(dest);
                return EXIT_FAILURE;
            }
        }

        free(dest);

    } else {
        ERROR("cert", "Unknown argument %s", cmd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
cmd_crl(const char *arg, char **UNUSED(tmp_config_file))
{
    int ret;
    char *args = strdupa(arg);
    char *cmd = NULL, *ptr = NULL, *path, *dest;
    char *crl_dir, *c_rehash_cmd;
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
            return EXIT_FAILURE;
        }

        dir = opendir(crl_dir);
        while ((d = readdir(dir))) {
            if (!strcmp(d->d_name + strlen(d->d_name) - 4, ".pem")) {
                none = 0;
                name = strdup(d->d_name);
                name[strlen(name) - 4] = '\0';
                asprintf(&path, "%s/%s", crl_dir, d->d_name);
                parse_crl(name, path);
                free(name);
                free(path);
            }
        }
        closedir(dir);
        if (none) {
            printf("No CRLs found in the default CRL directory.\n");
        }
        free(crl_dir);

    } else if (!strcmp(cmd, "add")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path || (strlen(path) < 5)) {
            ERROR("crl add", "Missing or wrong path to the certificate");
            return EXIT_FAILURE;
        }
        if (eaccess(path, R_OK)) {
            ERROR("crl add", "Cannot access certificate \"%s\": %s", path, strerror(errno));
            return EXIT_FAILURE;
        }

        crl_dir = get_default_CRL_dir(NULL);
        if (!crl_dir) {
            ERROR("crl add", "Could not get the default CRL directory");
            return EXIT_FAILURE;
        }

        if ((asprintf(&dest, "%s/%s", crl_dir, strrchr(path, '/') + 1) == -1)
                || (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", crl_dir) == -1)) {
            ERROR("crl add", "Memory allocation failed");
            free(crl_dir);
            return EXIT_FAILURE;
        }
        free(crl_dir);

        if (strcmp(dest + strlen(dest) - 4, ".pem")) {
            ERROR("crl add", "CRLs are expected to be in *.pem format");
            strcpy(dest + strlen(dest) - 4, ".pem");
        }

        if (cp(dest, path)) {
            ERROR("crl add", "Could not copy the CRL \"%s\": %s", path, strerror(errno));
            free(dest);
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }
        free(dest);

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("crl add", "c_rehash execution failed");
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }

        free(c_rehash_cmd);

    } else if (!strcmp(cmd, "remove")) {
        path = strtok_r(NULL, " ", &ptr);
        if (!path) {
            ERROR("crl remove", "Missing the certificate name");
            return EXIT_FAILURE;
        }

        // delete ".pem" if the user unnecessarily included it
        if ((strlen(path) > 4) && !strcmp(path + strlen(path) - 4, ".pem")) {
            path[strlen(path) - 4] = '\0';
        }

        crl_dir = get_default_CRL_dir(NULL);
        if (!crl_dir) {
            ERROR("crl remove", "Could not get the default CRL directory");
            return EXIT_FAILURE;
        }

        if ((asprintf(&dest, "%s/%s.pem", crl_dir, path) == -1)
                || (asprintf(&c_rehash_cmd, "c_rehash %s &> /dev/null", crl_dir) == -1)) {
            ERROR("crl remove", "Memory allocation failed");
            free(crl_dir);
            return EXIT_FAILURE;
        }
        free(crl_dir);

        if (remove(dest)) {
            ERROR("crl remove", "Cannot remove CRL \"%s\": %s (use the name from \"crl display\" output)",
                  path, strerror(errno));
            free(dest);
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }
        free(dest);

        if (((ret = system(c_rehash_cmd)) == -1) || WEXITSTATUS(ret)) {
            ERROR("crl remove", "c_rehash execution failed");
            free(c_rehash_cmd);
            return EXIT_FAILURE;
        }

        free(c_rehash_cmd);

    } else {
        ERROR("crl", "Unknown argument %s", cmd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
cmd_connect_listen_tls(struct arglist *cmd, int is_connect)
{
    const char *func_name = (is_connect ? "cmd_connect" : "cmd_listen");
    static unsigned short listening = 0;
    char *host = NULL;
    DIR *dir = NULL;
    struct dirent* d;
    int c, n, timeout = 0, ret = EXIT_FAILURE;
    char *cert = NULL, *key = NULL, *trusted_dir = NULL, *crl_dir = NULL, *trusted_store = NULL;
    unsigned short port = 0;
    int option_index = 0;
    struct option long_options[] = {
        {"tls", 0, 0, 't'},
        {"host", 1, 0, 'o'},
        {"port", 1, 0, 'p'},
        {"cert", 1, 0, 'c'},
        {"key", 1, 0, 'k'},
        {"trusted", 1, 0, 'r'},
        {"timeout", 1, 0, 'i'},
        {0, 0, 0, 0}
    };

    if (is_connect) {
        /* remove timeout option for use as connect command */
        memset(&long_options[6], 0, sizeof long_options[6]);
    }

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    while ((c = getopt_long(cmd->count, cmd->list, (is_connect ? "to:p:c:k:r:" : "ti:o:p:c:k:r:"), long_options, &option_index)) != -1) {
        switch (c) {
        case 't':
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
                //nc_callhome_listen_stop();
                listening = 0;
            }
            break;
        case 'c':
            asprintf(&cert, "%s", optarg);
            break;
        case 'k':
            asprintf(&key, "%s", optarg);
            break;
        case 'r':
            trusted_store = optarg;
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
        nc_client_tls_ch_add_bind_listen(host, port);
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

int
cmd_searchpath(const char *arg, char **UNUSED(tmp_config_file))
{
    const char *path;

    for (arg += 10; isspace(arg[0]); ++arg);

    if (!arg[0]) {
        path = nc_client_get_schema_searchpath();
        fprintf(stdout, "%s\n", path[0] ? path : "<none>");
        return 0;
    }

    if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
        cmd_searchpath_help();
        return 0;
    }

    nc_client_set_schema_searchpath(arg);
    return 0;
}

int
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
        output_flag = LYP_FORMAT;
    } else if (!strncmp(format, "xml_noformat", 12) && ((format[12] == '\0') || (format[12] == ' '))) {
        output_format = LYD_XML;
        output_flag = 0;
    } else if (!strncmp(format, "json", 4) && ((format[4] == '\0') || (format[4] == ' '))) {
        output_format = LYD_JSON;
        output_flag = LYP_FORMAT;
    } else if (!strncmp(format, "json_noformat", 13) && ((format[13] == '\0') || (format[13] == ' '))) {
        output_format = LYD_JSON;
        output_flag = 0;
    } else {
        fprintf(stderr, "Unknown output format \"%s\".\n", format);
        return 1;
    }

    return 0;
}

int
cmd_version(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    fprintf(stdout, "Netopeer2 CLI %s\n", VERSION);
    fprintf(stdout, "Compile time: %s, %s\n", __DATE__, __TIME__);
    return 0;
}

int
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
        nc_libssh_thread_verbosity(0);
    } else if (!strcmp(verb, "warning") || !strcmp(verb, "1")) {
        nc_verbosity(1);
        nc_libssh_thread_verbosity(1);
    } else if (!strcmp(verb, "verbose")  || !strcmp(verb, "2")) {
        nc_verbosity(2);
        nc_libssh_thread_verbosity(2);
    } else if (!strcmp(verb, "debug")  || !strcmp(verb, "3")) {
        nc_verbosity(3);
        nc_libssh_thread_verbosity(3);
    } else {
        fprintf(stderr, "Unknown verbosity \"%s\"\n", verb);
        return 1;
    }

    return 0;
}

int
cmd_disconnect(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    if (session == NULL) {
        ERROR("disconnect", "Not connected to any NETCONF server.");
    } else {
        /* possible data race, but let's be optimistic */
        ntf_tid = 0;
        nc_session_free(session, NULL);
        session = NULL;
    }

    return EXIT_SUCCESS;
}

int
cmd_status(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    const char *s;
    const char * const *cpblts;
    int i;

    if (!session) {
        printf("Client is not connected to any NETCONF server.\n");
    } else {
        printf("Current NETCONF session:\n");
        printf("  ID          : %u\n", nc_session_get_id(session));
        printf("  Host        : %s\n", nc_session_get_host(session));
        printf("  Port        : %u\n", nc_session_get_port(session));
        printf("  User        : %s\n", nc_session_get_username(session));
        switch (nc_session_get_ti(session)) {
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            s = "SSH";
            break;
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            s = "TLS";
            break;
#endif
        case NC_TI_FD:
            s = "FD";
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
    int c, ret;
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
#endif
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    if (session) {
        ERROR(func_name, "Already connected to %s.", nc_session_get_host(session));
        return EXIT_FAILURE;
    }

    /* process given arguments */
    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    ret = -1;

#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    optstring = "hsti:o:p:l:c:k:r:";
#elif defined(NC_ENABLED_SSH)
    optstring = "hsi:o:p:l:";
#elif defined(NC_ENABLED_TLS)
    optstring = "hti:o:p:c:k:r:";
#endif

    while ((c = getopt_long(cmd.count, cmd.list, optstring, long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            if (is_connect) {
                cmd_connect_help();
            } else {
                cmd_listen_help();
            }
            clear_arglist(&cmd);
            ret = EXIT_SUCCESS;
            break;
#ifdef NC_ENABLED_SSH
        case 's':
            ret = cmd_connect_listen_ssh(&cmd, is_connect);
            break;
#endif
#ifdef NC_ENABLED_TLS
        case 't':
            ret = cmd_connect_listen_tls(&cmd, is_connect);
            break;
#endif
        default:
            break;
        }
    }

    if (ret == -1) {
#ifdef NC_ENABLED_SSH
        ret = cmd_connect_listen_ssh(&cmd, is_connect);
#elif defined(NC_ENABLED_TLS)
        ret = cmd_connect_listen_tls(&cmd, is_connect);
#endif
    }

    if (!ret) {
        interleave = 1;
    }

    clear_arglist(&cmd);
    return ret;
}

int
cmd_connect(const char *arg, char **UNUSED(tmp_config_file))
{
    return cmd_connect_listen(arg, 1);
}

int
cmd_listen(const char *arg, char **UNUSED(tmp_config_file))
{
    return cmd_connect_listen(arg, 0);
}

int
cmd_quit(const char *UNUSED(arg), char **UNUSED(tmp_config_file))
{
    done = 1;
    return 0;
}

int
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

int
cmd_editor(const char *arg, char **UNUSED(tmp_config_file))
{
    char *cmd, *args = strdupa(arg), *ptr = NULL;

    cmd = strtok_r(args, " ", &ptr);
    cmd = strtok_r(NULL, " ", &ptr);
    if (cmd == NULL) {
        printf("Current editor: ");
        printf("%s\n", config_editor);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        cmd_editor_help();
    } else {
        free(config_editor);
        config_editor = strdup(cmd);
    }

    return EXIT_SUCCESS;
}

int
cmd_cancelcommit(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE;
    const char *persist_id = NULL;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"persist-id", 1, 0, 'i'},
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

    while ((c = getopt_long(cmd.count, cmd.list, "hi:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_cancelcommit_help();
            ret = EXIT_SUCCESS;
            goto fail;
        case 'i':
            persist_id = optarg;
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

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

int
cmd_commit(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret = EXIT_FAILURE, confirmed = 0;
    int32_t confirm_timeout = 0;
    char *persist = NULL, *persist_id = NULL;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"confirmed", 0, 0, 'c'},
            {"confirm-timeout", 1, 0, 't'},
            {"persist", 1, 0, 'p'},
            {"persist-id", 1, 0, 'i'},
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

    while ((c = getopt_long(cmd.count, cmd.list, "hct:p:i:", long_options, &option_index)) != -1) {
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

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

int
cmd_copyconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE;
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
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:s:c::d:", long_options, &option_index)) != -1) {
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

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    free(src);
    clear_arglist(&cmd);

    return ret;
}

int
cmd_deleteconfig(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE;
    const char *trg = NULL;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"target", 1, 0, 't'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:", long_options, &option_index)) != -1) {
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

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    return ret;
}

int
cmd_discardchanges(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
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

    while ((c = getopt_long(cmd.count, cmd.list, "h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_discardchanges_help();
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_discardchanges_help();
            clear_arglist(&cmd);
            return EXIT_FAILURE;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_discardchanges_help();
        clear_arglist(&cmd);
        return EXIT_FAILURE;
    }

    clear_arglist(&cmd);

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        return EXIT_FAILURE;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        return EXIT_FAILURE;
    }

    rpc = nc_rpc_discard();
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        return EXIT_FAILURE;
    }

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);
    return ret;
}

int
cmd_editconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, content_param = 0;
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
            {"error", 1, 0, 'r'},
            {"config", 2, 0, 'c'},
            {"url", 1, 0, 'u'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:o:e:r:c::u:", long_options, &option_index)) != -1) {
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
        case 'r':
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

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    free(content);
    return ret;
}

int
cmd_get(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0;
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
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs::x:d:o:", long_options, &option_index)) != -1) {
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
        ret = cli_send_recv(rpc, output, wd);
    } else {
        ret = cli_send_recv(rpc, stdout, wd);
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

int
cmd_getconfig(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0;
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
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hu:s::x:d:o:", long_options, &option_index)) != -1) {
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
        ret = cli_send_recv(rpc, output, wd);
    } else {
        ret = cli_send_recv(rpc, stdout, wd);
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

int
cmd_killsession(const char *arg, char **UNUSED(tmp_config_file))
{
    struct nc_rpc *rpc;
    int c, ret;
    uint32_t sid = 0;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"sid", 1, 0, 's'},
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

    while ((c = getopt_long(cmd.count, cmd.list, "hs:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_killsession_help();
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
        case 's':
            sid = atoi(optarg);
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_killsession_help();
            clear_arglist(&cmd);
            return EXIT_FAILURE;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_killsession_help();
        clear_arglist(&cmd);
        return EXIT_FAILURE;
    }

    clear_arglist(&cmd);

    if (!sid) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_killsession_help();
        return EXIT_FAILURE;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        return EXIT_FAILURE;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        return EXIT_FAILURE;
    }

    if (!sid) {
        ERROR(__func__, "Session ID was not specififed or not a number.");
        return EXIT_FAILURE;
    }

    rpc = nc_rpc_kill(sid);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        return EXIT_FAILURE;
    }

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);
    return ret;
}

int
cmd_lock(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"target", 1, 0, 't'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_lock_help();
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
        case 't':
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                clear_arglist(&cmd);
                return EXIT_FAILURE;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_lock_help();
            clear_arglist(&cmd);
            return EXIT_FAILURE;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_lock_help();
        clear_arglist(&cmd);
        return EXIT_FAILURE;
    }

    clear_arglist(&cmd);

    if (!target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_lock_help();
        return EXIT_FAILURE;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        return EXIT_FAILURE;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        return EXIT_FAILURE;
    }

    /* create requests */
    rpc = nc_rpc_lock(target);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        return EXIT_FAILURE;
    }

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);
    return ret;
}

int
cmd_unlock(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret;
    struct nc_rpc *rpc;
    NC_DATASTORE target = NC_DATASTORE_ERROR;;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"target", 1, 0, 't'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmd_unlock_help();
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
        case 't':
            if (!strcmp(optarg, "running")) {
                target = NC_DATASTORE_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                target = NC_DATASTORE_STARTUP;
            } else if (!strcmp(optarg, "candidate")) {
                target = NC_DATASTORE_CANDIDATE;
            } else {
                ERROR(__func__, "Invalid source datastore specified (%s).", optarg);
                clear_arglist(&cmd);
                return EXIT_FAILURE;
            }
            break;
        default:
            ERROR(__func__, "Unknown option -%c.", c);
            cmd_unlock_help();
            clear_arglist(&cmd);
            return EXIT_FAILURE;
        }
    }

    if (cmd.list[optind]) {
        ERROR(__func__, "Unparsed command arguments.");
        cmd_unlock_help();
        clear_arglist(&cmd);
        return EXIT_FAILURE;
    }

    clear_arglist(&cmd);

    if (!target) {
        ERROR(__func__, "Mandatory command arguments missing.");
        cmd_unlock_help();
        return EXIT_FAILURE;
    }

    if (!session) {
        ERROR(__func__, "Not connected to a NETCONF server, no RPCs can be sent.");
        return EXIT_FAILURE;
    }

    if (!interleave) {
        ERROR(__func__, "NETCONF server does not support interleaving RPCs and notifications.");
        return EXIT_FAILURE;
    }

    /* create requests */
    rpc = nc_rpc_unlock(target);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        return EXIT_FAILURE;
    }

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);
    return ret;
}

int
cmd_validate(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE;
    struct stat config_stat;
    char *src = NULL, *config_m = NULL, *src_start;
    NC_DATASTORE source = NC_DATASTORE_ERROR;
    struct nc_rpc *rpc;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"source", 1, 0, 's'},
            {"src-config", 2, 0, 'c'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs:c::", long_options, &option_index)) != -1) {
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
    src_start = trim_top_elem(src, "config", "urn:ietf:params:xml:ns:netconf:base:1.0");
    if (!src_start) {
        ERROR(__func__, "Provided configuration content is invalid.");
        goto fail;
    }

    /* create requests */
    rpc = nc_rpc_validate(source, src_start, NC_PARAMTYPE_CONST);
    if (!rpc) {
        ERROR(__func__, "RPC creation failed.");
        goto fail;
    }

    ret = cli_send_recv(rpc, stdout, 0);

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    free(src);
    return ret;
}

int
cmd_subscribe(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE, filter_param = 0;
    struct stat config_stat;
    char *filter = NULL, *config_m = NULL, *start = NULL, *stop = NULL;
    const char *stream = NULL;
    struct nc_rpc *rpc;
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
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hs::x:b:e:t:o:", long_options, &option_index)) != -1) {
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
            if (optarg[0] == '-' || optarg[0] == '+') {
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
                start = nc_time2datetime(t, NULL, NULL);
            } else { /* c == 'e' */
                stop = nc_time2datetime(t, NULL, NULL);
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

    if (ntf_tid) {
        ERROR(__func__, "Already subscribed to a notification stream.");
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

    ret = cli_send_recv(rpc, stdout, 0);
    nc_rpc_free(rpc);

    if (ret) {
        goto fail;
    }

    /* create notification thread */
    if (!output) {
        output = stdout;
    }
    nc_session_set_data(session, output);
    ret = nc_recv_notif_dispatch(session, cli_ntf_clb);
    if (ret) {
        ERROR(__func__, "Failed to create notification thread.");
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

    return ret;
}

int
cmd_getschema(const char *arg, char **UNUSED(tmp_config_file))
{
    int c, ret = EXIT_FAILURE;
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
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "hm:v:f:o:", long_options, &option_index)) != -1) {
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
        ret = cli_send_recv(rpc, output, 0);
    } else {
        ret = cli_send_recv(rpc, stdout, 0);
    }

    nc_rpc_free(rpc);

fail:
    clear_arglist(&cmd);
    if (output) {
        fclose(output);
    }
    return ret;
}

int
cmd_userrpc(const char *arg, char **tmp_config_file)
{
    int c, config_fd, ret = EXIT_FAILURE;
    struct stat config_stat;
    char *content = NULL, *config_m = NULL;
    struct nc_rpc *rpc;
    FILE *output = NULL;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"content", 1, 0, 'c'},
            {"out", 1, 0, 'o'},
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    init_arglist(&cmd);
    if (addargs(&cmd, "%s", arg)) {
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(cmd.count, cmd.list, "ht:s:c::d:", long_options, &option_index)) != -1) {
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
        ret = cli_send_recv(rpc, output, 0);
    } else {
        ret = cli_send_recv(rpc, stdout, 0);
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

int
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
        {"knownhosts", cmd_knownhosts, cmd_knownhosts_help, "Manage the user knownhosts file"},
#endif
#ifdef NC_ENABLED_TLS
        {"cert", cmd_cert, cmd_cert_help, "Manage trusted or your own certificates"},
        {"crl", cmd_crl, cmd_crl_help, "Manage Certificate Revocation List directory"},
#endif
        {"outputformat", cmd_outputformat, cmd_outputformat_help, "Set the output format of all the data"},
        {"searchpath", cmd_searchpath, cmd_searchpath_help, "Set the search path for models"},
        {"verb", cmd_verb, cmd_verb_help, "Change verbosity"},
        {"version", cmd_version, NULL, "Print Netopeer2 CLI version"},
        {"disconnect", cmd_disconnect, NULL, "Disconnect from a NETCONF server"},
        {"status", cmd_status, NULL, "Display information about the current NETCONF session"},
        {"connect", cmd_connect, cmd_connect_help, "Connect to a NETCONF server"},
        {"listen", cmd_listen, cmd_listen_help, "Wait for a Call Home connection from a NETCONF server"},
        {"quit", cmd_quit, NULL, "Quit the program"},
        {"help", cmd_help, NULL, "Display commands description"},
        {"editor", cmd_editor, cmd_editor_help, "Set the text editor for working with XML data"},
        {"cancel-commit", cmd_cancelcommit, cmd_cancelcommit_help, "ietf-netconf <cancel-commit> operation"},
        {"commit", cmd_commit, cmd_commit_help, "ietf-netconf <commit> operation"},
        {"copy-config", cmd_copyconfig, cmd_copyconfig_help, "ietf-netconf <copy-config> operation"},
        {"delete-config", cmd_deleteconfig, cmd_deleteconfig_help, "ietf-netconf <delete-config> operation"},
        {"discard-changes", cmd_discardchanges, cmd_discardchanges_help, "ietf-netconf <discard-changes> operation"},
        {"edit-config", cmd_editconfig, cmd_editconfig_help, "ietf-netconf <edit-config> operation"},
        {"get", cmd_get, cmd_get_help, "ietf-netconf <get> operation"},
        {"get-config", cmd_getconfig, cmd_getconfig_help, "ietf-netconf <get-config> operation"},
        {"kill-session", cmd_killsession, cmd_killsession_help, "ietf-netconf <kill-session> operation"},
        {"lock", cmd_lock, cmd_lock_help, "ietf-netconf <lock> operation"},
        {"unlock", cmd_unlock, cmd_unlock_help, "ietf-netconf <unlock> operation"},
        {"validate", cmd_validate, cmd_validate_help, "ietf-netconf <validate> operation"},
        {"subscribe", cmd_subscribe, cmd_subscribe_help, "notifications <create-subscription> operation"},
        {"get-schema", cmd_getschema, cmd_getschema_help, "ietf-netconf-monitoring <get-schema> operation"},
        {"user-rpc", cmd_userrpc, cmd_userrpc_help, "Send your own content in an RPC envelope (for DEBUG purposes)"},
        {"timed", cmd_timed, cmd_timed_help, "Time all the commands (that communicate with a server) from issuing a RPC to getting a reply"},
        /* synonyms for previous commands */
        {"?", cmd_help, NULL, "Display commands description"},
        {"exit", cmd_quit, NULL, "Quit the program"},
        {NULL, NULL, NULL, NULL}
};
