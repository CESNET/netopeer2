/**
 * @file commands.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libyang's yanglint tool commands
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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pwd.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include <libyang/libyang.h>
#include <nc_client.h>

#include "commands.h"

COMMAND commands[];
extern int done;
extern char *search_path;

struct nc_session* session = NULL;

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

static void
addargs(struct arglist *args, char *format, ...)
{
    va_list arguments;
    char *aux = NULL, *aux1 = NULL;
    int len;

    if (args == NULL) {
        return;
    }

    /* store arguments to aux string */
    va_start(arguments, format);
    if ((len = vasprintf(&aux, format, arguments)) == -1) {
        perror("addargs - vasprintf");
    }
    va_end(arguments);

    /* parse aux string and store it to the arglist */
    /* find \n and \t characters and replace them by space */
    while ((aux1 = strpbrk(aux, "\n\t")) != NULL) {
        *aux1 = ' ';
    }
    /* remember the begining of the aux string to free it after operations */
    aux1 = aux;

    /*
     * get word by word from given string and store words separately into
     * the arglist
     */
    for (aux = strtok(aux, " "); aux; aux = strtok(NULL, " ")) {
        if (!strcmp(aux, ""))
        continue;

        if (!args->list) { /* initial memory allocation */
            if ((args->list = (char **)malloc(8 * sizeof(char *))) == NULL) {
                perror("Fatal error while allocating memory");
            }
            args->size = 8;
            args->count = 0;
        } else if (args->count + 2 >= args->size) {
            /*
             * list is too short to add next to word so we have to
             * extend it
             */
            args->size += 8;
            args->list = realloc(args->list, args->size * sizeof(char *));
        }
        /* add word in the end of the list */
        if ((args->list[args->count] = malloc((strlen(aux) + 1) * sizeof(char))) == NULL) {
            perror("Fatal error while allocating memory");
        }
        strcpy(args->list[args->count], aux);
        args->list[++args->count] = NULL; /* last argument */
    }

    /* clean up */
    free(aux1);
}

void
cmd_searchpath_help(void)
{
    printf("searchpath <model-dir-path>\n");
}

void
cmd_verb_help(void)
{
    printf("verb (error/0 | warning/1 | verbose/2 | debug/3)\n");
}

#ifdef ENABLE_SSH

void
cmd_auth_help(void)
{
    printf("auth (--help | pref [(publickey | interactive | password) <preference>] | keys [add <private_key_path>] [remove <key_index>])\n");
}

void
cmd_knownhosts_help(void)
{
    printf("knownhosts [--help] [--del <key_index>]\n");
}

#endif /* ENABLE_SSH */

void
cmd_connect_help(void)
{
#ifdef ENABLE_TLS
    printf("connect [--help] [--port <num>] [--login <username>] [--tls] [--cert <cert_path> [--key <key_path>]] [--trusted <trusted_CA_store.pem>] host\n");
#else
    printf("connect [--help] [--port <num>] [--login <username>] host\n");
#endif
}

void
cmd_listen_help(void)
{
    /* TODO */
}

int
cmd_searchpath(const char *arg)
{
    const char *path;
    struct stat st;

    if (strchr(arg, ' ') == NULL) {
        fprintf(stderr, "Missing the search path.\n");
        return 1;
    }
    path = strchr(arg, ' ')+1;

    if (!strcmp(path, "-h") || !strcmp(path, "--help")) {
        cmd_searchpath_help();
        return 0;
    }

    if (stat(path, &st) == -1) {
        fprintf(stderr, "Failed to stat the search path (%s).\n", strerror(errno));
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "\"%s\" is not a directory.\n", path);
        return 1;
    }

    free(search_path);
    search_path = strdup(path);

    return 0;
}

int
cmd_verb(const char *arg)
{
    const char *verb;
    if (strlen(arg) < 5) {
        cmd_verb_help();
        return 1;
    }

    verb = arg + 5;
    if (!strcmp(verb, "error") || !strcmp(verb, "0")) {
        nc_verbosity(0);
    } else if (!strcmp(verb, "warning") || !strcmp(verb, "1")) {
        nc_verbosity(1);
    } else if (!strcmp(verb, "verbose")  || !strcmp(verb, "2")) {
        nc_verbosity(2);
    } else if (!strcmp(verb, "debug")  || !strcmp(verb, "3")) {
        nc_verbosity(3);
    } else {
        fprintf(stderr, "Unknown verbosity \"%s\"\n", verb);
        return 1;
    }

    return 0;
}

#ifdef ENABLE_SSH

int
cmd_auth(const char *arg)
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
            if ((pref = nc_get_ssh_auth_pref(NC_SSH_AUTH_PUBLICKEY)) < 0) {
                printf("\t'publickey':   disabled\n");
            } else {
                printf("\t'publickey':   %d\n", pref);
            }
            if ((pref = nc_get_ssh_auth_pref(NC_SSH_AUTH_PASSWORD)) < 0) {
                printf("\t'password':    disabled\n");
            } else {
                printf("\t'password':    %d\n", pref);
            }
            if ((pref = nc_get_ssh_auth_pref(NC_SSH_AUTH_INTERACTIVE)) < 0) {
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
                nc_set_ssh_auth_pref(NC_SSH_AUTH_PUBLICKEY, atoi(cmd));
            }
        } else if (strcmp(cmd, "interactive") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth pref interactive", "Missing the preference argument");
                return EXIT_FAILURE;
            } else {
                nc_set_ssh_auth_pref(NC_SSH_AUTH_INTERACTIVE, atoi(cmd));
            }
        } else if (strcmp(cmd, "password") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth pref password", "Missing the preference argument");
                return EXIT_FAILURE;
            } else {
                nc_set_ssh_auth_pref(NC_SSH_AUTH_PASSWORD, atoi(cmd));
            }
        } else {
            ERROR("auth pref", "Unknown authentication method (%s)", cmd);
            return EXIT_FAILURE;
        }

    } else if (strcmp(cmd, "keys") == 0) {
        cmd = strtok_r(NULL, " ", &ptr);
        if (cmd == NULL) {
            printf("The keys used for SSH authentication:\n");
            if (nc_get_ssh_keypair_count() == 0) {
                printf("(none)\n");
            } else {
                for (i = 0; i < nc_get_ssh_keypair_count(); ++i) {
                    nc_get_ssh_keypair(i, &pub_key, &priv_key);
                    printf("#%d: %s (private %s)\n", i, pub_key, priv_key);
                }
            }
        } else if (strcmp(cmd, "add") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth keys add", "Missing the key path");
                return EXIT_FAILURE;
            }

            asprintf(&str, "%s.pub", cmd);
            if (nc_add_ssh_keypair(str, cmd) != EXIT_SUCCESS) {
                ERROR("auth keys add", "Failed to add key");
                free(str);
                return EXIT_FAILURE;
            }

            if (eaccess(cmd, R_OK) != 0) {
                ERROR("auth keys add", "The new private key is not accessible (%s), but added anyway", strerror(errno));
            }
            if (eaccess(str, R_OK) != 0) {
                ERROR("auth keys add", "The public key for the new private key is not accessible (%s), but added anyway", strerror(errno));
            }
            free(str);

        } else if (strcmp(cmd, "remove") == 0) {
            cmd = strtok_r(NULL, " ", &ptr);
            if (cmd == NULL) {
                ERROR("auth keys remove", "Missing the key index");
                return EXIT_FAILURE;
            }

            i = strtol(cmd, &ptr, 10);
            if (ptr[0] || nc_del_ssh_keypair(i)) {
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
cmd_knownhosts(const char *arg)
{
    char* ptr, *kh_file, *line = NULL, **pkeys = NULL, *text;
    int del_idx = -1, i, j, pkey_len = 0, written;
    size_t line_len, text_len;
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
    addargs(&cmd, "%s", arg);

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
        text[text_len] = '\0';

        if (fread(text, 1, text_len, file) < text_len) {
            ERROR("knownhosts", "Cannot read known hosts file (%s)", strerror(ferror(file)));
            free(text);
            fclose(file);
            return EXIT_FAILURE;
        }
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

#endif /* ENABLE_SSH */

#define ACCEPT_TIMEOUT 60000 /* 1 minute */

void nc_callhome_listen_stop() {}
#undef ENABLE_TLS

static int
cmd_connect_listen(const char* arg, int is_connect)
{
    const char *func_name = (is_connect ? "connect" : "listen");
    static unsigned short listening = 0;
    int timeout = ACCEPT_TIMEOUT;
    char *host = NULL, *user = NULL;
#ifdef ENABLE_TLS
    DIR *dir = NULL;
    struct dirent* d;
    int usetls = 0, n;
    char *cert = NULL, *key = NULL, *trusted_dir = NULL, *crl_dir = NULL, *trusted_store = NULL;
#endif
    int hostfree = 0;
    unsigned short port = 0;
    int c;
    struct arglist cmd;
    struct option long_options[] = {
            {"help", 0, 0, 'h'},
            {"port", 1, 0, 'p'},
            {"login", 1, 0, 'l'},
#ifdef ENABLE_TLS
            {"tls", 0, 0, 't'},
            {"cert", 1, 0, 'c'},
            {"key", 1, 0, 'k'},
            {"trusted", 1, 0, 's'},
#endif
            {0, 0, 0, 0}
    };
    int option_index = 0;

    /* set back to start to be able to use getopt() repeatedly */
    optind = 0;

    if (session) {
        ERROR(func_name, "Already connected to %s.", nc_get_session_host(session));
        return EXIT_FAILURE;
    }

    /* process given arguments */
    init_arglist(&cmd);
    addargs(&cmd, "%s", arg);

#ifdef ENABLE_TLS
    while ((c = getopt_long(cmd.count, cmd.list, "hp:l:tc:k:s:", long_options, &option_index)) != -1)
#else
    while ((c = getopt_long(cmd.count, cmd.list, "hp:l:", long_options, &option_index)) != -1)
#endif
    {
        switch (c) {
        case 'h':
            if (is_connect) {
                cmd_connect_help();
            } else {
                cmd_listen_help();
            }
            clear_arglist(&cmd);
            return EXIT_SUCCESS;
            break;
        case 'p':
            port = (unsigned short)atoi(optarg);
            if (!is_connect && listening && (listening != port)) {
                nc_callhome_listen_stop();
                listening = 0;
            }
            break;
        case 'l':
            user = optarg;
            break;
#ifdef ENABLE_TLS
        case 't':
            if (!port) {
                port = (is_connect ? NC_PORT_TLS : NC_PORT_CH_TLS);
            }
            usetls = 1;
            break;
        case 'c':
            asprintf(&cert, "%s", optarg);
            break;
        case 'k':
            asprintf(&key, "%s", optarg);
            break;
        case 's':
            trusted_store = optarg;
            break;
#endif
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
    if (!port) {
        port = (is_connect ? NC_PORT_SSH : NC_PORT_CH_SSH);
    }
#ifdef ENABLE_TLS
    if (usetls) {
        /* use the default TLS user if not specified by user
         * (it does not have any effect except for seeing it
         * in status command as the session user) */
        if (!user) {
            user = strdupa("certificate-based");
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
            if ((strlen(trusted_store) < 5) || strcmp(trusted_store+strlen(trusted_store)-4, ".pem")) {
                ERROR(func_name, "Trusted CA store in an unknown format.");
                goto error_cleanup;
            }
        }
        if (!(crl_dir = get_default_CRL_dir(NULL))) {
            ERROR(func_name, "Could not use the CRL directory.");
            goto error_cleanup;
        }

        if (nc_tls_init(cert, key, trusted_store, trusted_dir, NULL, crl_dir) != EXIT_SUCCESS) {
            ERROR(func_name, "Initiating TLS failed.");
            goto error_cleanup;
        }
    }
#endif

    if (is_connect) {
        if (optind == cmd.count) {
            /* get mandatory argument */
            host = malloc(sizeof(char) * 1024);
            if (host == NULL) {
                ERROR(func_name, "Memory allocation error (%s).", strerror(errno));
                goto error_cleanup;
            }
            hostfree = 1;
            INSTRUCTION("Hostname to connect to: ");
            if (scanf("%1023s", host) == EOF) {
                ERROR(func_name, "Reading the user input failed (%s).", errno ? strerror(errno) : "Unexpected input");
                if (hostfree) {
                    free(host);
                }
                goto error_cleanup;
            }
        } else if ((optind + 1) == cmd.count) {
            host = cmd.list[optind];
        }

        /* create the session */
        session = nc_connect_ssh(host, port, user, ly_ctx_new(search_path));
        if (session == NULL) {
            ERROR(func_name, "Connecting to the %s:%d as user \"%s\" failed.", host, port, user);
            if (hostfree) {
                free(host);
            }
            goto error_cleanup;
        }
        if (hostfree) {
            free(host);
        }
    } else {
        /* create the session */
        /*if (!listening) {
            if (nc_callhome_listen(port) == EXIT_FAILURE) {
                ERROR(func_name, "Unable to start listening for incoming Call Home");
                goto error_cleanup;
            }
            listening = port;
        }

        if (verb_level == 0) {
            printf("\tWaiting 1 minute for call home on port %d...\n", port);
        }
        session = nc_callhome_accept(user, opts->cpblts, &timeout);
        if (!session) {
            if (!timeout) {
                ERROR(func_name, "No Call Home");
            } else {
                ERROR(func_name, "Receiving Call Home failed");
            }
        }*/
    }

#ifdef ENABLE_TLS
    free(trusted_dir);
    free(crl_dir);
    free(cert);
    free(key);
#endif
    clear_arglist(&cmd);
    return EXIT_SUCCESS;

error_cleanup:
#ifdef ENABLE_TLS
    free(trusted_dir);
    free(crl_dir);
    free(cert);
    free(key);
#endif
    clear_arglist(&cmd);
    return EXIT_FAILURE;
}

int
cmd_connect(const char* arg)
{
    return cmd_connect_listen(arg, 1);
}

int
cmd_quit(const char *UNUSED(arg))
{
    done = 1;
    return 0;
}

int
cmd_help(const char *arg)
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

COMMAND commands[] = {
        {"help", cmd_help, NULL, "Display commands description"},
        {"searchpath", cmd_searchpath, cmd_searchpath_help, "Set the search path for models"},
        {"verb", cmd_verb, cmd_verb_help, "Change verbosity"},
        {"quit", cmd_quit, NULL, "Quit the program"},
        {"auth", cmd_auth, cmd_auth_help, "Manage SSH authentication options"},
        {"knownhosts", cmd_knownhosts, cmd_knownhosts_help, "Manage the user knownhosts file"},
        {"connect", cmd_connect, cmd_connect_help, "Connect to a NETCONF server"},
        /* synonyms for previous commands */
        {"?", cmd_help, NULL, "Display commands description"},
        {"exit", cmd_quit, NULL, "Quit the program"},
        {NULL, NULL, NULL, NULL}
};
