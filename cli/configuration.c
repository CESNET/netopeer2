/**
 * @file configuration.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-cli configuration
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <dirent.h>

#include "configuration.h"
#include "commands.h"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

struct cli_opts *opts;

extern int done;

/* NetConf Client home (appended to ~/) */
#define NCC_DIR ".netopeer2-cli"
/* all these appended to NCC_DIR */
#define CA_DIR "certs"
#define CRL_DIR "crl"
#define CERT_CRT "client.crt"
#define CERT_PEM "client.pem"
#define CERT_KEY "client.key"

char *
get_netconf_dir(void)
{
    int ret;
    struct passwd *pw;
    char *user_home, *netconf_dir;

    if (!(pw = getpwuid(getuid()))) {
        ERROR("get_netconf_dir", "Determining home directory failed: getpwuid: %s.", strerror(errno));
        return NULL;
    }
    user_home = pw->pw_dir;

    if (asprintf(&netconf_dir, "%s/%s", user_home, NCC_DIR) == -1) {
        ERROR("get_netconf_dir", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        return NULL;
    }

    ret = eaccess(netconf_dir, R_OK | X_OK);
    if (ret == -1) {
        if (errno == ENOENT) {
            /* directory does not exist */
            ERROR("get_netconf_dir", "Configuration directory \"%s\" does not exist, creating it.", netconf_dir);
            if (mkdir(netconf_dir, 00700)) {
                ERROR("get_netconf_dir", "Configuration directory \"%s\" cannot be created: %s", netconf_dir, strerror(errno));
                free(netconf_dir);
                return NULL;
            }
        } else {
            ERROR("get_netconf_dir", "Configuration directory \"%s\" exists but something else failed: %s", netconf_dir, strerror(errno));
            free(netconf_dir);
            return NULL;
        }
    }

    return netconf_dir;
}

void
get_default_client_cert(char **cert, char **key)
{
    char *netconf_dir;
    struct stat st;
    int ret;

    assert(cert && !*cert);
    assert(key && !*key);

    if (!(netconf_dir = get_netconf_dir())) {
        return;
    }

    // trying to use *.crt and *.key format
    if (asprintf(cert, "%s/%s", netconf_dir, CERT_CRT) == -1 || asprintf(key, "%s/%s", netconf_dir, CERT_KEY) == -1) {
        ERROR("get_default_client_cert", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR("get_default_client_cert", "Unable to use the default client certificate due to the previous error.");
        free(netconf_dir);
        return;
    }

    if (eaccess(*cert, R_OK) == -1 || eaccess(*key, R_OK) == -1) {
        if (errno != ENOENT) {
            ERROR("get_default_client_cert", "Unable to access \"%s\" and \"%s\": %s", *cert, *key, strerror(errno));
            free(*key);
            *key = NULL;
            free(*cert);
            *cert = NULL;
            free(netconf_dir);
            return;
        }

        // *.crt & *.key failed, trying to use *.pem format
        free(*key);
        *key = NULL;
        free(*cert);
        if (asprintf(cert, "%s/%s", netconf_dir, CERT_PEM) == -1) {
            ERROR("get_default_client_cert", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
            ERROR("get_default_client_cert", "Unable to use the default client certificate due to the previous error.");
            free(netconf_dir);
            return;
        }

        ret = eaccess(*cert, R_OK);
        if (ret == -1) {
            if (errno != ENOENT) {
                ERROR("get_default_client_cert", "Unable to access \"%s\": %s", *cert, strerror(errno));
            } else {
                // *.pem failed as well
                ERROR("get_default_client_cert", "Unable to find the default client certificate.");
            }
            free(*cert);
            *cert = NULL;
            free(netconf_dir);
            return;
        } else {
            /* check permissions on *.pem */
            if (stat(*cert, &st) != 0) {
                ERROR("get_default_client_cert", "Stat on \"%s\" failed: %s", *cert, strerror(errno));
            } else if (st.st_mode & 0066) {
                ERROR("get_default_client_cert", "Unsafe permissions on \"%s\"", *cert);
            }
        }
    } else {
        /* check permissions on *.key */
        if (stat(*key, &st) != 0) {
            ERROR("get_default_client_cert", "Stat on \"%s\" failed: %s", *key, strerror(errno));
        } else if (st.st_mode & 0066) {
            ERROR("get_default_client_cert", "Unsafe permissions on \"%s\"", *key);
        }
    }

    free(netconf_dir);
}

char *
get_default_trustedCA_dir(DIR **ret_dir)
{
    char *netconf_dir, *cert_dir;

    if (!(netconf_dir = get_netconf_dir())) {
        return NULL;
    }

    if (asprintf(&cert_dir, "%s/%s", netconf_dir, CA_DIR) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to use the trusted CA directory due to the previous error.");
        free(netconf_dir);
        return NULL;
    }
    free(netconf_dir);

    if (ret_dir) {
        if (!(*ret_dir = opendir(cert_dir))) {
            ERROR(__func__, "Unable to open the default trusted CA directory (%s).", strerror(errno));
            free(cert_dir);
            return NULL;
        }
        return NULL;
    }

    errno = 0;
    if (eaccess(cert_dir, R_OK | W_OK | X_OK)) {
        if (errno == ENOENT) {
            ERROR(__func__, "Default trusted CA directory does not exist, creating it.");
            if (mkdir(cert_dir, 00777)) {
                ERROR(__func__, "Failed to create the default trusted CA directory (%s).", strerror(errno));
                free(cert_dir);
                return NULL;
            }
        } else {
            ERROR(__func__, "Unable to access the default trusted CA directory (%s).", strerror(errno));
            free(cert_dir);
            return NULL;
        }
    }

    return cert_dir;
}

char *
get_default_CRL_dir(DIR **ret_dir)
{
    char *netconf_dir, *crl_dir;

    if (!(netconf_dir = get_netconf_dir())) {
        return NULL;
    }

    if (asprintf(&crl_dir, "%s/%s", netconf_dir, CRL_DIR) == -1) {
        ERROR(__func__, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
        ERROR(__func__, "Unable to use the trusted CA directory due to the previous error.");
        free(netconf_dir);
        return NULL;
    }
    free(netconf_dir);

    if (ret_dir) {
        if (!(*ret_dir = opendir(crl_dir))) {
            ERROR(__func__, "Unable to open the default CRL directory (%s).", strerror(errno));
            free(crl_dir);
            return NULL;
        }
        return NULL;
    }

    errno = 0;
    if (eaccess(crl_dir, R_OK | W_OK | X_OK)) {
        if (errno == ENOENT) {
            ERROR(__func__, "Default CRL dir does not exist, creating it.");
            if (mkdir(crl_dir, 00777)) {
                ERROR(__func__, "Failed to create the default CRL directory (%s).", strerror(errno));
                free(crl_dir);
                return NULL;
            }
        } else {
            ERROR(__func__, "Unable to access the default CRL directory (%s).", strerror(errno));
            free(crl_dir);
            return NULL;
        }
    }

    return crl_dir;
}

void
load_config(void)
{
//     char* netconf_dir, *history_file, *config_file;
// #ifdef ENABLE_TLS
//     struct stat st;
//     char* trusted_dir, *crl_dir;
// #endif
//     char* tmp_cap;
//     int i, ret, history_fd, config_fd;
//     xmlDocPtr config_doc;
//     xmlNodePtr config_cap, tmp_node;
//
// #ifndef DISABLE_LIBSSH
//     char * key_priv, *key_pub, *prio;
//     xmlNodePtr tmp_auth, tmp_pref, tmp_key;
// #endif
//
//     if ((netconf_dir = get_netconf_dir()) == NULL) {
//         return;
//     }
//
//     if (opts != NULL) {
//         for (i = 0; i < opts->key_count; ++i) {
//             free(opts->keys[i]);
//         }
//         nc_cpblts_free(opts->cpblts);
//         free(opts->config_editor);
//         free(opts->keys);
//         free(opts);
//     }
//     opts = calloc(1, sizeof(struct cli_options));
//     opts->cpblts = nc_session_get_cpblts_default();
//     opts->pubkey_auth_pref = 3;
//     nc_ssh_pref(NC_SSH_AUTH_PUBLIC_KEYS, 3);
//     opts->passwd_auth_pref = 2;
//     nc_ssh_pref(NC_SSH_AUTH_PASSWORD, 2);
//     opts->inter_auth_pref = 1;
//     nc_ssh_pref(NC_SSH_AUTH_INTERACTIVE, 1);
//
// #ifdef ENABLE_TLS
//     if (asprintf (&trusted_dir, "%s/%s", netconf_dir, CA_DIR) == -1) {
//         ERROR("load_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("load_config", "Unable to check trusted CA directory due to the previous error.");
//         trusted_dir = NULL;
//     } else {
//         if (stat(trusted_dir, &st) == -1) {
//             if (errno == ENOENT) {
//                 ERROR("load_config", "Trusted CA directory (%s) does not exist, creating it", trusted_dir);
//                 if (mkdir(trusted_dir, 0700) == -1) {
//                     ERROR("load_config", "Trusted CA directory cannot be created (%s)", strerror(errno));
//                 }
//             } else {
//                 ERROR("load_config", "Accessing the trusted CA directory failed (%s)", strerror(errno));
//             }
//         } else {
//             if (!S_ISDIR(st.st_mode)) {
//                 ERROR("load_config", "Accessing the trusted CA directory failed (Not a directory)");
//             }
//         }
//     }
//     free(trusted_dir);
//
//     if (asprintf (&crl_dir, "%s/%s", netconf_dir, CRL_DIR) == -1) {
//         ERROR("load_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("load_config", "Unable to check CRL directory due to the previous error.");
//         crl_dir = NULL;
//     } else {
//         if (stat(crl_dir, &st) == -1) {
//             if (errno == ENOENT) {
//                 ERROR("load_config", "CRL directory (%s) does not exist, creating it", crl_dir);
//                 if (mkdir(crl_dir, 0700) == -1) {
//                     ERROR("load_config", "CRL directory cannot be created (%s)", strerror(errno));
//                 }
//             } else {
//                 ERROR("load_config", "Accessing the CRL directory failed (%s)", strerror(errno));
//             }
//         } else {
//             if (!S_ISDIR(st.st_mode)) {
//                 ERROR("load_config", "Accessing the CRL directory failed (Not a directory)");
//             }
//         }
//     }
//     free(crl_dir);
// #endif /* ENABLE_TLS */
//
//     if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
//         ERROR("load_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("load_config", "Unable to load commands history due to the previous error.");
//         history_file = NULL;
//     } else {
//         ret = eaccess(history_file, R_OK);
//         if (ret == -1) {
//             if (errno == ENOENT) {
//                 ERROR("load_config", "History file (%s) does not exist, creating it", history_file);
//                 if ((history_fd = creat(history_file, 0600)) == -1) {
//                     ERROR("load_config", "History file cannot be created (%s)", strerror(errno));
//                 } else {
//                     close(history_fd);
//                 }
//             } else {
//                 ERROR("load_config", "Accessing the history file failed (%s)", strerror(errno));
//             }
//         } else {
//             /* file exist and is accessible */
//             if (read_history(history_file)) {
//                 ERROR("load_config", "Failed to load history.");
//             }
//         }
//     }
//
//     if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
//         ERROR("load_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("load_config", "Unable to load configuration due to the previous error.");
//         config_file = NULL;
//     } else {
//         ret = eaccess(config_file, R_OK);
//         if (ret == -1) {
//             if (errno == ENOENT) {
//                 ERROR("load_config", "Configuration file (%s) does not exits, creating it", config_file);
//                 if ((config_fd = creat(config_file, 0600)) == -1) {
//                     ERROR("load_config", "Configuration file cannot be created (%s)", strerror(errno));
//                 } else {
//                     close(config_fd);
//                 }
//             } else {
//                 ERROR("load_config", "Configuration file cannot accessed (%s)", strerror(errno));
//             }
//         } else {
//             /* file exist and is accessible */
//             if ((config_doc = xmlReadFile(config_file, NULL, XML_PARSE_NOBLANKS | XML_PARSE_NSCLEAN)) == NULL) {
//                 ERROR("load_config", "Failed to load configuration of NETCONF client (xmlReadFile failed).");
//             } else {
//                 /* doc -> <netconf-client/>*/
//                 if (config_doc->children != NULL && xmlStrEqual(config_doc->children->name, BAD_CAST "netconf-client")) {
//                     tmp_node = config_doc->children->children;
//                     while (tmp_node) {
//                         if (xmlStrEqual(tmp_node->name, BAD_CAST "capabilities")) {
//                             /* doc -> <netconf-client> -> <capabilities> */
//                             nc_cpblts_free(opts->cpblts);
//                             opts->cpblts = nc_cpblts_new(NULL);
//                             config_cap = tmp_node->children;
//                             while (config_cap) {
//                                 tmp_cap = (char*)xmlNodeGetContent(config_cap);
//                                 nc_cpblts_add(opts->cpblts, tmp_cap);
//                                 free(tmp_cap);
//                                 config_cap = config_cap->next;
//                             }
//                         } else if (xmlStrEqual(tmp_node->name, BAD_CAST "editor")) {
//                             /* doc -> <netconf-client> -> <editor> */
//                             opts->config_editor = (char*)xmlNodeGetContent(tmp_node);
//                         }
// #ifndef DISABLE_LIBSSH
//                         else if (xmlStrEqual(tmp_node->name, BAD_CAST "authentication")) {
//                             /* doc -> <netconf-client> -> <authentication> */
//                             tmp_auth = tmp_node->children;
//                             while (tmp_auth) {
//                                 if (xmlStrEqual(tmp_auth->name, BAD_CAST "pref")) {
//                                     tmp_pref = tmp_auth->children;
//                                     while (tmp_pref) {
//                                         prio = (char*) xmlNodeGetContent(tmp_pref);
//                                         if (xmlStrEqual(tmp_pref->name, BAD_CAST "publickey")) {
//                                             nc_ssh_pref(NC_SSH_AUTH_PUBLIC_KEYS, atoi(prio));
//                                             opts->pubkey_auth_pref = atoi(prio);
//                                         } else if (xmlStrEqual(tmp_pref->name, BAD_CAST "interactive")) {
//                                             nc_ssh_pref(NC_SSH_AUTH_INTERACTIVE, atoi(prio));
//                                             opts->inter_auth_pref = atoi(prio);
//                                         } else if (xmlStrEqual(tmp_pref->name, BAD_CAST "password")) {
//                                             nc_ssh_pref(NC_SSH_AUTH_PASSWORD, atoi(prio));
//                                             opts->passwd_auth_pref = atoi(prio);
//                                         }
//                                         free(prio);
//                                         tmp_pref = tmp_pref->next;
//                                     }
//                                 } else if (xmlStrEqual(tmp_auth->name, BAD_CAST "keys")) {
//                                     tmp_key = tmp_auth->children;
//                                     while (tmp_key) {
//                                         if (xmlStrEqual(tmp_key->name, BAD_CAST "key-path")) {
//                                             key_priv = (char*)xmlNodeGetContent(tmp_key);
//                                             if (asprintf(&key_pub, "%s.pub", key_priv) == -1) {
//                                                 ERROR("load_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//                                                 ERROR("load_config", "Unable to set SSH keys pair due to the previous error.");
//                                                 key_pub = NULL;
//                                                 tmp_key = tmp_key->next;
//                                                 continue;
//                                             }
//                                             nc_set_keypair_path(key_priv, key_pub);
//                                             ++opts->key_count;
//                                             opts->keys = realloc(opts->keys, opts->key_count*sizeof(char*));
//                                             opts->keys[opts->key_count-1] = key_priv;
//
//                                             free(key_pub);
//                                         }
//                                         tmp_key = tmp_key->next;
//                                     }
//                                 }
//                                 tmp_auth = tmp_auth->next;
//                             }
//                         }
// #endif /* not DISABLE_LIBSSH */
//                         tmp_node = tmp_node->next;
//                     }
//                 }
//                 xmlFreeDoc(config_doc);
//             }
//         }
//     }
//
//     free(config_file);
//     free(history_file);
//     free(netconf_dir);
}

void
store_config(void)
{
//     char* netconf_dir, *history_file, *config_file, str_pref[8];
//     const char* cap;
//     int history_fd, ret, i;
//     xmlDocPtr config_doc;
//     xmlNodePtr config_node;
//     FILE *config_f;
//
//     if ((netconf_dir = get_netconf_dir()) == NULL) {
//         return;
//     }
//
//     if (asprintf(&history_file, "%s/history", netconf_dir) == -1) {
//         ERROR("store_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("store_config", "Unable to store commands history due to the previous error.");
//         history_file = NULL;
//     } else {
//         ret = eaccess(history_file, R_OK | W_OK);
//         if (ret == -1) {
//             if (errno == ENOENT) {
//                 /* file does not exit, create it */
//                 if ((history_fd = creat(history_file, 0600)) == -1) {
//                     /* history file can not be created */
//                 } else {
//                     close(history_fd);
//                 }
//             }
//             ERROR("store_config", "Accessing the history file failed (%s)", strerror(errno));
//         }
//
//         if (write_history(history_file)) {
//             ERROR("save_config", "Failed to save history.");
//         }
//         free(history_file);
//     }
//
//     if (asprintf(&config_file, "%s/config.xml", netconf_dir) == -1) {
//         ERROR("store_config", "asprintf() failed (%s:%d).", __FILE__, __LINE__);
//         ERROR("store_config", "Unable to store configuration due to the previous error.");
//         config_file = NULL;
//     } else if (opts != NULL) {
//         config_doc = xmlNewDoc(BAD_CAST "1.0");
//         config_doc->children = xmlNewDocNode(config_doc, NULL, BAD_CAST "netconf-client", NULL);
//         if (config_doc != NULL) {
//             /* capabilities */
//             config_node = xmlNewChild(config_doc->children, NULL, BAD_CAST "capabilities", NULL);
//             nc_cpblts_iter_start(opts->cpblts);
//             while ((cap = nc_cpblts_iter_next(opts->cpblts)) != NULL) {
//                 xmlNewChild(config_node, NULL, BAD_CAST "capability", BAD_CAST cap);
//             }
//
//             /* editor */
//             if (opts->config_editor != NULL) {
//                 xmlNewChild(config_doc->children, NULL, BAD_CAST "editor", BAD_CAST opts->config_editor);
//             }
//
//             /* authentication */
//             if (opts->pubkey_auth_pref != 3 || opts->passwd_auth_pref != 2 || opts->inter_auth_pref != 1 || opts->key_count > 0) {
//                 config_node = xmlNewChild(config_doc->children, NULL, BAD_CAST "authentication", NULL);
//
//                 /* pref */
//                 if (opts->pubkey_auth_pref != 3 || opts->passwd_auth_pref != 2 || opts->inter_auth_pref != 1) {
//                     config_node = xmlNewChild(config_node, NULL, BAD_CAST "pref", NULL);
//
//                     sprintf(str_pref, "%d", opts->pubkey_auth_pref);
//                     xmlNewChild(config_node, NULL, BAD_CAST "publickey", BAD_CAST str_pref);
//                     sprintf(str_pref, "%d", opts->passwd_auth_pref);
//                     xmlNewChild(config_node, NULL, BAD_CAST "password", BAD_CAST str_pref);
//                     sprintf(str_pref, "%d", opts->inter_auth_pref);
//                     xmlNewChild(config_node, NULL, BAD_CAST "interactive", BAD_CAST str_pref);
//
//                     config_node = config_node->parent;
//                 }
//
//                 /* keys */
//                 if (opts->key_count > 0) {
//                     config_node = xmlNewChild(config_node, NULL, BAD_CAST "keys", NULL);
//
//                     for (i = 0; i < opts->key_count; ++i) {
//                         xmlNewChild(config_node, NULL, BAD_CAST "key-path", BAD_CAST opts->keys[i]);
//                     }
//                 }
//             }
//
//             if ((config_f = fopen(config_file, "w")) == NULL || xmlDocFormatDump(config_f, config_doc, 1) < 0) {
//                 ERROR("store_config", "Cannot write configuration to file %s", config_file);
//             } else {
//                 fclose(config_f);
//             }
//             xmlFreeDoc(config_doc);
//         } else {
//             ERROR("store_config", "Cannot write configuration to file %s", config_file);
//         }
//     }
//
//     if (done && opts != NULL) {
//         nc_cpblts_free(opts->cpblts);
//         free(opts->config_editor);
//         for (i = 0; i < opts->key_count; ++i) {
//             free(opts->keys[i]);
//         }
//         free(opts->keys);
//
//         free(opts);
//     }
//
//     free(netconf_dir);
//     free(config_file);
//
//     if (done) {
//         xmlCleanupParser();
//     }
}
