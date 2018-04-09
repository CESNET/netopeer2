/**
 * @file ietf_keystore.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server ietf-keystore model configuration
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "operations.h"

int
np_hostkey_clb(const char *name, void *UNUSED(user_data), char **privkey_path, char **UNUSED(privkey_data),
               int *UNUSED(privkey_data_rsa))
{
    if (asprintf(privkey_path, NP2SRV_KEYSTORED_DIR "/%s.pem", name) == -1) {
        EMEM;
        return 1;
    }

    return 0;
}

int
np_server_cert_clb(const char *name, void *UNUSED(user_data), char **UNUSED(cert_path), char **cert_data,
                   char **privkey_path, char **UNUSED(privkey_data), int *UNUSED(privkey_data_rsa))
{
    int ret;
    char *path, *key_begin, *key_end, quot;
    sr_val_t *sr_cert;

    ret = asprintf(&path, "/ietf-keystore:keystore/private-keys/private-key/certificate-chains/"
                   "certificate-chain[name='%s']/certificate[1]", name);
    if (ret == -1) {
        EMEM;
        return 1;
    }

    if (np2srv.sr_sess.ds != SR_DS_RUNNING) {
        if (np2srv_sr_session_switch_ds(np2srv.sr_sess.srs, SR_DS_RUNNING, NULL)) {
            free(path);
            return 1;
        }
        np2srv.sr_sess.ds = SR_DS_RUNNING;
    }

    /* Refresh the session to prevent sysrepo returning cached data
     * forthe certificate (if the certificate is changed).
     */
    if (np2srv_sr_session_refresh(np2srv.sr_sess.srs, NULL)) {
	    ERR("%s:%d Failed session refresh", __func__, __LINE__);
	    free(path);
	    return 1;
    }

    if (np2srv_sr_get_item(np2srv.sr_sess.srs, path, &sr_cert, NULL)) {
        free(path);
        return 1;
    }
    free(path);

    /* get the private key name */
    key_begin = strstr(sr_cert->xpath, "private-key[name=");
    if (!key_begin) {
        EINT;
        sr_free_val(sr_cert);
        return 1;
    }
    key_begin += 17;
    quot = key_begin[0];
    ++key_begin;

    key_end = strchr(key_begin, quot);
    if (!key_end) {
        EMEM;
        sr_free_val(sr_cert);
        return 1;
    }

    ret = asprintf(privkey_path, NP2SRV_KEYSTORED_DIR "/%.*s.pem", (int)(key_end - key_begin), key_begin);
    *cert_data = strdup(sr_cert->data.binary_val);
    sr_free_val(sr_cert);

    if ((ret == -1) || !*cert_data) {
        EMEM;
        return 1;
    }

    return 0;
}

int
np_trusted_cert_list_clb(const char *name, void *UNUSED(user_data), char ***UNUSED(cert_paths), int *UNUSED(cert_path_count),
                         char ***cert_data, int *cert_data_count)
{
    int ret;
    char *path;
    sr_val_t *sr_certs;
    size_t sr_cert_count, i;

    ret = asprintf(&path, "/ietf-keystore:keystore/trusted-certificates[name='%s']/trusted-certificate/certificate",
                   name);
    if (ret == -1) {
        EMEM;
        return 1;
    }

    if (np2srv.sr_sess.ds != SR_DS_RUNNING) {
        if (np2srv_sr_session_switch_ds(np2srv.sr_sess.srs, SR_DS_RUNNING, NULL)) {
            free(path);
            return 1;
        }
        np2srv.sr_sess.ds = SR_DS_RUNNING;
    }

    /* Refresh the session to prevent sysrepo returning cached data */
    if (np2srv_sr_session_refresh(np2srv.sr_sess.srs, NULL)) {
	    ERR("%s:%d Failed session refresh", __func__, __LINE__);
	    free(path);
	    return 1;
    }

    if (np2srv_sr_get_items(np2srv.sr_sess.srs, path, &sr_certs, &sr_cert_count, NULL)) {
        free(path);
        return 1;
    }
    free(path);

    *cert_data = calloc(sr_cert_count, sizeof **cert_data);
    for (i = 0; i < sr_cert_count; ++i) {
        (*cert_data)[i] = strdup(sr_certs[i].data.binary_val);
    }
    *cert_data_count = sr_cert_count;

    sr_free_values(sr_certs, sr_cert_count);
    return 0;
}
