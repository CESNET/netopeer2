/**
 * @file netconf_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server callbacks
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

#define _GNU_SOURCE /* asprintf() */

#include "netconf_server.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"

int
np2srv_libnetconf2_config_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    int rc = 0;
    const struct lyd_node *diff = NULL;

    /* get diff and apply it */
    diff = sr_get_change_diff(session);
    rc = nc_server_config_setup_diff(diff);
    if (rc) {
        ERR("Configuring NETCONF server failed.");
        return rc;
    }

    return SR_ERR_OK;
}

#ifdef NC_ENABLED_SSH_TLS

static int
np2srv_validate_posix_username(const char *username)
{
    /* use POSIX username definition
     * https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_437 */

    /* not empty */
    if (strlen(username) == 0) {
        return -1;
    }

    /* no hyphen as first char */
    if (username[0] == '-') {
        return -1;
    }

    /* check for Portable Filename Character Set */
    for (unsigned long i = 0; i < strlen(username); i++) {
        if (!(isalnum(username[i]) || (username[i] == '.') || (username[i] == '_') || (username[i] == '-'))) {
            return -1;
        }
    }

    return 0;
}

int
np2srv_pubkey_auth_cb(const struct nc_session *session, ssh_key key, void *UNUSED(user_data))
{
    FILE *f = NULL;
    struct passwd *pwd;
    ssh_key pub_key = NULL;
    enum ssh_keytypes_e ktype;
    const char *username;
    char *line = NULL, *ptr, *ptr2;
    size_t n;
    int r, ret = 1, line_num = 0;

    username = nc_session_get_username(session);

    errno = 0;
    pwd = getpwnam(username);

    if (!NP2SRV_SSH_AUTHORIZED_KEYS_ARG_IS_USERNAME && !pwd) {
        ERR("Failed to find user entry for \"%s\" (%s).", username, errno ? strerror(errno) : "User not found");
        goto cleanup;
    }

    if (!pwd && np2srv_validate_posix_username(username)) {
        ERR("The username \"%s\" is not a valid posix username.", username);
        goto cleanup;
    }

    /* check any authorized keys */
    r = asprintf(&line, NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN, NP2SRV_SSH_AUTHORIZED_KEYS_ARG_IS_USERNAME ? username : pwd->pw_dir);
    if (r == -1) {
        EMEM;
        line = NULL;
        goto cleanup;
    }
    n = r;

    f = fopen(line, "r");
    if (!f) {
        if (errno == ENOENT) {
            VRB("User \"%s\" has no authorized_keys file.", username);
        } else {
            ERR("Failed to open \"%s\" authorized_keys file (%s).", line, strerror(errno));
        }
        goto cleanup;
    }

    while (getline(&line, &n, f) > -1) {
        ++line_num;

        /* separate key type */
        ptr = line;
        for (ptr2 = ptr; !isspace(ptr2[0]); ++ptr2) {}
        if (ptr2[0] == '\0') {
            WRN("Invalid authorized key format of \"%s\" (line %d).", username, line_num);
            continue;
        }
        ptr2[0] = '\0';

        /* detect key type */
        ktype = ssh_key_type_from_name(ptr);
        if (ktype == SSH_KEYTYPE_UNKNOWN) {
            WRN("Unknown key type \"%s\" (line %d).", ptr, line_num);
            continue;
        }

        /* separate key data */
        ptr = ptr2 + 1;
        for (ptr2 = ptr; !isspace(ptr2[0]); ++ptr2) {}
        ptr2[0] = '\0';

        r = ssh_pki_import_pubkey_base64(ptr, ktype, &pub_key);
        if (r != SSH_OK) {
            WRN("Failed to import authorized key of \"%s\" (%s, line %d).",
                    username, r == SSH_EOF ? "Unexpected end-of-file" : "SSH error", line_num);
            continue;
        }

        /* compare public keys */
        if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
            /* key matches */
            ret = 0;
            goto cleanup;
        }

        /* not a match, next key */
        ssh_key_free(pub_key);
        pub_key = NULL;
    }
    if (!feof(f)) {
        WRN("Failed reading from authorized_keys file of \"%s\".", username);
        goto cleanup;
    }

    /* no match */

cleanup:
    if (f) {
        fclose(f);
    }
    free(line);
    ssh_key_free(pub_key);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */
