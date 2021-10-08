/**
 * @file netconf_confirmed_commit.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief ietf-netconf confirmed-commit capability callbacks
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

#include "netconf_confirmed_commit.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "err_netconf.h"
#include "log.h"

#define META_FILE "meta"

#define NCC_DIR "confirmed_commit"

/**
 * @brief Context for confirmed commits.
 *
 * When accessing struct members must use the lock mutex.
 * Alternatively use the set_* and get_* functions
 */
typedef struct commit_ctx_s {
    char *persist;        /* What persist-id is expected */
    timer_t timer;        /* POSIX timer used for rollback, zero if none */
    pthread_mutex_t lock; /* Lock mutexing this structure and access to NCC_DIR */
} commit_ctx_t;

static commit_ctx_t commit_ctx = {.persist = NULL, .timer = 0, .lock = PTHREAD_MUTEX_INITIALIZER};

void
ncc_commit_ctx_destroy(void)
{
    if (commit_ctx.timer) {
        timer_delete(commit_ctx.timer);
    }
    free(commit_ctx.persist);
    commit_ctx.persist = NULL;
}

/**
 * @brief Set value of persist in the commit context structure.
 *
 * @param[in] value New value to set.
 * @return SR_ERR_NO_MEMORY When out of memory.
 * @return SR_ERR_OK When successful.
 */
static int
ncc_set_persist(const char *value)
{
    int rc = SR_ERR_OK;
    char *new = NULL;

    free(commit_ctx.persist);
    if (!value) {
        commit_ctx.persist = NULL;
        goto cleanup;
    }

    new = strdup(value);
    if (!new) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    commit_ctx.persist = new;

cleanup:
    return rc;
}

/**
 * @brief Transform filename into module name.
 *
 * @param[in] filename Name of the file to extract module name out of.
 * @return Module name.
 */
static char *
get_module_name_from_filename(const char *filename)
{
    char *point = strstr(filename, ".json");
    char *new = NULL;

    if (!point) {
        goto cleanup;
    }

    new = strndup(filename, point - filename);
    if (!new) {
        EMEM;
        goto cleanup;
    }

cleanup:
    return new;
}

/**
 * @brief Rename a file if restore failed.
 *
 * @param[in] filename Name of the file to create new name from.
 * @param[in] path Absolute path to the file.
 */
static void
rename_failed_file(const char *filename, const char *path)
{
    char *new = NULL;

    if (asprintf(&new, "%s/%s/%s-%ld.failed", np2srv.server_dir, NCC_DIR, filename, time(NULL)) == -1) {
        EMEM;
        return;
    }

    if (rename(path, new)) {
        ERR("Renaming \"%s\" failed (%s).", filename, strerror(errno));
        goto cleanup;
    }

cleanup:
    free(new);
}

/**
 * @brief Read a backup file located on @p path and parse it
 *
 * @param[in] ctx Libyang context used for parsing.
 * @param[in] path Path where the backup file is located.
 * @param[out] node Parsed backup file into lyd_node.
 * @return SR_ERR_LY When failed parsing.
 * @return SR_ERR_OK When successful.
 */
static int
get_running_backup(const struct ly_ctx *ctx, const char *path, struct lyd_node **node)
{
    int ret = SR_ERR_OK;

    if (lyd_parse_data_path(ctx, path, LYD_JSON, LYD_PARSE_ORDERED | LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, node)) {
        ERR("Failed parsing confirmed commit backup of running for file \"%s\" (%s).", path, ly_errmsg(ctx));
        ret = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    return ret;
}

/**
 * @brief Check if directory on @p path exists. Create it otherwise.
 *
 * @param[in] path Path to the directory to check.
 * @return SR_ERR_SYS When failed creating the directory.
 * @return SR_ERR_OK When successful
 */
static int
ncc_check_dir_exists(const char *path)
{
    int rc = SR_ERR_OK;

    if ((mkdir(path, S_IRWXU) == -1) && (errno != EEXIST)) {
        ERR("Failed creating directory \"%s\" (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
    }

    return rc;
}

/**
 * @brief Check if directory on @p path has owner set to current user.
 *
 * @param[in] path Path to the directory to check.
 * @return SR_ERR_SYS When failed getting directory stats or changing the owner.
 * @return SR_ERR_OK When successful
 */
static int
ncc_check_dir_owner(const char *path)
{
    int rc = SR_ERR_OK;
    struct stat statbuf;
    uid_t euid;
    gid_t egid;

    euid = geteuid();
    egid = getegid();
    if (stat(path, &statbuf) == -1) {
        ERR("Failed getting owner of directory \"%s\" (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }
    if ((statbuf.st_uid != euid) || (statbuf.st_gid != egid)) {
        VRB("Changing owner and group UID of directory \"%s\".", path);
        if (chown(np2srv.server_dir, euid, egid) == -1) {
            ERR("Failed changing ownership of directory \"%s\" (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
    }

cleanup:
    return rc;
}

/**
 * @brief Check if directory on @p path has permissions set to 700. Change if it does not.
 *
 * @param[in] path Path to the directory to check.
 * @return SR_ERR_SYS When failed getting directory stats or changing the permissions.
 * @return SR_ERR_OK When successful
 */
static int
ncc_check_dir_permissions(const char *path)
{
    int rc = SR_ERR_OK;
    mode_t expected_mode = S_IRWXU;

    if (chmod(path, expected_mode) == -1) {
        ERR("Failed changing permissions of directory \"%s\" (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

cleanup:
    return rc;
}

/**
 * @brief check if NCC_DIR exists, try creating it otherwise. Check permissions and ownership. Change if wrong.
 *
 * @return SR_ERR_SYS When failed during creation of the directory.
 * @return SR_ERR_NO_MEMRY When out of memory.
 * @return SR_ERR_OK When directory exists or was successfully created.
 */
static int
ncc_check_dir(void)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    if (asprintf(&path, "%s/%s", np2srv.server_dir, NCC_DIR) == -1) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /* Create folders if they do not exist */
    if ((rc = ncc_check_dir_exists(np2srv.server_dir))) {
        goto cleanup;
    }
    if ((rc = ncc_check_dir_exists(path))) {
        goto cleanup;
    }

    /* In theory if they were both just created it can skip this part */

    /* Check ownership, change if not current user */
    if ((rc = ncc_check_dir_owner(np2srv.server_dir))) {
        goto cleanup;
    }
    if ((rc = ncc_check_dir_owner(path))) {
        goto cleanup;
    }

    /* Check permissions, change if not 700 */
    if ((rc = ncc_check_dir_permissions(np2srv.server_dir))) {
        goto cleanup;
    }
    if ((rc = ncc_check_dir_permissions(path))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return rc;
}

/**
 * @brief Restore running using the backup files.
 * Thread run after the timer in commit_ctx_s runs out.
 */
static void
changes_rollback(union sigval UNUSED(sev))
{
    int rc;
    struct lyd_node *node = NULL;
    const struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    sr_session_ctx_t *session;
    char *path = NULL, *module_name = NULL, *meta = NULL, *srv_path = NULL;
    uint32_t nc_id;
    DIR *dir = NULL;
    struct dirent *dirent = NULL;

    VRB("Confirmed commit timeout reached. Restoring previous running.");
    ctx = sr_get_context(np2srv.sr_conn);

    /* Start a session */
    if ((rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &session))) {
        ERR("Failed starting a sysrepo session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    /* set session attributes for diff_check_cb to skip NACM check */
    sr_session_set_orig_name(session, "netopeer2");
    /* nc_id */
    nc_id = 0;
    sr_session_push_orig_data(session, sizeof nc_id, &nc_id);
    /* username */
    sr_session_push_orig_data(session, 1, "");

    if ((rc = ncc_check_dir())) {
        goto cleanup;
    }
    /* Iterate over all files in backup directory */
    if (asprintf(&srv_path, "%s/%s", np2srv.server_dir, NCC_DIR) == -1) {
        EMEM;
        goto cleanup;
    }
    dir = opendir(srv_path);
    if (!dir) {
        ERR("Failed opening netopeer2 server directory \"%s\".", srv_path);
        goto cleanup;
    }
    while ((dirent = readdir(dir))) {
        if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, "..") || !strcmp(dirent->d_name, META_FILE)) {
            continue;
        }

        /* try to find the module that corresponds with the file */
        free(module_name);
        module_name = get_module_name_from_filename(dirent->d_name);
        if (!module_name) {
            /* Skipping files that do not match the expected format */
            continue;
        }
        free(path);
        path = NULL;
        if (asprintf(&path, "%s/%s/%s", np2srv.server_dir, NCC_DIR, dirent->d_name) == -1) {
            EMEM;
            goto cleanup;
        }
        module = ly_ctx_get_module_implemented(ctx, module_name);
        if (!module) {
            ERR("Module \"%s\" does not exist/not implemented.", module_name);
            rename_failed_file(module_name, path);
            continue;
        }

        /* get, restore and delete the backup */
        VRB("Rolling back module \"%s\"", module->name);
        if (get_running_backup(ctx, path, &node)) {
            rename_failed_file(module_name, path);
            continue;
        }
        if ((rc = sr_replace_config(session, module->name, node, np2srv.sr_timeout))) {
            ERR("Failed restoring backup for module \"%s\".", module->name);
            rename_failed_file(module_name, path);
            continue;
        }
        if (unlink(path) == -1) {
            ERR("Failed removing backup file \"%s\" (%s).", path, strerror(errno));
            goto cleanup;
        }
    }

    if (asprintf(&meta, "%s/%s/%s", np2srv.server_dir, NCC_DIR, META_FILE) < 0) {
        EMEM;
        goto cleanup;
    }
    if (unlink(meta) == -1) {
        ERR("Failed removing confirmed commit meta file (%s).", strerror(errno));
        goto cleanup;
    }

cleanup:
    closedir(dir);
    sr_session_stop(session);
    free(path);
    free(srv_path);
    free(meta);
    free(module_name);
}

/**
 * @brief Remove all the backup files not marked as failed.
 */
static void
clean_backup_directory(void)
{
    DIR *dir = NULL;
    struct dirent *dirent;
    char *path = NULL, *ncc_path = NULL;

    if (asprintf(&ncc_path, "%s/%s", np2srv.server_dir, NCC_DIR) == -1) {
        EMEM;
        return;
    }

    dir = opendir(ncc_path);
    if (!dir) {
        ERR("Could not open netopeer2 server directory \"%s\" (%s).", ncc_path, strerror(errno));
        goto cleanup;
    }
    while ((dirent = readdir(dir))) {
        if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, "..") ||
                !strstr(".json", dirent->d_name) || strcmp(META_FILE, dirent->d_name)) {
            /* If some unexpected file, just skip */
            continue;
        }

        if (asprintf(&path, "%s/%s", ncc_path, dirent->d_name) == -1) {
            EMEM;
            goto cleanup;
        }

        if (unlink(path) == -1) {
            ERR("Could not remove backup file \"%s\" (%s).", path, strerror(errno));
            goto cleanup;
        }
        free(path);
        path = NULL;
    }

cleanup:
    closedir(dir);
    free(path);
    free(ncc_path);
}

/**
 * @brief Confirm pending commit. Clear the timer. Clean the directory.
 */
static void
ncc_commit_confirmed(void)
{
    timer_delete(commit_ctx.timer);
    commit_ctx.timer = 0;
    clean_backup_directory();
}

/**
 * @brief Cancel pending commit. Rollback running from backup.
 */
static void
ncc_commit_cancel(void)
{
    changes_rollback((union sigval)0);
    ncc_commit_confirmed();
}

/**
 * @brief Backup a module into a file
 *
 * @param[in] session Sysrepo session used to get data of the module.
 * @param[in] module Module to backup.
 *
 * @return SR_ERR_LY When printing into the file failed.
 * @return SR_ERR_NO_MEMORY When memory ran during allocation
 * @return SR_ERR_OK On success
 */
static int
backup_module(sr_session_ctx_t *session, const struct lys_module *module)
{
    int rc = SR_ERR_OK;
    char *path = NULL, *xpath = NULL, *ncc_path = NULL;
    struct lyd_node *node = NULL;

    if (asprintf(&ncc_path, "%s/%s", np2srv.server_dir, NCC_DIR) == -1) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    VRB("Backing up module \"%s\".", module->name);

    if (asprintf(&xpath, "/%s:*", module->name) == -1) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    if ((rc = sr_get_data(session, xpath, 0, 0, 0, &node))) {
        ERR("Failed getting configuration of running for module \"%s\" (%s).", module->name, sr_strerror(rc));
        goto cleanup;
    }

    if (asprintf(&path, "%s/%s.json", ncc_path, module->name) == -1) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if (lyd_print_path(path, node, LYD_JSON, LY_PRINT_SHRINK)) {
        ERR("Failed backing up node of module \"%s\" into file \"%s\" (%s).",
                module->name, path, ly_errmsg(LYD_CTX(node)));
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    lyd_free_tree(node);
    free(path);
    free(xpath);
    return rc;
}

/**
 * @brief Schedule a rollback of confirmed commit. Create the timer and set all the options.
 *
 * @param[in] timeout_s Time (in seconnds) after which the timer will start the rollback.
 *
 * @return SR_ERR_SYS When creating the timer fails.
 * @return SR_ERR_OK When succeeded.
 */
static int
ncc_commit_timeout_schedule(uint32_t timeout_s)
{
    struct sigevent sev = {0};
    struct itimerspec its = {0};
    timer_t timer_id;

    /* create and arm the timer */
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = changes_rollback;
    its.it_value.tv_sec = timeout_s;
    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1) {
        ERR("Could not create a timer for confirmed commit rollback (%s).", strerror(errno));
        return SR_ERR_SYS;
    }
    if (timer_settime(timer_id, 0, &its, NULL) == -1) {
        ERR("Could not set time in timer for confirmed commit rollback (%s).", strerror(errno));
        return SR_ERR_SYS;
    }
    commit_ctx.timer = timer_id;

    return SR_ERR_OK;
}

/**
 * @brief Get information from meta file and remove it.
 *
 * @param[out] time When the confirmed commit was called.
 * @param[out] timeout_s What was the timeout (seconds) supposed to be.
 * @return SR_ERR_SYS When reading file failed;
 * @return SR_ERR_OK When successful. If time is zero no meta file existed.
 */
static int
read_meta_file(time_t *time, uint32_t *timeout_s)
{
    int rc = SR_ERR_OK;
    FILE *file = NULL;
    char *meta = NULL;

    *time = 0;
    *timeout_s = 0;

    /* Check for file */
    if (asprintf(&meta, "%s/%s/%s", np2srv.server_dir, NCC_DIR, META_FILE) < 0) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if (access(meta, F_OK)) {
        goto cleanup;
    }

    file = fopen(meta, "r");
    if (!file) {
        ERR("Confirmed commit meta file found but not readable.");
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    if (fscanf(file, "%ld\n%" SCNu32 "\n", (long *)time, timeout_s) != 2) {
        ERR("Malformed confirmed commit meta file. Could not recover.");
        *time = 0;
        *timeout_s = 0;
        rc = SR_ERR_SYS;
        goto cleanup;
    }

cleanup:
    if (file) {
        fclose(file);
    }
    free(meta);
    return rc;
}

void
ncc_try_restore(void)
{
    time_t timestamp = 0, end_time = 0, current = 0;
    uint32_t timeout = 0, new_timeout = 0;

    /* In theory it should be under a mutex, but since it is called in init it is not needed */

    if (read_meta_file(&timestamp, &timeout)) {
        return;
    }
    if (!timestamp) {
        /* No meta file existed */
        return;
    }

    /* Check when the confirmed commit was supposed to timeout */
    end_time = timestamp + timeout;
    current = time(NULL);
    if (end_time > current) {
        /* In the future -> compute the remaining time */
        new_timeout = end_time - current;
    }
    /* else it was in the past -> should be zero */

    VRB("Restoring a previous confirmed commit.");
    ncc_commit_timeout_schedule(new_timeout);
}

/**
 * @brief Create backup files for all implemented modules
 *
 * @return SR_ERR_OK When successful.
 */
static int
set_running_backup(void)
{
    int rc = SR_ERR_OK, read = 0, write = 0;
    const struct ly_ctx *ctx;
    struct sr_session_ctx_s *session;
    struct lys_module *module;
    sr_conn_ctx_t *conn;
    uint32_t index = 0;

    if ((rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &session))) {
        ERR("Failed starting a sysrepo session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* Iterate over all implemented modules */
    conn = sr_session_get_connection(session);
    ctx = sr_get_context(conn);
    if ((rc = ncc_check_dir())) {
        goto cleanup;
    }
    while ((module = ly_ctx_get_module_iter(ctx, &index))) {
        /* check if module should and can be backed up */
        if (!module->implemented) {
            continue;
        }
        if (!np_ly_mod_has_data(module, LYS_CONFIG_W)) {
            continue;
        }

        /* Check if has both read and write permission for module in sysrepo */
        if ((rc = sr_check_module_ds_access(conn, "edit1", SR_DS_RUNNING, &read, &write))) {
            ERR("Failed getting permissions of module \"%s\".", module->name);
            goto cleanup;
        }
        if (!read || !write) {
            continue;
        }

        /* Create the backup */
        if ((rc = backup_module(session, module))) {
            ERR("Failed creating backup of module \"%s\".", module->name);
            goto cleanup;
        }
    }

cleanup:
    sr_session_stop(session);
    return rc;
}

/**
 * @brief Create a file containing metadata about confirmed commit. Used when restoring after crash.
 *
 * @param[in] timeout_s Timeout (in seconds) that was used for the confirmed commit.
 */
static void
create_meta_file(uint32_t timeout_s)
{
    FILE *file = NULL;
    char *meta;

    if (asprintf(&meta, "%s/%s/%s", np2srv.server_dir, NCC_DIR, META_FILE) < 0) {
        EMEM;
        goto cleanup;
    }
    file = fopen(meta, "w");
    if (!file) {
        WRN("Failed creating confirmed commit meta file. Changes will not recover in case the server is stopped.");
        goto cleanup;
    }
    fprintf(file, "%ld\n%" PRIu32 "\n", (long)time(NULL), timeout_s);

cleanup:
    if (file) {
        fclose(file);
    }
    free(meta);
}

/**
 * @brief Callback for the confirmed commit RPC.
 *
 * @param[in] session Sysrepo session.
 * @param[in] input RPC parsed into lyd_node.
 * @return SR_ERR_INVAL_ARG When timeout was not a valid uint32 number or persist-id given when not expected.
 * @return SR_ERR_OK When successful.
 */
static int
np2srv_confirmed_commit_cb(sr_session_ctx_t *session, const struct lyd_node *input)
{
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess;
    const sr_error_info_t *err_info;
    const char *persist = NULL;
    struct lyd_node *node = NULL;
    char *endptr = NULL;
    uint32_t timeout;

    /* get the user session */
    if ((rc = np_get_user_sess(session, NULL, &user_sess))) {
        goto cleanup;
    }

    /* confirm-timeout */
    lyd_find_path(input, "confirm-timeout", 0, &node);
    assert(node);
    timeout = strtoul(lyd_get_value(node), &endptr, 10);
    if (*endptr) {
        rc = SR_ERR_INVAL_ARG;
        ERR("Invalid timeout \"%s\" given", lyd_get_value(node));
        goto cleanup;
    }

    /* persist */
    lyd_find_path(input, "persist", 0, &node);
    if (node) {
        persist = lyd_get_value(node);
    }

    /* persist-id */
    lyd_find_path(input, "persist-id", 0, &node);
    if (node) {
        ERR("Persist-id given in confirmed commit rpc.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* create and store the backup */
    if ((rc = sr_session_switch_ds(user_sess->sess, SR_DS_RUNNING))) {
        goto cleanup;
    }
    if (set_running_backup()) {
        goto cleanup;
    }
    create_meta_file(timeout);

    /* Set persist and start timer thread for rollback */
    if (persist) {
        if (ncc_set_persist(persist)) {
            goto cleanup;
        }
    }
    if (ncc_commit_timeout_schedule(timeout)) {
        goto cleanup;
    }

    /* sysrepo API */
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout);
    if ((rc == SR_ERR_LOCKED) && NP_IS_ORIG_NP(session)) {
        /* NETCONF error */
        sr_session_get_error(user_sess->sess, &err_info);
        np_err_sr2nc_in_use(session, err_info);
    } else if (rc) {
        /* Sysrepo error */
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

cleanup:
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_commit_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id),
        struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess = NULL;
    struct lyd_node *node;
    const sr_error_info_t *err_info;
    const char *persist_id = NULL;
    const char *persist;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get the user session */
    if ((rc = np_get_user_sess(session, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, SR_DS_RUNNING);

    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);
    /* check if confirmed-commit */
    lyd_find_path(input, "confirmed", 0, &node);
    if (node) {
        rc = np2srv_confirmed_commit_cb(session, input);
        goto cleanup;
    }

    /* persist-id */
    lyd_find_path(input, "persist-id", 0, &node);
    if (node) {
        persist_id = lyd_get_value(node);
    }

    persist = commit_ctx.persist;
    if ((persist && !persist_id) || (!persist && persist_id) || (persist && persist_id && strcmp(persist, persist_id))) {
        np_err_invalid_value(session, "Confirming commit does not match pending confirmed commit.", persist_id);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (persist_id) {
        /* confirming commit, set persist to NULL */
        ncc_set_persist(NULL);
    }

    /* If there is a commit waiting to be confirmed, confirm it */
    if (commit_ctx.timer) {
        ncc_commit_confirmed();
    }

    /* sysrepo API */
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout);
    if ((rc == SR_ERR_LOCKED) && NP_IS_ORIG_NP(session)) {
        /* NETCONF error */
        sr_session_get_error(user_sess->sess, &err_info);
        np_err_sr2nc_in_use(session, err_info);
    } else if (rc) {
        /* Sysrepo error */
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

    /* success */

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_cancel_commit_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id),
        struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct lyd_node *node;
    const char *persist_id = NULL, *persist = NULL;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* persist-id */
    lyd_find_path(input, "persist-id", 0, &node);
    if (node) {
        persist_id = lyd_get_value(node);
    }
    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);
    persist = commit_ctx.persist;
    if ((persist && !persist_id) || (!persist && persist_id) || (persist && persist_id && strcmp(persist, persist_id))) {
        np_err_invalid_value(session, "Confirming commit does not match pending confirmed commit.", persist_id);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    ncc_commit_cancel();

    /* success */

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);
    return rc;
}
