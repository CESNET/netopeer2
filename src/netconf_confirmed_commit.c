/**
 * @file netconf_confirmed_commit.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf confirmed-commit capability callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
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
#include <sysrepo/netconf_acm.h>

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
static struct {
    char *persist;              /* persist-id of the commit */
    struct nc_session *nc_sess; /* NETCONF session of the pending commit */
    timer_t timer;              /* POSIX timer used for rollback, zero if none */
    pthread_mutex_t lock;       /* Lock for access to this structure and to NCC_DIR */
} commit_ctx = {.persist = NULL, .timer = 0, .lock = PTHREAD_MUTEX_INITIALIZER};

void
ncc_commit_ctx_destroy(void)
{
    if (commit_ctx.timer) {
        timer_delete(commit_ctx.timer);
    }
    free(commit_ctx.persist);
    commit_ctx.persist = NULL;
}

int
ncc_ongoing_confirmed_commit(struct nc_session **nc_sess)
{
    int cc;

    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);

    if (commit_ctx.timer) {
        *nc_sess = commit_ctx.nc_sess;
        cc = 1;
    } else {
        cc = 0;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);

    return cc;
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
ncc_get_module_name_from_filename(const char *filename)
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
ncc_rename_failed_file(const char *filename, const char *path)
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
ncc_get_running_backup(const struct ly_ctx *ctx, const char *path, struct lyd_node **node)
{
    int ret = SR_ERR_OK;

    if (lyd_parse_data_path(ctx, path, LYD_JSON, LYD_PARSE_ORDERED | LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, node)) {
        ERR("Failed parsing confirmed commit backup of running for file \"%s\" (%s).", path, ly_err_last(ctx)->msg);
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
ncc_check_server_dir(void)
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
 * @brief Remove all the backup files not marked as failed.
 */
static void
ncc_clean_backup_directory(void)
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
        if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, "..")) {
            continue;
        }

        if (!strstr(dirent->d_name, ".json") && strcmp(META_FILE, dirent->d_name)) {
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
    if (commit_ctx.timer) {
        timer_delete(commit_ctx.timer);
    }
    commit_ctx.timer = 0;
    commit_ctx.nc_sess = NULL;
    ncc_set_persist(NULL);
    ncc_clean_backup_directory();
}

/**
 * @brief Restore running using the backup files.
 * Thread run after the timer in commit_ctx_s runs out.
 *
 * @param[in] sev Received signal. 0 when called by the timer (no commit lock).
 */
static void
ncc_changes_rollback_cb(union sigval sev)
{
    int rc;
    struct np2_user_sess *user_sess = NULL;
    sr_session_ctx_t *sr_sess = NULL;
    struct lyd_node *node = NULL;
    const struct ly_ctx *ly_ctx;
    struct lys_module *module = NULL;
    char *path = NULL, *module_name = NULL, *meta = NULL, *srv_path = NULL, *nacm_user = NULL;
    DIR *dir = NULL;
    struct dirent *dirent = NULL;

    /* basic server dir check */
    if (ncc_check_server_dir()) {
        return;
    }
    ly_ctx = sr_acquire_context(np2srv.sr_conn);

    if (!sev.sival_int) {
        /* LOCK */
        pthread_mutex_lock(&commit_ctx.lock);
    }

    if (commit_ctx.nc_sess) {
        /* get user session, use the original NC (SR) session in case it was used for locking running DS */
        if ((rc = np_acquire_user_sess(commit_ctx.nc_sess, &user_sess))) {
            goto cleanup;
        }
        sr_sess = user_sess->sess;

        /* clear user to skip NACM checks */
        nacm_user = strdup(sr_nacm_get_user(sr_sess));
        if (!nacm_user) {
            EMEM;
            goto cleanup;
        }
        sr_nacm_set_user(sr_sess, NULL);

        /* replacing running datastore */
        sr_session_switch_ds(sr_sess, SR_DS_RUNNING);
    } else {
        /* create a new SR session for the rollback */
        if ((rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess))) {
            goto cleanup;
        }
    }

    /* iterate over all the files in backup directory */
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
        module_name = ncc_get_module_name_from_filename(dirent->d_name);
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
        module = ly_ctx_get_module_implemented(ly_ctx, module_name);
        if (!module) {
            ERR("Module \"%s\" does not exist/not implemented.", module_name);
            ncc_rename_failed_file(module_name, path);
            continue;
        }

        /* get, restore, and delete the backup */
        VRB("Rolling back module \"%s\"...", module->name);
        if (ncc_get_running_backup(ly_ctx, path, &node)) {
            ncc_rename_failed_file(module_name, path);
            continue;
        }
        if ((rc = sr_replace_config(sr_sess, module->name, node, np2srv.sr_timeout))) {
            ERR("Failed restoring backup for module \"%s\".", module->name);
            ncc_rename_failed_file(module_name, path);
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

    /* just timer clean up */
    ncc_commit_confirmed();

cleanup:
    if (!sev.sival_int) {
        /* UNLOCK */
        pthread_mutex_unlock(&commit_ctx.lock);

        /* send notification about timeout for confirmed-commits */
        np_send_notif_confirmed_commit(commit_ctx.nc_sess, sr_sess, NP_CC_TIMEOUT, 0, 0);
    }
    sr_release_context(np2srv.sr_conn);
    if (user_sess) {
        if (nacm_user) {
            sr_nacm_set_user(sr_sess, nacm_user);
            free(nacm_user);
        }
        np_release_user_sess(user_sess);
    } else {
        sr_session_stop(sr_sess);
    }
    closedir(dir);
    free(path);
    free(srv_path);
    free(meta);
    free(module_name);
}

void
ncc_del_session(const struct nc_session *nc_sess, sr_session_ctx_t *sr_sess)
{
    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);

    if (commit_ctx.timer && !commit_ctx.persist && (commit_ctx.nc_sess == nc_sess)) {
        /* rollback */
        VRB("Performing confirmed commit rollback after the issuing session has terminated.");
        ncc_changes_rollback_cb((union sigval)1);

        /* send notification about canceling confirmed-commits */
        np_send_notif_confirmed_commit(nc_sess, sr_sess, NP_CC_CANCEL, 0, 0);
    }

    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);
}

/**
 * @brief Backup a module into a file
 *
 * @param[in] session Sysrepo session used to get data of the module.
 * @param[in] module Module to backup.
 * @return SR_ERR_LY When printing into the file failed.
 * @return SR_ERR_NO_MEMORY When memory ran during allocation
 * @return SR_ERR_OK On success
 */
static int
ncc_backup_module(sr_session_ctx_t *session, const struct lys_module *module)
{
    int rc = SR_ERR_OK;
    char *path = NULL, *xpath = NULL, *ncc_path = NULL;
    sr_data_t *data = NULL;

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

    if ((rc = sr_get_data(session, xpath, 0, 0, 0, &data))) {
        ERR("Failed getting configuration of running for module \"%s\" (%s).", module->name, sr_strerror(rc));
        goto cleanup;
    }

    if (asprintf(&path, "%s/%s.json", ncc_path, module->name) == -1) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if (lyd_print_path(path, data ? data->tree : NULL, LYD_JSON, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK)) {
        ERR("Failed backing up node of module \"%s\" into file \"%s\".", module->name, path);
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    sr_release_data(data);
    free(ncc_path);
    free(path);
    free(xpath);
    return rc;
}

/**
 * @brief Schedule a rollback of confirmed commit. Create the timer and set all the options.
 *
 * @param[in] timeout_s Time (in seconds) after which the timer will start the rollback.
 * @return SR_ERR_SYS on timer creation failure.
 * @return SR_ERR_OK on succeeded.
 */
static int
ncc_commit_timeout_schedule(uint32_t timeout_s)
{
    struct sigevent sev = {0};
    struct itimerspec its = {0};
    timer_t timer_id;

    assert(!commit_ctx.timer);

    VRB("Scheduling confirmed commit rollback in %" PRIu32 "s.", timeout_s);

    if (!timeout_s) {
        /* just perform the rollback without locking */
        ncc_changes_rollback_cb((union sigval)1);
    } else {
        /* create and arm the timer */
        sev.sigev_notify = SIGEV_THREAD;
        sev.sigev_value = (union sigval)0;
        sev.sigev_notify_function = ncc_changes_rollback_cb;
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
    }

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
ncc_read_meta_file(time_t *time, uint32_t *timeout_s)
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

    file = fopen(meta, "r");
    if (!file) {
        if (errno != ENOENT) {
            ERR("Confirmed commit meta file opening failed (%s).", strerror(errno));
            rc = SR_ERR_SYS;
        } /* else does not exist */
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
    time_t timestamp = 0;
    uint32_t timeout = 0;

    /* it should be under a mutex, but since it is called in init it is not needed */

    if (ncc_read_meta_file(&timestamp, &timeout)) {
        return;
    }
    if (!timestamp) {
        /* no meta file existed */
        return;
    }

    VRB("Performing confirmed commit rollback after server restart.");
    ncc_changes_rollback_cb((union sigval)1);
}

/**
 * @brief Create backup files for all implemented modules
 *
 * @return SR_ERR_OK When successful.
 */
static int
ncc_running_backup(void)
{
    int rc = SR_ERR_OK, read = 0, write = 0;
    const struct ly_ctx *ly_ctx;
    sr_session_ctx_t *session;
    struct lys_module *module;
    uint32_t index = 0;

    ly_ctx = sr_acquire_context(np2srv.sr_conn);

    if ((rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &session))) {
        ERR("Failed starting a sysrepo session (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* iterate over all implemented modules */
    if ((rc = ncc_check_server_dir())) {
        goto cleanup;
    }
    while ((module = ly_ctx_get_module_iter(ly_ctx, &index))) {
        /* check if module should and can be backed up */
        if (!module->implemented) {
            continue;
        }
        if (!np_ly_mod_has_data(module, LYS_CONFIG_W)) {
            continue;
        }
        if (!strcmp(module->name, "sysrepo")) {
            continue;
        }

        /* Check if has both read and write permission for module in sysrepo */
        if ((rc = sr_check_module_ds_access(np2srv.sr_conn, module->name, SR_DS_RUNNING, &read, &write))) {
            ERR("Failed getting permissions of module \"%s\".", module->name);
            goto cleanup;
        }
        if (!read || !write) {
            continue;
        }

        /* Create the backup */
        if ((rc = ncc_backup_module(session, module))) {
            ERR("Failed creating backup of module \"%s\".", module->name);
            goto cleanup;
        }
    }

cleanup:
    sr_release_context(np2srv.sr_conn);
    sr_session_stop(session);
    return rc;
}

/**
 * @brief Create a file containing metadata about confirmed commit. Used when restoring after crash.
 *
 * @param[in] timeout_s Timeout (in seconds) that was used for the confirmed commit.
 */
static void
ncc_create_meta_file(uint32_t timeout_s)
{
    int fd = -1;
    FILE *file = NULL;
    char *meta;

    if (asprintf(&meta, "%s/%s/%s", np2srv.server_dir, NCC_DIR, META_FILE) < 0) {
        EMEM;
        goto cleanup;
    }

    fd = open(meta, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        WRN("Failed creating confirmed commit meta file. Changes will not recover in case the server is stopped.");
        goto cleanup;
    }

    file = fdopen(fd, "w");
    if (!file) {
        WRN("Failed creating confirmed commit meta file. Changes will not recover in case the server is stopped.");
        goto cleanup;
    }
    fd = -1;

    fprintf(file, "%ld\n%" PRIu32 "\n", (long)time(NULL), timeout_s);

cleanup:
    if (fd > -1) {
        close(fd);
    }
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
    struct np2_user_sess *user_sess = NULL;
    struct nc_session *nc_sess;
    const sr_error_info_t *err_info;
    const char *persist = NULL;
    struct lyd_node *node = NULL;
    char *endptr = NULL;
    uint32_t timeout;
    uint8_t timeout_changed = 0;

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, &nc_sess, &user_sess))) {
        goto cleanup;
    }
    if ((rc = sr_session_switch_ds(user_sess->sess, SR_DS_RUNNING))) {
        goto cleanup;
    }

    /* confirm-timeout */
    lyd_find_path(input, "confirm-timeout", 0, &node);
    assert(node);
    timeout = strtoul(lyd_get_value(node), &endptr, 10);
    if (*endptr) {
        ERR("Invalid timeout \"%s\" given", lyd_get_value(node));
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* persist */
    if (!lyd_find_path(input, "persist", 0, &node)) {
        persist = lyd_get_value(node);
    }

    /* persist-id */
    if (!lyd_find_path(input, "persist-id", 0, &node)) {
        ERR("Persist-id given in confirmed commit rpc.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (!commit_ctx.timer) {
        /* create and store the backup */
        if (ncc_running_backup()) {
            goto cleanup;
        }
    } else {
        if (commit_ctx.persist) {
            if (!persist || strcmp(persist, commit_ctx.persist)) {
                np_err_invalid_value(session, "Follow-up confirm commit does not match pending confirmed commit.", "persist");
                rc = SR_ERR_INVAL_ARG;
                goto cleanup;
            }
        } else {
            assert(commit_ctx.nc_sess);
            if (commit_ctx.nc_sess != nc_sess) {
                np_err_operation_failed(session,
                        "Follow-up confirm commit session does not match the pending confirmed commit session.");
                rc = SR_ERR_OPERATION_FAILED;
                goto cleanup;
            }
        }

        /* there is already a pending confirmed commit, keep its backup, but the timeout will be reset */
        timer_delete(commit_ctx.timer);
        commit_ctx.timer = 0;
        timeout_changed = 1;
    }

    /* (re)set the meta file timeout */
    ncc_create_meta_file(timeout);

    /* set persist or NC session */
    if (persist) {
        if (ncc_set_persist(persist)) {
            goto cleanup;
        }
    } else {
        commit_ctx.nc_sess = nc_sess;
    }

    /* (re)schedule the timer thread for rollback */
    if (ncc_commit_timeout_schedule(timeout)) {
        goto cleanup;
    }

    if (timeout_changed) {
        /* send notification about extending timeout for confirmed-commits */
        np_send_notif_confirmed_commit(nc_sess, session, NP_CC_EXTEND, timeout, 0);
    } else {
        /* send notification about starting confirmed-commits */
        np_send_notif_confirmed_commit(nc_sess, session, NP_CC_START, timeout, 0);
    }

    /* sysrepo API */
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout);
    if (rc == SR_ERR_LOCKED) {
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
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess = NULL;
    struct nc_session *nc_sess;
    struct lyd_node *node;
    const sr_error_info_t *err_info;
    const char *persist_id = NULL, *persist;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);

    /* check if confirmed-commit */
    if (!lyd_find_path(input, "confirmed", 0, NULL)) {
        rc = np2srv_confirmed_commit_cb(session, input);
        goto cleanup;
    }

    /* persist-id */
    if (!lyd_find_path(input, "persist-id", 0, &node)) {
        persist_id = lyd_get_value(node);
    }

    persist = commit_ctx.persist;
    if ((persist && !persist_id) || (!persist && persist_id) || (persist && persist_id && strcmp(persist, persist_id))) {
        np_err_invalid_value(session, "Commit does not match pending confirmed commit.", "persist_id");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* get the user session */
    if ((rc = np_find_user_sess(session, __func__, &nc_sess, &user_sess))) {
        goto cleanup;
    }

    /* if there is a commit waiting to be confirmed, confirm it */
    if (commit_ctx.timer) {
        if (!persist_id && (commit_ctx.nc_sess != nc_sess)) {
            np_err_operation_failed(session, "Commit session does not match the pending confirmed commit session.");
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup;
        }
        ncc_commit_confirmed();

        /* send notification about complete confirmed-commits */
        np_send_notif_confirmed_commit(nc_sess, session, NP_CC_COMPLETE, 0, 0);
    }

    /* sysrepo API */
    sr_session_switch_ds(user_sess->sess, SR_DS_RUNNING);
    rc = sr_copy_config(user_sess->sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout);
    if (rc == SR_ERR_LOCKED) {
        /* NETCONF error */
        sr_session_get_error(user_sess->sess, &err_info);
        np_err_sr2nc_in_use(session, err_info);
    } else if (rc) {
        /* Sysrepo error */
        sr_session_dup_error(user_sess->sess, session);
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_cancel_commit_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    int rc = SR_ERR_OK, is_locked;
    struct nc_session *nc_sess;
    struct lyd_node *node;
    const char *persist_id = NULL, *persist = NULL;
    uint32_t sr_id;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get the NC session */
    if ((rc = np_find_user_sess(session, __func__, &nc_sess, NULL))) {
        goto cleanup;
    }

    /* persist-id */
    if (!lyd_find_path(input, "persist-id", 0, &node)) {
        persist_id = lyd_get_value(node);
    }

    /* LOCK */
    pthread_mutex_lock(&commit_ctx.lock);

    /* check there is a confirmed commit to cancel */
    if (!commit_ctx.timer) {
        np_err_invalid_value(session, "No pending confirmed commit to cancel.", NULL);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* check persist-id */
    persist = commit_ctx.persist;
    if ((persist && !persist_id) || (!persist && persist_id) || (persist && persist_id && strcmp(persist, persist_id))) {
        np_err_invalid_value(session, "Cancel commit does not match pending confirmed commit.", persist_id);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (!persist_id) {
        /* non-persist pending confirmed commit and session issuing the <cancel-commit> does not match
         * the one issuing <commit> */
        if (commit_ctx.nc_sess != nc_sess) {
            np_err_operation_failed(session, "Cancel commit session does not match the pending confirmed commit session.");
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup;
        }
    } else {
        /* make sure the running datastore in unlocked */
        if ((rc = sr_get_lock(np2srv.sr_conn, SR_DS_RUNNING, NULL, &is_locked, &sr_id, NULL))) {
            np_err_operation_failed(session, "Failed to learn the lock state of the <running> datastore.");
            goto cleanup;
        } else if (is_locked && (sr_session_get_id(((struct np2_user_sess *)nc_session_get_data(nc_sess))->sess) != sr_id)) {
            np_err_in_use(session, sr_id);
            rc = SR_ERR_LOCKED;
            goto cleanup;
        }

        /* persist commit, set the NC session to use for the rollback */
        assert(!commit_ctx.nc_sess);
        commit_ctx.nc_sess = nc_sess;
    }

    /* rollback */
    VRB("Performing confirmed commit rollback after receiving <cancel-commit>.");
    ncc_changes_rollback_cb((union sigval)1);

    /* send notification about canceling confirmed-commits */
    np_send_notif_confirmed_commit(nc_sess, session, NP_CC_CANCEL, 0, 0);

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&commit_ctx.lock);
    return rc;
}
