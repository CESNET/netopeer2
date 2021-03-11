/**
 * @file netconf_acm.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NACM and ietf-netconf-acm callbacks
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "log.h"
#include "netconf_acm.h"

static struct ncac nacm;

/* /ietf-netconf-acm:nacm */
int
ncac_nacm_params_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "enable-nacm")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (((struct lyd_node_leaf_list *)node)->value.bln) {
                    nacm.enabled = 1;
                } else {
                    nacm.enabled = 0;
                }
            }
        } else if (!strcmp(node->schema->name, "read-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(((struct lyd_node_leaf_list *)node)->value_str, "permit")) {
                    nacm.default_read_deny = 0;
                } else {
                    nacm.default_read_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "write-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(((struct lyd_node_leaf_list *)node)->value_str, "permit")) {
                    nacm.default_write_deny = 0;
                } else {
                    nacm.default_write_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "exec-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(((struct lyd_node_leaf_list *)node)->value_str, "permit")) {
                    nacm.default_exec_deny = 0;
                } else {
                    nacm.default_exec_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "enable-external-groups")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (((struct lyd_node_leaf_list *)node)->value.bln) {
                    nacm.enable_external_groups = 1;
                } else {
                    nacm.enable_external_groups = 0;
                }
            }
        }
    }

    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/denied-* */
int
ncac_state_data_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name), const char *path,
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *node;
    char num_str[11];

    assert(*parent);

    pthread_mutex_lock(&nacm.lock);

    if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-operations")) {
        sprintf(num_str, "%u", nacm.denied_operations);
        node = lyd_new_path(*parent, NULL, "denied-operations", num_str, 0, 0);
    } else if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-data-writes")) {
        sprintf(num_str, "%u", nacm.denied_data_writes);
        node = lyd_new_path(*parent, NULL, "denied-data-writes", num_str, 0, 0);
    } else {
        assert(!strcmp(path, "/ietf-netconf-acm:nacm/denied-notifications"));
        sprintf(num_str, "%u", nacm.denied_notifications);
        node = lyd_new_path(*parent, NULL, "denied-notifications", num_str, 0, 0);
    }

    pthread_mutex_unlock(&nacm.lock);

    if (!node) {
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/groups/group */
int
ncac_group_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list, *group_name, *user_name;
    struct ncac_group *group = NULL;
    struct ly_ctx *ly_ctx;
    uint32_t i, j;
    char *xpath2;
    bool prev_dflt;
    int rc;
    void *mem;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "group")) {
            /* name must be present */
            assert(!strcmp(node->child->schema->name, "name"));
            group_name = ((struct lyd_node_leaf_list *)node->child)->value_str;

            switch (op) {
            case SR_OP_CREATED:
                /* add new group */
                mem = realloc(nacm.groups, (nacm.group_count + 1) * sizeof *nacm.groups);
                if (!mem) {
                    EMEM;
                    pthread_mutex_unlock(&nacm.lock);
                    return SR_ERR_NOMEM;
                }
                nacm.groups = mem;
                group = &nacm.groups[nacm.group_count];
                ++nacm.group_count;

                group->name = lydict_insert(ly_ctx, group_name, 0);
                group->users = NULL;
                group->user_count = 0;
                break;
            case SR_OP_DELETED:
                /* find it */
                for (i = 0; i < nacm.group_count; ++i) {
                    /* both in dictionary */
                    if (nacm.groups[i].name == group_name) {
                        group = &nacm.groups[i];
                        break;
                    }
                }
                assert(i < nacm.group_count);

                /* delete it */
                lydict_remove(ly_ctx, group->name);
                for (j = 0; j < group->user_count; ++j) {
                    lydict_remove(ly_ctx, group->users[j]);
                }
                free(group->users);

                --nacm.group_count;
                if (i < nacm.group_count) {
                    memcpy(group, &nacm.groups[nacm.group_count], sizeof *group);
                }
                if (!nacm.group_count) {
                    free(nacm.groups);
                    nacm.groups = NULL;
                }
                group = NULL;
                break;
            default:
                EINT;
                pthread_mutex_unlock(&nacm.lock);
                return SR_ERR_INTERNAL;
            }
        } else {
            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            group_name = ((struct lyd_node_leaf_list *)node->parent->child)->value_str;
            group = NULL;
            for (i = 0; i < nacm.group_count; ++i) {
                /* both in dictionary */
                if (nacm.groups[i].name == group_name) {
                    group = &nacm.groups[i];
                    break;
                }
            }

            if (!strcmp(node->schema->name, "user-name")) {
                if ((op == SR_OP_DELETED) && !group) {
                    continue;
                }

                assert(group);
                user_name = ((struct lyd_node_leaf_list *)node)->value_str;

                if (op == SR_OP_CREATED) {
                    mem = realloc(group->users, (group->user_count + 1) * sizeof *group->users);
                    if (!mem) {
                        EMEM;
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NOMEM;
                    }
                    group->users = mem;
                    group->users[group->user_count] = (char *)lydict_insert(ly_ctx, user_name, 0);
                    ++group->user_count;
                } else {
                    assert(op == SR_OP_DELETED);
                    for (i = 0; i < group->user_count; ++i) {
                        /* both in dictionary */
                        if (group->users[i] == user_name) {
                            break;
                        }
                    }
                    assert(i < group->user_count);

                    /* delete it */
                    lydict_remove(ly_ctx, group->users[i]);
                    --group->user_count;
                    if (i < group->user_count) {
                        group->users[i] = group->users[group->user_count];
                    }
                    if (!group->user_count) {
                        free(group->users);
                        group->users = NULL;
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

static void
ncac_remove_rules(struct ncac_rule_list *list)
{
    struct ncac_rule *rule, *tmp;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    LY_TREE_FOR_SAFE(list->rules, tmp, rule) {
        lydict_remove(ly_ctx, rule->name);
        lydict_remove(ly_ctx, rule->module_name);
        lydict_remove(ly_ctx, rule->target);
        lydict_remove(ly_ctx, rule->comment);
        free(rule);
    }
    list->rules = NULL;
}

/* /ietf-netconf-acm:nacm/rule-list */
int
ncac_rule_list_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    struct ly_ctx *ly_ctx;
    const char *prev_val, *prev_list, *rlist_name, *group_name;
    struct ncac_rule_list *rlist = NULL, *prev_rlist;
    char *xpath2;
    bool prev_dflt;
    int rc, len;
    uint32_t i;
    void *mem;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "rule-list")) {
            /* name must be present */
            assert(!strcmp(node->child->schema->name, "name"));
            rlist_name = ((struct lyd_node_leaf_list *)node->child)->value_str;

            switch (op) {
            case SR_OP_MOVED:
                /* find it */
                prev_rlist = NULL;
                for (rlist = nacm.rule_lists; rlist && (rlist->name != rlist_name); rlist = rlist->next) {
                    prev_rlist = rlist;
                }
                assert(rlist);

                /* unlink it */
                if (prev_rlist) {
                    prev_rlist->next = rlist->next;
                } else {
                    nacm.rule_lists = rlist->next;
                }
                /* fallthrough */
            case SR_OP_CREATED:
                if (op == SR_OP_CREATED) {
                    /* create new rule list */
                    rlist = calloc(1, sizeof *rlist);
                    if (!rlist) {
                        EMEM;
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NOMEM;
                    }
                    rlist->name = lydict_insert(ly_ctx, rlist_name, 0);
                }

                /* find previous list */
                assert(prev_list);
                if (prev_list[0]) {
                    assert(strchr(prev_list, '\''));
                    prev_list = strchr(prev_list, '\'') + 1;
                    len = strchr(prev_list, '\'') - prev_list;
                    prev_rlist = nacm.rule_lists;
                    while (prev_rlist && strncmp(prev_rlist->name, prev_list, len)) {
                        prev_rlist = prev_rlist->next;
                    }
                    assert(prev_rlist);
                } else {
                    prev_rlist = NULL;
                }

                /* insert after previous list */
                if (prev_rlist) {
                    rlist->next = prev_rlist->next;
                    prev_rlist->next = rlist;
                } else {
                    rlist->next = nacm.rule_lists;
                    nacm.rule_lists = rlist;
                }
                break;
            case SR_OP_DELETED:
                /* find it */
                prev_rlist = NULL;
                for (rlist = nacm.rule_lists; rlist && (rlist->name != rlist_name); rlist = rlist->next) {
                    prev_rlist = rlist;
                }
                assert(rlist);

                /* delete it */
                lydict_remove(ly_ctx, rlist->name);
                for (i = 0; i < rlist->group_count; ++i) {
                    lydict_remove(ly_ctx, rlist->groups[i]);
                }
                free(rlist->groups);
                ncac_remove_rules(rlist);
                if (prev_rlist) {
                    prev_rlist->next = rlist->next;
                } else {
                    nacm.rule_lists = rlist->next;
                }
                free(rlist);
                rlist = NULL;
                break;
            default:
                EINT;
                pthread_mutex_unlock(&nacm.lock);
                return SR_ERR_INTERNAL;
            }
        } else {
            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rlist_name = ((struct lyd_node_leaf_list *)node->parent->child)->value_str;
            for (rlist = nacm.rule_lists; rlist && (rlist->name != rlist_name); rlist = rlist->next);

            if (!strcmp(node->schema->name, "group")) {
                if ((op == SR_OP_DELETED) && !rlist) {
                    continue;
                }

                assert(rlist);
                group_name = ((struct lyd_node_leaf_list *)node)->value_str;

                if (op == SR_OP_CREATED) {
                    mem = realloc(rlist->groups, (rlist->group_count + 1) * sizeof *rlist->groups);
                    if (!mem) {
                        EMEM;
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NOMEM;
                    }
                    rlist->groups = mem;
                    rlist->groups[rlist->group_count] = (char *)lydict_insert(ly_ctx, group_name, 0);
                    ++rlist->group_count;
                } else {
                    assert(op == SR_OP_DELETED);
                    for (i = 0; i < rlist->group_count; ++i) {
                        /* both in dictionary */
                        if (rlist->groups[i] == group_name) {
                            break;
                        }
                    }
                    assert(i < rlist->group_count);

                    /* delete it */
                    lydict_remove(ly_ctx, rlist->groups[i]);
                    --rlist->group_count;
                    if (i < rlist->group_count) {
                        rlist->groups[i] = rlist->groups[rlist->group_count];
                    }
                    if (!rlist->group_count) {
                        free(rlist->groups);
                        rlist->groups = NULL;
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/rule-list/rule */
int
ncac_rule_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
        uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    struct ly_ctx *ly_ctx;
    const char *prev_val, *prev_list, *rule_name, *rlist_name, *str;
    struct ncac_rule_list *rlist;
    struct ncac_rule *rule = NULL, *prev_rule;
    char *xpath2;
    bool prev_dflt;
    int rc, len;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "rule")) {
            /* find parent rule list */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rlist_name = ((struct lyd_node_leaf_list *)node->parent->child)->value_str;
            for (rlist = nacm.rule_lists; rlist && (rlist->name != rlist_name); rlist = rlist->next);
            if ((op == SR_OP_DELETED) && !rlist) {
                /* even parent rule-list was deleted */
                continue;
            }
            assert(rlist);

            /* name must be present */
            assert(!strcmp(node->child->schema->name, "name"));
            rule_name = ((struct lyd_node_leaf_list *)node->child)->value_str;

            switch (op) {
            case SR_OP_MOVED:
                /* find it */
                prev_rule = NULL;
                for (rule = rlist->rules; rule && (rule->name != rule_name); rule = rule->next) {
                    prev_rule = rule;
                }
                assert(rule);

                /* unlink it */
                if (prev_rule) {
                    prev_rule->next = rule->next;
                } else {
                    rlist->rules = rule->next;
                }
                /* fallthrough */
            case SR_OP_CREATED:
                if (op == SR_OP_CREATED) {
                    /* create new rule */
                    rule = calloc(1, sizeof *rule);
                    if (!rule) {
                        EMEM;
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NOMEM;
                    }
                    rule->name = lydict_insert(ly_ctx, rule_name, 0);
                    rule->target_type = NCAC_TARGET_ANY;
                }
                assert(rule);

                /* find previous rule */
                assert(prev_list);
                if (prev_list[0]) {
                    assert(strchr(prev_list, '\''));
                    prev_list = strchr(prev_list, '\'') + 1;
                    len = strchr(prev_list, '\'') - prev_list;
                    prev_rule = rlist->rules;
                    while (prev_rule && strncmp(prev_rule->name, prev_list, len)) {
                        prev_rule = prev_rule->next;
                    }
                    assert(prev_rule);
                } else {
                    prev_rule = NULL;
                }

                /* insert after previous rule */
                if (prev_rule) {
                    rule->next = prev_rule->next;
                    prev_rule->next = rule;
                } else {
                    rule->next = rlist->rules;
                    rlist->rules = rule;
                }
                break;
            case SR_OP_DELETED:
                /* find it */
                prev_rule = NULL;
                for (rule = rlist->rules; rule && (rule->name != rule_name); rule = rule->next) {
                    prev_rule = rule;
                }
                assert(rule);

                /* delete it */
                lydict_remove(ly_ctx, rule->name);
                lydict_remove(ly_ctx, rule->module_name);
                lydict_remove(ly_ctx, rule->target);
                lydict_remove(ly_ctx, rule->comment);
                if (prev_rule) {
                    prev_rule->next = rule->next;
                } else {
                    rlist->rules = rule->next;
                }
                free(rule);
                break;
            default:
                EINT;
                pthread_mutex_unlock(&nacm.lock);
                return SR_ERR_INTERNAL;
            }
        } else {
            /* find parent rule list */
            assert(!strcmp(node->parent->parent->child->schema->name, "name"));
            rlist_name = ((struct lyd_node_leaf_list *)node->parent->parent->child)->value_str;
            for (rlist = nacm.rule_lists; rlist && (rlist->name != rlist_name); rlist = rlist->next);
            if ((op == SR_OP_DELETED) && !rlist) {
                /* even parent rule-list was deleted */
                continue;
            }
            assert(rlist);

            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rule_name = ((struct lyd_node_leaf_list *)node->parent->child)->value_str;
            for (rule = rlist->rules; rule && (rule->name != rule_name); rule = rule->next);
            if ((op == SR_OP_DELETED) && !rule) {
                /* even parent rule was deleted */
                continue;
            }
            assert(rule);

            if (!strcmp(node->schema->name, "module-name")) {
                str = ((struct lyd_node_leaf_list *)node)->value_str;
                lydict_remove(ly_ctx, rule->module_name);
                if (!strcmp(str, "*")) {
                    rule->module_name = NULL;
                } else {
                    rule->module_name = lydict_insert(ly_ctx, str, 0);
                }
            } else if (!strcmp(node->schema->name, "rpc-name") || !strcmp(node->schema->name, "notification-name")
                        || !strcmp(node->schema->name, "path")) {
                if (op == SR_OP_DELETED) {
                    lydict_remove(ly_ctx, rule->target);
                    rule->target = NULL;
                    rule->target_type = NCAC_TARGET_ANY;
                } else {
                    str = ((struct lyd_node_leaf_list *)node)->value_str;
                    lydict_remove(ly_ctx, rule->target);
                    if (!strcmp(str, "*")) {
                        rule->target = NULL;
                    } else {
                        rule->target = lydict_insert(ly_ctx, str, 0);
                    }
                    if (!strcmp(node->schema->name, "rpc-name")) {
                        rule->target_type = NCAC_TARGET_RPC;
                    } else if (!strcmp(node->schema->name, "notification-name")) {
                        rule->target_type = NCAC_TARGET_NOTIF;
                    } else {
                        assert(!strcmp(node->schema->name, "path"));
                        rule->target_type = NCAC_TARGET_DATA;
                    }
                }
            } else if (!strcmp(node->schema->name, "access-operations")) {
                str = ((struct lyd_node_leaf_list *)node)->value_str;
                rule->operations = 0;
                if (!strcmp(str, "*")) {
                    rule->operations = NCAC_OP_ALL;
                } else {
                    if (strstr(str, "create")) {
                        rule->operations |= NCAC_OP_CREATE;
                    }
                    if (strstr(str, "read")) {
                        rule->operations |= NCAC_OP_READ;
                    }
                    if (strstr(str, "update")) {
                        rule->operations |= NCAC_OP_UPDATE;
                    }
                    if (strstr(str, "delete")) {
                        rule->operations |= NCAC_OP_DELETE;
                    }
                    if (strstr(str, "exec")) {
                        rule->operations |= NCAC_OP_EXEC;
                    }
                }
            } else if (!strcmp(node->schema->name, "action")) {
                if (!strcmp(((struct lyd_node_leaf_list *)node)->value_str, "permit")) {
                    rule->action_deny = 0;
                } else {
                    rule->action_deny = 1;
                }
            } else if (!strcmp(node->schema->name, "comment")) {
                if (op == SR_OP_DELETED) {
                    lydict_remove(ly_ctx, rule->comment);
                    rule->comment = NULL;
                } else {
                    assert((op == SR_OP_MODIFIED) || (op == SR_OP_CREATED));
                    lydict_remove(ly_ctx, rule->comment);
                    rule->comment = lydict_insert(ly_ctx, ((struct lyd_node_leaf_list *)node)->value_str, 0);
                }
            }
        }
    }

    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

enum ncac_access {
    NCAC_ACCESS_DENY = 1,           /**< access to the node is denied */
    NCAC_ACCESS_PARTIAL_DENY = 2,   /**< access to the node is denied but it is a prefix of a matching rule */
    NCAC_ACCESS_PARTIAL_PERMIT = 3, /**< access to the node is permitted but any children must still be checked */
    NCAC_ACCESS_PERMIT = 4          /**< access to the node is permitted with any children */
};

#define NCAC_ACCESS_IS_NODE_PERMIT(x) ((x) > 2)

void
ncac_init(void)
{
    pthread_mutex_init(&nacm.lock, NULL);
}

void
ncac_destroy(void)
{
    struct ncac_group *group;
    struct ncac_rule_list *rule_list, *tmp;
    struct ly_ctx *ly_ctx;
    uint32_t i, j;

    ly_ctx = (struct ly_ctx *)sr_get_context(np2srv.sr_conn);

    for (i = 0; i < nacm.group_count; ++i) {
        group = &nacm.groups[i];
        lydict_remove(ly_ctx, group->name);
        for (j = 0; j < group->user_count; ++j) {
            lydict_remove(ly_ctx, group->users[j]);
        }
        free(group->users);
    }
    free(nacm.groups);

    LY_TREE_FOR_SAFE(nacm.rule_lists, tmp, rule_list) {
        lydict_remove(ly_ctx, rule_list->name);
        for (i = 0; i < rule_list->group_count; ++i) {
            lydict_remove(ly_ctx, rule_list->groups[i]);
        }
        free(rule_list->groups);
        ncac_remove_rules(rule_list);
        free(rule_list);
    }

    pthread_mutex_destroy(&nacm.lock);
}

/**
 * @brief Get passwd entry of a user, specifically its UID and GID.
 *
 * @param[in] user User to learn about.
 * @param[out] uid User UID, if set.
 * @param[out] gid User GID, if set.
 * @return 0 on success, 1 on user not found, -1 on error.
 */
static int
ncac_getpwnam(const char *user, uid_t *uid, gid_t *gid)
{
    struct passwd pwd, *pwd_p;
    char *buf = NULL;
    ssize_t buflen;
    int ret;

    assert(user);

    buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen == -1) {
        buflen = 2048;
    }
    buf = malloc(buflen);
    if (!buf) {
        EMEM;
        return -1;
    }
    ret = getpwnam_r(user, &pwd, buf, buflen, &pwd_p);
    if (ret) {
        ERR("Getting user \"%s\" pwd entry failed (%s).", user, strerror(ret));
        free(buf);
        return -1;
    } else if (!pwd_p) {
        free(buf);
        return 1;
    }

    if (uid) {
        *uid = pwd.pw_uid;
    }
    if (gid) {
        *gid = pwd.pw_gid;
    }
    free(buf);
    return 0;
}

/**
 * @brief Check NACM acces for the data tree. If this check passes, no other check is necessary.
 * If not, each node must be checked separately to decide.
 *
 * @param[in] top_node Top-level node of the data.
 * @param[in] user User, whose access to check.
 * @return non-zero if access allowed, 0 if more checks are required.
 */
static int
ncac_allowed_tree(const struct lys_node *top_node, const char *user)
{
    struct lys_node *parent;
    uid_t user_uid;

    for (parent = lys_parent(top_node); parent && (parent->nodetype & (LYS_USES | LYS_CASE | LYS_CHOICE)); parent = lys_parent(parent));
    if (parent) {
        EINT;
        return 0;
    }

    /* 1) NACM is off */
    if (!nacm.enabled) {
        return 1;
    }

    /* 2) recovery session allowed */
    if (!ncac_getpwnam(user, &user_uid, NULL) && (user_uid == NP2SRV_NACM_RECOVERY_UID)) {
        return 1;
    }

    /* 3) <close-session> and notifications <replayComplete>, <notificationComplete> always allowed */
    if ((top_node->nodetype == LYS_RPC) && !strcmp(top_node->name, "close-session")
            && !strcmp(lys_node_module(top_node)->name, "ietf-netconf")) {
        return 1;
    } else if ((top_node->nodetype == LYS_NOTIF) && !strcmp(lys_node_module(top_node)->name, "nc-notifications")) {
        return 1;
    }

    /* 4) <get>, <get-config>, and <get-data> not checked for execute permission - RFC 8341 section 3.2.4
     * (assume it is the same for <get-data>) */
    if ((top_node->nodetype == LYS_RPC) && (((!strcmp(top_node->name, "get") || !strcmp(top_node->name, "get-config"))
            && !strcmp(lys_node_module(top_node)->name, "ietf-netconf")) || (!strcmp(top_node->name, "get-data")
            && !strcmp(lys_node_module(top_node)->name, "ietf-netconf-nmda")))) {
        return 1;
    }

    return 0;
}

/**
 * @brief Collect all NACM groups for a user. If enabled, even system ones.
 *
 * @param[in] ly_ctx libyang context for dictionary.
 * @param[in] user User to collect groups for.
 * @param[out] groups Array of collected groups.
 * @param[out] group_count Number of collected groups.
 * @return 0 on success, -1 on error.
 */
static int
ncac_collect_groups(struct ly_ctx *ly_ctx, const char *user, char ***groups, uint32_t *group_count)
{
    struct group grp, *grp_p;
    gid_t user_gid;
    const char *user_dict = NULL, *grp_dict;
    char *buf = NULL;
    gid_t *gids = NULL;
    ssize_t buflen;
    uint32_t i, j;
    void *mem;
    int gid_count = 0, ret, rc = -1;

    user_dict = lydict_insert(ly_ctx, user, 0);

    *groups = NULL;
    *group_count = 0;

    /* collect NACM groups */
    for (i = 0; i < nacm.group_count; ++i) {
        for (j = 0; j < nacm.groups[i].user_count; ++j) {
            if (nacm.groups[i].users[j] == user_dict) {
                mem = realloc(*groups, (*group_count + 1) * sizeof **groups);
                if (!mem) {
                    EMEM;
                    goto cleanup;
                }
                *groups = mem;
                (*groups)[*group_count] = (char *)lydict_insert(ly_ctx, nacm.groups[i].name, 0);
                ++(*group_count);
            }
        }
    }

    /* collect system groups */
    if (nacm.enable_external_groups) {
        ret = ncac_getpwnam(user, NULL, &user_gid);
        if (ret) {
            if (ret == 1) {
                /* no user, no more groups */
                rc = 0;
            }
            goto cleanup;
        }

        /* get all GIDs */
        getgrouplist(user, user_gid, gids, &gid_count);
        gids = malloc(gid_count * sizeof *gids);
        if (!gids) {
            EMEM;
            goto cleanup;
        }
        ret = getgrouplist(user, user_gid, gids, &gid_count);
        if (ret == -1) {
            ERR("Getting system groups of user \"%s\" failed.", user);
            goto cleanup;
        }

        /* add all GIDs group names */
        buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (buflen == -1) {
            buflen = 2048;
        }
        free(buf);
        buf = malloc(buflen);
        if (!buf) {
            EMEM;
            goto cleanup;
        }
        for (i = 0; i < (unsigned)gid_count; ++i) {
            ret = getgrgid_r(gids[i], &grp, buf, buflen, &grp_p);
            if (ret) {
                ERR("Getting GID grp entry failed (%s).", strerror(ret));
                goto cleanup;
            } else if (!grp_p) {
                ERR("Getting GID grp entry failed (Group not found).");
                goto cleanup;
            }
            grp_dict = lydict_insert(ly_ctx, grp.gr_name, 0);

            /* check for duplicates */
            for (j = 0; j < *group_count; ++j) {
                if ((*groups)[j] == grp_dict) {
                    break;
                }
            }

            if (j < *group_count) {
                /* duplicate */
                lydict_remove(ly_ctx, grp_dict);
            } else {
                mem = realloc(*groups, (*group_count + 1) * sizeof *groups);
                if (!mem) {
                    EMEM;
                    goto cleanup;
                }
                *groups = mem;
                (*groups)[*group_count] = (char *)grp_dict;
                ++(*group_count);
            }
        }
    }

    /* success */
    rc = 0;

cleanup:
    free(gids);
    free(buf);
    lydict_remove(ly_ctx, user_dict);
    return rc;
}

/**
 * @brief Check NACM match of a node path and specific rule target.
 *
 * Details on matching in description of typedef ietf-netconf-acm:node-instance-identifier.
 *
 * @param[in] rule_target Rule target instance-identifier.
 * @param[in] node_path Node data path.
 * @return 0 if does not match.
 * @return 1 if the rule path matches.
 * @return 2 if the path is a partial match.
 */
static int
ncac_allowed_path(const char *rule_target, const char *node_path)
{
    const char *rule_ptr, *node_ptr;

    rule_ptr = rule_target;
    node_ptr = node_path;

    while (rule_ptr[0] && node_ptr[0]) {
        if (rule_ptr[0] == node_ptr[0]) {
            ++rule_ptr;
            ++node_ptr;
        } else if ((rule_ptr[0] == '/') && (node_ptr[0] == '[')) {
            /* target has no predicate, skip it in path as well because it matches any value */
            while (node_ptr[0] != ']') {
                if (node_ptr[0] == '\'') {
                    do {
                        ++node_ptr;
                    } while (node_ptr[0] != '\'');
                }

                ++node_ptr;
            }

            ++node_ptr;
        } else if ((rule_ptr[0] == ']') && (node_ptr[0] == '=')) {
            /* There is a key/value contained in the node_path but a only the key-name in the rule target. */
            while (node_ptr[0] != ']') {
                if (node_ptr[0] == '\'') {
                    do {
                        ++node_ptr;
                    } while (node_ptr[0] != '\'');
                }

                ++node_ptr;
            }

            ++node_ptr;
            /* Proceed to the character after the closing bracket. */
            ++rule_ptr;
        } else {
            /* not a match */
            return 0;
        }
    }

    if (!rule_ptr[0] && !node_ptr[0]) {
        /* full match */
        return 1;
    } else if (rule_ptr[0]) {
        assert(!node_ptr[0]);
        /* rule continues, it is a partial match */
        return 2;
    } else {
        assert(!rule_ptr[0]);
        /* node continues, prefix (descendant) match */
        return 1;
    }
}

/**
 * @brief Check NACM access for a single node.
 *
 * @param[in] node Node to check.
 * @param[in] user User, whose access to check.
 * @param[in] oper Operation to check.
 * @return NCAC access enum.
 */
static enum ncac_access
ncac_allowed_node(const struct lyd_node *node, const char *user, uint8_t oper)
{
    struct ncac_rule_list *rlist;
    struct ncac_rule *rule;
    struct ly_ctx *ly_ctx;
    char **groups, *path;
    uint32_t i, j, group_count;
    enum ncac_access access = NCAC_ACCESS_DENY, partial_access = NCAC_ACCESS_DENY;
    int path_match;

    assert(oper);

    ly_ctx = lyd_node_module(node)->ctx;

    /*
     * ref https://tools.ietf.org/html/rfc8341#section-3.4.4
     */

    /* 4) collect groups */
    if (ncac_collect_groups(ly_ctx, user, &groups, &group_count)) {
        goto cleanup;
    }

    /* 5) no groups */
    if (!group_count) {
        goto step10;
    }

    /* 6) find matching rule lists */
    for (rlist = nacm.rule_lists; rlist; rlist = rlist->next) {
        for (i = 0; i < rlist->group_count; ++i) {
            if (strcmp(rlist->groups[i], "*")) {
                for (j = 0; j < group_count; ++j) {
                    if (rlist->groups[i] == groups[j]) {
                        break;
                    }
                }
                if (j < group_count) {
                    /* match */
                    break;
                }
            } else {
                /* match for all groups */
                break;
            }
        }
        if (i == rlist->group_count) {
            /* no match */
            continue;
        }

        /* 7) find matching rules */
        for (rule = rlist->rules; rule; rule = rule->next) {
            /* module name matching */
            if (rule->module_name && (rule->module_name != lyd_node_module(node)->name)) {
                continue;
            }

            /* access operation matching */
            if (!(rule->operations & oper)) {
                continue;
            }

            /* target (rule) type matching */
            switch (rule->target_type) {
            case NCAC_TARGET_RPC:
                if (node->schema->nodetype != LYS_RPC) {
                    continue;
                }
                if (rule->target && (rule->target != node->schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case NCAC_TARGET_NOTIF:
                /* only top-level notification */
                if (lys_parent(node->schema) || (node->schema->nodetype != LYS_NOTIF)) {
                    continue;
                }
                if (rule->target && (rule->target != node->schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case NCAC_TARGET_DATA:
                if (node->schema->nodetype & (LYS_RPC | LYS_NOTIF)) {
                    continue;
                }
                /* fallthrough */
            case NCAC_TARGET_ANY:
                if (rule->target) {
                    path = lyd_path(node);
                    /* exact match or is a descendant (specified in RFC 8341 page 27) for full tree access */
                    path_match = ncac_allowed_path(rule->target, path);
                    free(path);
                    if (!path_match) {
                        continue;
                    } else if (path_match == 2) {
                        /* partial match, continue searching for a full match (only partial permit has some meaning,
                         * do not overwrite it) */
                        partial_access = rule->action_deny ? partial_access : NCAC_ACCESS_PARTIAL_PERMIT;
                        continue;
                    }
                }
                break;
            }

            /* 8) rule matched */
            access = rule->action_deny ? NCAC_ACCESS_DENY : NCAC_ACCESS_PERMIT;
            goto cleanup;
        }
    }

    /* 9) no matching rule found */

step10:
    /* 10) check default-deny-all extension */
    for (i = 0; i < node->schema->ext_size; ++i) {
        if (!strcmp(node->schema->ext[i]->def->module->name, "ietf-netconf-acm")) {
            if (!strcmp(node->schema->ext[i]->def->name, "default-deny-all")) {
                goto cleanup;
            }
            if ((oper & (NCAC_OP_CREATE | NCAC_OP_UPDATE | NCAC_OP_DELETE))
                    && !strcmp(node->schema->ext[i]->def->name, "default-deny-write")) {
                goto cleanup;
            }
        }
    }

    /* 11) was already covered in 10) */

    /* 12) check defaults */
    switch (oper) {
    case NCAC_OP_READ:
        if (nacm.default_read_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case NCAC_OP_CREATE:
    case NCAC_OP_UPDATE:
    case NCAC_OP_DELETE:
        if (nacm.default_write_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case NCAC_OP_EXEC:
        if (nacm.default_exec_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    default:
        EINT;
        goto cleanup;
    }

    if ((access == NCAC_ACCESS_DENY) && (partial_access == NCAC_ACCESS_PARTIAL_PERMIT)) {
        /* node itself is not allowed but a rule allows access to some descendants so it may be allowed at the end */
        access = NCAC_ACCESS_PARTIAL_DENY;
    }

cleanup:
    for (i = 0; i < group_count; ++i) {
        lydict_remove(ly_ctx, groups[i]);
    }
    free(groups);
    return access;
}

const struct lyd_node *
ncac_check_operation(const struct lyd_node *data, const char *user)
{
    const struct lyd_node *op;
    int allowed = 0;

    pthread_mutex_lock(&nacm.lock);

    /* check access for the whole data tree first */
    if (ncac_allowed_tree(data->schema, user)) {
        allowed = 1;
        goto cleanup;
    }

    op = data;
    while (op) {
        if (op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
            /* we found the desired node */
            break;
        }

        switch (op->schema->nodetype) {
        case LYS_CONTAINER:
        case LYS_LIST:
            if (!op->child) {
                /* list/container without children, invalid */
                op = NULL;
            } else {
                op = op->child;
            }
            break;
        case LYS_LEAF:
            assert(lys_is_key((struct lys_node_leaf *)op->schema, NULL));
            if (!op->next) {
                /* last key of the last in-depth list, invalid */
                op = NULL;
            } else {
                op = op->next;
            }
            break;
        default:
            op = NULL;
            break;
        }
    }
    if (!op) {
        EINT;
        goto cleanup;
    }

    if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
        /* check X access on the RPC/action */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(op, user, NCAC_OP_EXEC))) {
            goto cleanup;
        }
    } else {
        assert(op->schema->nodetype == LYS_NOTIF);

        /* check R access on the notification */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(op, user, NCAC_OP_READ))) {
            goto cleanup;
        }
    }

    if (op->parent) {
        /* check R access on the parents, the last parent must be enough */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(op->parent, user, NCAC_OP_READ))) {
            goto cleanup;
        }
    }

    allowed = 1;

cleanup:
    if (allowed) {
        op = NULL;
    } else {
        if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
            ++nacm.denied_operations;
        } else {
            ++nacm.denied_notifications;
        }
    }
    pthread_mutex_unlock(&nacm.lock);
    return op;
}

/**
 * @brief Filter out any siblings for which the user does not have R access, recursively.
 *
 * @param[in,out] first First sibling to filter.
 * @param[in] user User for the NACM filtering.
 * @return Highest access among descendants (recursively), permit is the highest.
 */
static enum ncac_access
ncac_check_data_read_filter_r(struct lyd_node **first, const char *user)
{
    struct lyd_node *next, *elem;
    enum ncac_access node_access, ret_access = NCAC_ACCESS_DENY;

    LY_TREE_FOR_SAFE(*first, next, elem) {
        /* check access of the node */
        node_access = ncac_allowed_node(elem, user, NCAC_OP_READ);

        if (node_access == NCAC_ACCESS_PARTIAL_DENY) {
            /* only partial deny access, we must check children recursively to learn whether this node is allowed or not */
            if (!(elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA))) {
                node_access = ncac_check_data_read_filter_r(&elem->child, user);
            }

            if (node_access != NCAC_ACCESS_PERMIT) {
                /* none of the descendants are actually permitted, access denied */
                node_access = NCAC_ACCESS_DENY;
            }
        } else if (node_access == NCAC_ACCESS_PARTIAL_PERMIT) {
            /* partial permit, the node will be included in the reply but we must check children as well */
            if (!(elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA))) {
                ncac_check_data_read_filter_r(&elem->child, user);
            }
            node_access = NCAC_ACCESS_PERMIT;
        }

        /* access denied, free the subtree */
        if (node_access == NCAC_ACCESS_DENY) {
            /* never free keys */
            if (!lys_is_key((struct lys_node_leaf *)elem->schema, NULL)) {
                if ((elem == *first) && !(*first)->parent) {
                    *first = (*first)->next;
                }
                lyd_free(elem);
            }
            continue;
        }

        /* access is permitted, update return access and check the next sibling */
        ret_access = NCAC_ACCESS_PERMIT;
    }

    return ret_access;
}

void
ncac_check_data_read_filter(struct lyd_node **data, const char *user)
{
    assert(data);

    pthread_mutex_lock(&nacm.lock);

    if (*data && !ncac_allowed_tree((*data)->schema, user)) {
        ncac_check_data_read_filter_r(data, user);
    }

    pthread_mutex_unlock(&nacm.lock);
}

/**
 * @brief Check whether diff node siblings can be applied by a user, recursively with children.
 *
 * @param[in] diff First diff sibling.
 * @param[in] user User for the NACM check.
 * @param[in] parent_op Inherited parent operation.
 * @return NULL if access allowed, otherwise the denied access data node.
 */
static const struct lyd_node *
ncac_check_diff_r(const struct lyd_node *diff, const char *user, const char *parent_op)
{
    const char *op;
    struct lyd_attr *attr;
    const struct lyd_node *node = NULL;
    uint8_t oper;

    LY_TREE_FOR(diff, diff) {
        /* find operation */
        LY_TREE_FOR(diff->attr, attr) {
            if (!strcmp(attr->name, "operation")) {
                assert(!strcmp(attr->annotation->module->name, "ietf-netconf") || !strcmp(attr->annotation->module->name, "sysrepo"));
                break;
            }
        }
        if (attr) {
            op = attr->value_str;
        } else {
            op = parent_op;
        }
        assert(op);

        /* get required access operation */
        switch (op[0]) {
        case 'n':
            /* "none" */
            oper = 0;
            break;
        case 'r':
            /* "replace" */
            assert(!strcmp(op, "replace"));
            oper = NCAC_OP_UPDATE;
            break;
        case 'c':
            /* "create" */
            oper = NCAC_OP_CREATE;
            break;
        case 'd':
            /* "delete" */
            oper = NCAC_OP_DELETE;
            break;
        default:
            EINT;
            return NULL;
        }

        /* check access for the node, none operation is always allowed, and partial access is relevant only for read operation */
        if (oper && !NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(diff, user, oper))) {
            node = diff;
            break;
        }

        /* go recursively */
        if (!(diff->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && diff->child) {
            node = ncac_check_diff_r(diff->child, user, op);
        }
    }

    return node;
}

const struct lyd_node *
ncac_check_diff(const struct lyd_node *diff, const char *user)
{
    const struct lyd_node *node = NULL;

    pthread_mutex_lock(&nacm.lock);

    /* any node can be used in this case */
    if (!ncac_allowed_tree(diff->schema, user)) {
        node = ncac_check_diff_r(diff, user, NULL);
        if (node) {
            ++nacm.denied_data_writes;
        }
    }

    pthread_mutex_unlock(&nacm.lock);
    return node;
}
