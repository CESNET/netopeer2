#include "SysrepoListener.hpp"

#include <sysrepo/xpath.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <string>
#include <unistd.h>

#define SR_TRY(x)                                                              \
  do {                                                                         \
    int rc = x;                                                                \
    if (rc != SR_ERR_OK) {                                                     \
      std::cerr << "sysrepo command failed: " << sr_strerror(rc) << "\n";      \
      return rc;                                                               \
    }                                                                          \
  } while (false)

using std::to_string;

std::string to_string(sr_notif_event_t e) {
  switch (e) {
  case SR_EV_VERIFY:
    return "SR_EV_VERIFY";
  case SR_EV_APPLY:
    return "SR_EV_APPLY";
  case SR_EV_ABORT:
    return "SR_EV_ABORT";
  case SR_EV_ENABLED:
    return "SR_EV_ENABLED";
  }
}

std::string to_string(sr_change_oper_t c) {
  switch (c) {
  case SR_OP_CREATED:
    return "SR_OP_CREATED";
  case SR_OP_MODIFIED:
    return "SR_OP_MODIFIED";
  case SR_OP_DELETED:
    return "SR_OP_DELETED";
  case SR_OP_MOVED:
    return "SR_OP_MOVED";
  }
}

void SysrepoListener::listen() {
  sysrepoConnect();
  subscribeToAll();
}

void SysrepoListener::sysrepoConnect() {
  while (attemptSysrepoConnect() != SR_ERR_OK) {
    usleep(1000 * 1000 * 1);
  }
}

int SysrepoListener::attemptSysrepoConnect() {
  SR_TRY(sr_connect("test_service", SR_CONN_DAEMON_REQUIRED, &m_connection));
  SR_TRY(sr_session_start(m_connection, SR_DS_RUNNING, SR_SESS_CONFIG_ONLY,
                          &m_session));
  return SR_ERR_OK;
}
int SysrepoListener::subscribeToAll() {
  sr_schema_t *schemas;
  size_t schemaCount;
  SR_TRY(sr_list_schemas(m_session, &schemas, &schemaCount));

  for (sr_schema_t *schema = schemas; (size_t)(schema - schemas) < schemaCount;
       schema++) {
    std::cerr << "Subscribing to module " << schema->module_name << "\n";
    if (sr_module_change_subscribe(
            m_session, schema->module_name, changeTrampoline, (void *)this,
            0 /*priority*/, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED,
            &m_subscription)) {
      std::cerr << "Failed to subscribe to " << schema->module_name << "\n";
    } else {
      std::cerr << "Subscribed to module " << schema->module_name << "\n";
    }
  }
  sr_free_schemas(schemas, schemaCount);

  return SR_ERR_OK;
}

int SysrepoListener::changeTrampoline(sr_session_ctx_t *session,
                                      const char *module,
                                      sr_notif_event_t event, void *data) {
  return ((SysrepoListener *)data)->handleChanges(session, module, event);
}

int SysrepoListener::handleChanges(sr_session_ctx_t *session,
                                   const char *module, sr_notif_event_t event) {
  std::ofstream events("/tmp/test-service-event-stream.yml",
                       std::ios::out | std::ios::app | std::ios::ate);
  if (!events) {
    std::cerr << "Failed to open event log file\n";
    return SR_ERR_OPERATION_FAILED;
  }
  std::ostringstream selector;
  selector << "/" << module << ":*";
  sr_change_iter_t *iter;
  SR_TRY(sr_get_changes_iter(session, selector.str().c_str(), &iter));

  events << "---\n";
  events << "event_type: " << to_string(event) << "\n";
  events << "values:\n";

  sr_val_t *old;
  sr_val_t *new_;
  sr_change_oper_t op;
  while (sr_get_change_next(session, iter, &op, &old, &new_) == SR_ERR_OK) {
    events << "  - operation: " << to_string(op) << "\n";
    if (old) {
      events << "    old-path: " << old->xpath << "\n";
      char *v = sr_val_to_str(old);
      events << "    old-value: " << v << "\n";
      free(v);
    }

    if (new_) {
      events << "    new-path: " << new_->xpath << "\n";
      char *v = sr_val_to_str(new_);
      events << "    new-value: " << v << "\n";
      free(v);
    }
  }

  sr_free_change_iter(iter);

  return SR_ERR_OK;
}

bool SysrepoListener::subscribeForAction(const char *xpath) {
  std::string key(xpath);
  if (m_subscribedActions.find(key) != m_subscribedActions.end()) {
    // Already subscribed
    return true;
  }

  if (sr_action_subscribe(m_session, xpath, &SysrepoListener::actionTrampoline,
                          (void *)this, SR_SUBSCR_CTX_REUSE,
                          &m_subscription) != SR_ERR_OK) {
    return false;
  }

  m_subscribedActions.insert(key);
  return true;
}

static std::string xpathToSchemaPath(const char *xpath) {
  char *mutableXpath = strdup(xpath);
  sr_xpath_ctx_t ctx;
  bzero(&ctx, sizeof(ctx));
  std::ostringstream oss;

  for (char *node = sr_xpath_next_node_with_ns(mutableXpath, &ctx); node;
       node = sr_xpath_next_node(nullptr, &ctx)) {
    oss << "/" << node;
  }
  std::free(mutableXpath);
  return oss.str();
}

void SysrepoListener::setActionValues(const char *xpath,
                                      std::unique_ptr<SysrepoValues> &&values) {
  std::string schema(xpathToSchemaPath(xpath));
  m_actionValues[schema] = std::move(values);
}

int SysrepoListener::actionTrampoline(const char *xpath, const sr_val_t *input,
                                      const size_t input_cnt, sr_val_t **output,
                                      size_t *output_cnt, void *data) {
  return ((SysrepoListener *)data)
      ->handleAction(xpath, input, input_cnt, output, output_cnt);
}

int SysrepoListener::handleAction(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt) {
  std::string schemaPath(xpathToSchemaPath(xpath));

  auto values = m_actionValues.find(schemaPath);
  if (values == m_actionValues.end()) {
    std::cerr << "Unexpected action at XPath " << xpath << " (schema path "
              << schemaPath << ")\n";
    return SR_ERR_INTERNAL;
  }

  sr_dup_values(values->second->values, values->second->valueCount, output);
  *output_cnt = values->second->valueCount;
}
