#pragma once

#include <sysrepo.h>
#include <sysrepo/values.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct SysrepoValues {
  sr_val_t *values;
  size_t valueCount;

  inline ~SysrepoValues() { sr_free_values(values, valueCount); }

  SysrepoValues(const SysrepoValues &other) = delete;
  SysrepoValues() = default;
};

class SysrepoListener {
public:
  SysrepoListener(const SysrepoListener &) = delete;
  SysrepoListener() = default;
  void listen();

  sr_session_ctx_t *m_session = nullptr;

  bool subscribeForAction(const char *xpath);
  void setActionValues(const char *xpath,
                       std::unique_ptr<SysrepoValues> &&values);

private:
  void sysrepoConnect();
  int attemptSysrepoConnect();
  int subscribeToAll();

  static int changeTrampoline(sr_session_ctx_t *session, const char *module,
                              sr_notif_event_t event, void *data);
  int handleChanges(sr_session_ctx_t *session, const char *module,
                    sr_notif_event_t event);

  static int actionTrampoline(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *data);
  int handleAction(const char *xpath, const sr_val_t *input,
                   const size_t input_cnt, sr_val_t **output,
                   size_t *output_cnt);

  sr_conn_ctx_t *m_connection = nullptr;
  sr_subscription_ctx_t *m_subscription = nullptr;

  std::unordered_map<std::string, std::shared_ptr<SysrepoValues>>
      m_actionValues;
  std::unordered_set<std::string> m_subscribedActions;
};
