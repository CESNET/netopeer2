#include "RequestHandler.hpp"

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/error/error.h>
#include <rapidjson/rapidjson.h>

#include <utility>

RequestHandler::RequestHandler(SysrepoListener &sysrepo)
    : m_endpoint("*:9080"), m_sysrepo(sysrepo) {
  Pistache::Rest::Routes::Post(
      m_router, "/send-notification",
      Pistache::Rest::Routes::bind(&RequestHandler::sendNotification, this));
  Pistache::Rest::Routes::Post(
      m_router, "/set-action-reply",
      Pistache::Rest::Routes::bind(&RequestHandler::setActionReply, this));
  m_endpoint.init(Pistache::Http::Endpoint::options().threads(1));
  m_endpoint.setHandler(m_router.handler());
  m_endpoint.serve();
}

#define TRY_OR_BAD_REQ(expr, msg)                                              \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::ostringstream oss;                                                  \
      oss << msg;                                                              \
      response.send(Pistache::Http::Code::Bad_Request, oss.str());             \
    }                                                                          \
  } while (false);

void RequestHandler::sendNotification(const Pistache::Rest::Request &request,
                                      Pistache::Http::ResponseWriter response) {
  rapidjson::Document d;
  rapidjson::ParseResult parseResult = d.Parse(request.body().c_str());
  if (!d.HasMember("no-op")) {
    TRY_OR_BAD_REQ(parseResult, "Failed to parse JSON document: "
                                    << GetParseError_En(parseResult.Code()));
    TRY_OR_BAD_REQ(d.HasMember("xpath"), "Missing xpath field");
    TRY_OR_BAD_REQ(d.HasMember("values"), "Missing values field");

    auto values = parseValueList(d["values"]);
    TRY_OR_BAD_REQ(values, "Failed to parse value list");

    sr_session_refresh(m_sysrepo.m_session);

    int ret = sr_event_notif_send(m_sysrepo.m_session, d["xpath"].GetString(),
                                  values->values, values->valueCount,
                                  SR_EV_NOTIF_DEFAULT);
    TRY_OR_BAD_REQ(ret == SR_ERR_OK, "Failed to send request to sysrepo");
  }

  response.send(Pistache::Http::Code::Ok, "");
}

void RequestHandler::setActionReply(const Pistache::Rest::Request &request,
                                    Pistache::Http::ResponseWriter response) {

  rapidjson::Document d;
  rapidjson::ParseResult parseResult = d.Parse(request.body().c_str());
  TRY_OR_BAD_REQ(parseResult, "Failed to parse JSON document: "
                                  << GetParseError_En(parseResult.Code()));
  if (!d.HasMember("no-op")) {
    TRY_OR_BAD_REQ(d.HasMember("xpath"), "Missing xpath field");
    TRY_OR_BAD_REQ(d.HasMember("values"), "Missing values field");

    auto values = parseValueList(d["values"]);
    TRY_OR_BAD_REQ(values, "Failed to parse value list");

    TRY_OR_BAD_REQ(m_sysrepo.subscribeForAction(d["xpath"].GetString()),
                   "Failed to subscribe to action");
    m_sysrepo.setActionValues(d["xpath"].GetString(), std::move(values));
  }

  response.send(Pistache::Http::Code::Ok, "");
}

std::unique_ptr<SysrepoValues>
parseValueList(const rapidjson::Value &parsedValues) {
  sr_val_t *values;
  int valueCount = parsedValues.Size();
  sr_new_values(valueCount, &values);
  auto ret = std::unique_ptr<SysrepoValues>(new SysrepoValues);
  ret->values = values;
  ret->valueCount = valueCount;

  for (int i = 0; i < valueCount; ++i) {
    if (!parsedValues[i].HasMember("xpath")) {
      return nullptr;
    }

    if (!parsedValues[i].HasMember("value")) {
      return nullptr;
    }

    sr_val_set_xpath(values + i, parsedValues[i]["xpath"].GetString());
    sr_val_set_str_data(values + i, SR_STRING_T,
                        parsedValues[i]["value"].GetString());
  }

  return ret;
}
