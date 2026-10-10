#include "sentinel/engine.hpp"
#include <algorithm>
#include <cctype>

namespace {
std::string upper(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}
bool untrusted(const std::string& destination) {
  auto value = upper(destination);
  return value == "UNTRUSTED" || value == "" || value == "EXTERNAL";
}
}
namespace sentinel {
Engine::Engine(std::string policy_name, bool block_unsafe_sql, bool block_xss)
    : policy_name_(std::move(policy_name)), block_unsafe_sql_(block_unsafe_sql), block_xss_(block_xss) {}
Result Engine::evaluate(const Event& event) const {
  if (block_xss_ && upper(event.event_type) == "HTML_RENDER" &&
      upper(event.data_classification) == "UNSAFE_HTML") {
    return {Decision::Block, policy_name_, "XSS_ATTEMPT"};
  }
  if (upper(event.event_type) == "PROCESS_EXEC" &&
      upper(event.data_classification) == "UNSAFE_COMMAND") {
    return {Decision::Block, policy_name_, "COMMAND_INJECTION_ATTEMPT"};
  }
  if (block_unsafe_sql_ && upper(event.event_type) == "DB_QUERY" &&
      upper(event.data_classification) == "UNSAFE_SQL") {
    return {Decision::Block, policy_name_, "SQL_INJECTION_ATTEMPT"};
  }
  if (upper(event.event_type) == "NETWORK_SEND" &&
      upper(event.data_classification) == "SECRET" && untrusted(event.destination)) {
    return {Decision::Block, policy_name_, "SECRET_EXFILTRATION"};
  }
  return {Decision::Allow, policy_name_, ""};
}
}
