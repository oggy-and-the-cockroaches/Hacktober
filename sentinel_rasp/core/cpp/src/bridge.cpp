#include "sentinel/engine.hpp"
#include <cstring>

// Small C ABI deliberately keeps Python's bridge thin and avoids payload copies.
extern "C" int sentinel_evaluate(const char* policy, const char* event_type,
    const char* request_id, const char* resource, const char* destination,
    const char* classification, const char* operation_id, int block_unsafe_sql, int block_xss,
    char* reason, unsigned int reason_size) {
  sentinel::Event event{event_type ? event_type : "", request_id ? request_id : "",
      resource ? resource : "", destination ? destination : "",
      classification ? classification : "", operation_id ? operation_id : ""};
  sentinel::Engine engine(policy ? policy : "prevent_secret_exfiltration", block_unsafe_sql != 0, block_xss != 0);
  auto result = engine.evaluate(event);
  if (reason && reason_size) {
    std::strncpy(reason, result.reason.c_str(), reason_size - 1);
    reason[reason_size - 1] = '\0';
  }
  return result.decision == sentinel::Decision::Block ? 1 : 0;
}
