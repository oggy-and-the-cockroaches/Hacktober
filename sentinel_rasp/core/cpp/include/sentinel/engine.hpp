#pragma once

#include <string>

namespace sentinel {

enum class Decision { Allow, Block };

struct Event {
  std::string event_type;
  std::string request_id;
  std::string resource;
  std::string destination;
  std::string data_classification;
  std::string operation_id;
};

struct Result {
  Decision decision;
  std::string policy;
  std::string reason;
};

// MVP finite-state policy: SECRET_ACCESS arms the request; a secret NETWORK_SEND
// to an untrusted destination is forbidden.
class Engine {
 public:
  explicit Engine(std::string policy_name = "prevent_secret_exfiltration", bool block_unsafe_sql = false,
                  bool block_xss = false);
  Result evaluate(const Event& event) const;
 private:
  std::string policy_name_;
  bool block_unsafe_sql_;
  bool block_xss_;
};
}
