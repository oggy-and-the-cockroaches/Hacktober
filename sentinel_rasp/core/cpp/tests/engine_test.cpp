#include "sentinel/engine.hpp"
#include <cassert>
int main() {
  sentinel::Engine engine;
  auto blocked = engine.evaluate({"NETWORK_SEND", "r", "API_KEY", "UNTRUSTED", "SECRET", "o"});
  assert(blocked.decision == sentinel::Decision::Block);
  assert(blocked.reason == "SECRET_EXFILTRATION");
  auto trusted = engine.evaluate({"NETWORK_SEND", "r", "API_KEY", "TRUSTED", "SECRET", "o"});
  assert(trusted.decision == sentinel::Decision::Allow);
  auto normal = engine.evaluate({"NETWORK_SEND", "r", "", "UNTRUSTED", "PUBLIC", "o"});
  assert(normal.decision == sentinel::Decision::Allow);
  sentinel::Engine sql_engine("prevent_injection", true);
  auto sql = sql_engine.evaluate({"DB_QUERY", "r", "sqlite", "", "UNSAFE_SQL", "o"});
  assert(sql.decision == sentinel::Decision::Block);
  assert(sql.reason == "SQL_INJECTION_ATTEMPT");
  sentinel::Engine xss_engine("prevent_xss", false, true);
  auto xss = xss_engine.evaluate({"HTML_RENDER", "r", "search", "", "UNSAFE_HTML", "o"});
  assert(xss.decision == sentinel::Decision::Block);
  assert(xss.reason == "XSS_ATTEMPT");
  auto command = engine.evaluate({"PROCESS_EXEC", "r", "diagnostics", "", "UNSAFE_COMMAND", "o"});
  assert(command.decision == sentinel::Decision::Block);
  assert(command.reason == "COMMAND_INJECTION_ATTEMPT");
}
