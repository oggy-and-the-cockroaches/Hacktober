// Low-latency request inspection engine for Shipcheck.
// C ABI keeps Python integration thin and avoids third-party bindings.
#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define SHIPCHECK_EXPORT extern "C" __declspec(dllexport)
#else
#define SHIPCHECK_EXPORT extern "C"
#endif

enum Finding : std::uint32_t {
    NONE = 0, BLIND_SQL = 1u << 0, HTML = 1u << 1, SSI = 1u << 2,
    SSTI = 1u << 3, XPATH = 1u << 4, RCE = 1u << 5, OS_COMMAND = 1u << 6,
    XML = 1u << 7, LDAP = 1u << 8, CRLF = 1u << 9,
};

static inline unsigned char lower_ascii(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
}

// Allocation-free ASCII substring check. The Python caller caps the inspected input.
static bool contains_ci(const char* data, std::size_t length, const char* needle, std::size_t size) {
    if (size == 0 || size > length) return false;
    for (std::size_t start = 0; start + size <= length; ++start) {
        std::size_t index = 0;
        while (index < size && lower_ascii(static_cast<unsigned char>(data[start + index])) == needle[index]) ++index;
        if (index == size) return true;
    }
    return false;
}
static bool contains(const char* data, std::size_t length, const char* needle, std::size_t size) {
    if (size == 0 || size > length) return false;
    for (std::size_t start = 0; start + size <= length; ++start) {
        std::size_t index = 0;
        while (index < size && data[start + index] == needle[index]) ++index;
        if (index == size) return true;
    }
    return false;
}

SHIPCHECK_EXPORT std::uint32_t shipcheck_inspect(const char* data, std::size_t length) {
    if (!data || length == 0) return NONE;
    std::uint32_t mask = NONE;
    if (contains_ci(data,length,"pg_sleep(",9) || contains_ci(data,length,"waitfor delay",13) || contains_ci(data,length,"benchmark(",10)) mask |= BLIND_SQL;
    if (contains_ci(data,length,"<iframe",7) || contains_ci(data,length,"<object",7) || contains_ci(data,length,"<svg",4)) mask |= HTML;
    if (contains_ci(data,length,"<!--#exec",9) || contains_ci(data,length,"<!--#include",12)) mask |= SSI;
    if (contains(data,length,"{{",2) || contains(data,length,"$" "{",2) || contains(data,length,"<%=",3)) mask |= SSTI;
    if (contains(data,length,"//*[",4) || contains(data,length,"]|//",4)) mask |= XPATH;
    if (contains_ci(data,length,"powershell",10) || contains_ci(data,length,"cmd.exe",7) || contains(data,length,"$(",2)) mask |= RCE;
    if (contains_ci(data,length,";whoami",7) || contains_ci(data,length,"&&whoami",8) || contains_ci(data,length,"|whoami",7)) mask |= OS_COMMAND;
    if (contains_ci(data,length,"<!entity",8) || contains_ci(data,length,"<!doctype",9)) mask |= XML;
    if (contains(data,length,")(|",3) || contains(data,length,")(&",3)) mask |= LDAP;
    if (contains(data,length,"\r\n",2) || contains(data,length,"\nset-cookie:",12)) mask |= CRLF;
    return mask;
}
SHIPCHECK_EXPORT const char* shipcheck_engine_version() { return "1.0.0"; }
