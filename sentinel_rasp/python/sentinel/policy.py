from dataclasses import dataclass
from pathlib import Path
import json

@dataclass(frozen=True)
class Policy:
    name: str
    trigger_event: str
    forbidden_event: str
    destination: str
    actions: tuple[str, ...]
    block_unsafe_sql: bool = False
    block_xss: bool = False

def _simple_yaml(text: str) -> dict:
    """Parse the deliberately small policy grammar without a runtime YAML dependency."""
    result, section = {}, None
    for line in text.splitlines():
        raw = line.split("#", 1)[0].rstrip()
        if not raw.strip(): continue
        if not raw.startswith((" ", "\t")):
            key, value = raw.split(":", 1); key, value = key.strip(), value.strip()
            if value: result[key] = value.strip("[] ").split(",") if key == "action" else value
            else: section = key; result[section] = {}
        elif section:
            key, value = raw.strip().split(":", 1); result[section][key.strip()] = value.strip()
    return result

def load_policy(path: str | Path) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
        raw = yaml.safe_load(text)
    except ImportError:
        raw = json.loads(text) if text.lstrip().startswith("{") else _simple_yaml(text)
    try:
        policy = Policy(raw["name"], raw["when"]["event"], raw["forbid"]["event"],
                        raw["condition"]["destination"], tuple(a.strip() for a in raw["action"]),
                        bool(raw.get("database", {}).get("block_unsafe_dynamic_sql", False)),
                        bool(raw.get("html", {}).get("block_unsafe_reflected_html", False)))
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid policy: name, when.event, forbid.event, condition.destination, action required") from exc
    if policy.trigger_event != "SECRET_ACCESS" or policy.forbidden_event != "NETWORK_SEND" or policy.destination != "UNTRUSTED" or "BLOCK" not in policy.actions:
        raise ValueError("unsupported MVP policy; expected SECRET_ACCESS -> NETWORK_SEND to UNTRUSTED with BLOCK")
    return policy
