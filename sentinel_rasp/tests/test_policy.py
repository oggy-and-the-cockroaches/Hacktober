from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / "python"))
from sentinel.events import EventType, SecurityEvent
from sentinel.policy import load_policy

POLICY = Path(__file__).parents[1] / "examples/vulnerable-fastapi/security.yaml"
def test_policy_loads():
    assert load_policy(POLICY).name == "prevent_secret_exfiltration"
def test_event_has_operation_id():
    assert SecurityEvent(EventType.SECRET_ACCESS).operation_id
def test_invalid_policy_rejected(tmp_path):
    path = tmp_path / "bad.yaml"; path.write_text("name: x\n")
    try: load_policy(path)
    except ValueError: return
    assert False
