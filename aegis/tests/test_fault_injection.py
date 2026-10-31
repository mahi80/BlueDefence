"""The fault-injection gate as a test: survives / safe / loud across every injected dependency failure."""

import pytest

from aegis.eval import fault_injection as fi


@pytest.mark.parametrize("name", [s.name for s in fi.SCENARIOS])
def test_fault_scenario(name):
    sc = next(s for s in fi.SCENARIOS if s.name == name)
    o = fi.run_scenario(sc)
    assert o.ok, f"{name}: failed {[k for k, v in o.checks.items() if not v]} — {o.detail}"
