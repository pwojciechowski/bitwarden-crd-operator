import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if "kubernetes" not in sys.modules:
    sys.modules["kubernetes"] = types.SimpleNamespace(
        client=types.SimpleNamespace(CoreV1Api=lambda: None, V1ObjectMeta=lambda **kw: kw)
    )


def _passthrough(*args, **kwargs):
    return lambda fn: fn


def _import_handlers(name):
    # Decorators must return the handler itself, so the test calls the code.
    kopf = types.ModuleType("kopf")
    kopf.on = types.SimpleNamespace(
        create=_passthrough, update=_passthrough, delete=_passthrough
    )
    kopf.timer = _passthrough
    kopf.TemporaryError = type("TemporaryError", (Exception,), {})
    kopf.PermanentError = type("PermanentError", (Exception,), {})
    kopf.append_owner_reference = lambda *args, **kwargs: None
    with patch.dict(sys.modules, {"kopf": kopf}):
        sys.modules.pop(name, None)
        return importlib.import_module(name)


class _Body(dict):
    def __init__(self, spec):
        super().__init__(spec=spec)
        self.metadata = types.SimpleNamespace(annotations={})


SPEC = {"id": "item-1", "name": "s", "namespace": "ns", "content": []}
TEMPLATE_SPEC = {"name": "s", "namespace": "ns", "filename": "f", "template": "t"}

# module, spec, change handlers, timer handler, the function that reads items
CASES = [
    ("kv", SPEC, ("create_managed_secret", "update_managed_secret"),
     "refresh_managed_secret", "get_secret_from_bitwarden"),
    ("dockerlogin", SPEC,
     ("create_managed_registry_secret", "update_managed_registry_secret"),
     "refresh_managed_registry_secret", "get_secret_from_bitwarden"),
    ("template", {**SPEC, "content": [{"f": {"filename": "f", "template": "t"}}]},
     ("create_managed_secret", "update_managed_secret"),
     "refresh_managed_secret", "create_template_obj"),
    ("template", TEMPLATE_SPEC, ("create_managed_secret", "update_managed_secret"),
     "refresh_managed_secret", "create_template_secret"),
]


class HandlerSyncTests(unittest.TestCase):
    """#108 B2: one vault sync per cycle (the scheduled one); a CR change still
    syncs first, so a new CR or an annotation bump reads fresh items."""

    def _run(self, module, handler, spec, lookup):
        calls = MagicMock()
        calls.lookup.return_value = {"data": {}}
        patches = {
            "unlock_bw": MagicMock(),
            "sync_bw": calls.sync,
            lookup: calls.lookup,
            "kubernetes": MagicMock(),
            "create_secret": MagicMock(),
            "update_secret": MagicMock(),
            "apply_owner_reference": MagicMock(),
        }
        for builder in ("create_kv", "create_dockerlogin"):
            if hasattr(module, builder):
                patches[builder] = MagicMock()
        with patch.multiple(module, **patches):
            getattr(module, handler)(
                spec=spec, status={}, name="cr", namespace="ns",
                logger=MagicMock(), body=_Body(spec),
            )
        return [name for name, _, _ in calls.mock_calls if name in ("sync", "lookup")]

    def test_change_handlers_sync_once_before_reading_items(self):
        for name, spec, handlers, _, lookup in CASES:
            module = _import_handlers(name)
            for handler in handlers:
                with self.subTest(module=name, handler=handler, lookup=lookup):
                    self.assertEqual(
                        ["sync", "lookup"], self._run(module, handler, spec, lookup)
                    )

    def test_timers_read_items_without_syncing(self):
        for name, spec, _, timer, lookup in CASES:
            module = _import_handlers(name)
            with self.subTest(module=name, lookup=lookup):
                self.assertEqual(["lookup"], self._run(module, timer, spec, lookup))


if __name__ == "__main__":
    unittest.main()
