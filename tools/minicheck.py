"""The few pytest idioms the TDX and Phala checks use, for standalone runs without pytest.

fixture, mark.parametrize and raises behave as in pytest; run() calls every test_* function of a module
with its fixtures (tmp_path, monkeypatch, capsys and the module's own), each case in a fresh directory.
"""
import contextlib
import importlib
import inspect
import io
import os
import re
import sys
import tempfile
import traceback
from pathlib import Path
from types import SimpleNamespace


def fixture(function=None, **options):
    def mark(f):
        f.minicheck_fixture = True
        return f
    return mark(function) if function else mark


class _Mark:
    @staticmethod
    def parametrize(names, cases):
        names = [n.strip() for n in names.split(",")] if isinstance(names, str) else list(names)

        def mark(function):
            function.minicheck_cases = [dict(zip(names, case if len(names) > 1 else (case,))) for case in cases]
            return function
        return mark


mark = _Mark()


class raises:
    def __init__(self, kind, match=None):
        self.kind, self.match = kind, match

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        if kind is None:
            raise AssertionError("did not raise " + self.kind.__name__)
        if not issubclass(kind, self.kind):
            return False
        if self.match and not re.search(self.match, str(value)):
            raise AssertionError(repr(self.match) + " not found in " + repr(str(value)))
        self.value = value
        return True


class MonkeyPatch:
    def __init__(self):
        self.undo = []

    def setattr(self, target, name, value=None):
        if isinstance(target, str):
            module, _, attribute = target.rpartition(".")
            target, name, value = importlib.import_module(module), attribute, name
        self.undo.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def delenv(self, name, raising=True):
        if name in os.environ:
            self.undo.append((os.environ, name, os.environ.pop(name)))
        elif raising:
            raise KeyError(name)

    def restore(self):
        for target, name, value in reversed(self.undo):
            if target is os.environ:
                os.environ[name] = value
            else:
                setattr(target, name, value)
        self.undo.clear()


class Capture:
    def __init__(self, stack):
        self.out, self.err = io.StringIO(), io.StringIO()
        stack.enter_context(contextlib.redirect_stdout(self.out))
        stack.enter_context(contextlib.redirect_stderr(self.err))

    def readouterr(self):
        result = SimpleNamespace(out=self.out.getvalue(), err=self.err.getvalue())
        self.out.seek(0), self.out.truncate(), self.err.seek(0), self.err.truncate()
        return result


def _call(function, namespace, given, built, stack):
    arguments = {}
    for name in inspect.signature(function).parameters:
        if name in given:
            arguments[name] = given[name]
        elif name not in built:
            maker = namespace.get(name)
            if not getattr(maker, "minicheck_fixture", False):
                raise TypeError("unknown fixture " + name)
            value = _call(maker, namespace, given, built, stack)
            if inspect.isgenerator(value):
                generator, value = value, next(value)
                stack.callback(lambda g=generator: next(g, None))
            built[name] = value
            arguments[name] = value
        else:
            arguments[name] = built[name]
    return function(**arguments)


def run(namespace):
    """Runs the module's tests; prints one line per case and returns the exit status."""
    failed = passed = 0
    for name, function in list(namespace.items()):
        if not name.startswith("test_") or not callable(function):
            continue
        for case in getattr(function, "minicheck_cases", [{}]):
            label = name + ("[" + ", ".join(str(v)[:30] for v in case.values()) + "]" if case else "")
            with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                patch = MonkeyPatch()
                stack.callback(patch.restore)
                built = {"tmp_path": Path(tmp), "monkeypatch": patch}
                if "capsys" in inspect.signature(function).parameters:
                    built["capsys"] = Capture(stack)
                try:
                    _call(function, namespace, case, built, stack)
                    passed += 1
                    outcome = "ok  "
                except Exception:
                    failed += 1
                    outcome = "FAIL"
                    report = traceback.format_exc()
                else:
                    report = ""
            print(outcome, label, flush=True)
            if report:
                print(report, file=sys.stderr, flush=True)
    print(str(passed) + " passed, " + str(failed) + " failed")
    return 1 if failed else 0
