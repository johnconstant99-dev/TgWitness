import importlib
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Callable

from .access import POLICY

GROUP = "tgwitness.extensions"
BUILT_IN = ("tgwitness_analyzer.extension:register",)


class JournalReader:
    def __init__(self, store):
        self._store = store

    def events(self, **filters):
        return self._store().events(**filters)

    def message_state(self, chat_id, message_id):
        return self._store().message_state(chat_id, message_id)

    def targets(self):
        return self._store().targets()


def workspace_goal(store):
    return (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")


@dataclass
class Context:
    app: object
    authenticate: Callable
    reader: JournalReader
    goal: Callable
    require_chat: Callable
    recheck: Callable

    def allow(self, route, permission, chats):
        POLICY[route] = (permission, chats)


def load(context, names=None):
    loaded, failed = [], []
    candidates = list(BUILT_IN) + [entry.value for entry in entry_points(group=GROUP)] if names is None else names
    for name in dict.fromkeys(candidates):
        module_name, _, attribute = name.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name and module_name.split(".")[0] == exc.name.split(".")[0]:
                continue
            failed.append({"module": module_name, "error": type(exc).__name__ + ": " + str(exc.name)})
            continue
        try:
            loaded.append(getattr(module, attribute or "register")(context))
        except Exception as exc:
            failed.append({"module": module_name, "error": type(exc).__name__})
    return {"loaded": loaded, "failed": failed}
