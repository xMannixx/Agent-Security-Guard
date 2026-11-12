"""What a browser tool's code does: read a page, act on it, or run anything.

Hermes's ``browser_exec`` takes ``code``: Python, run as a full interpreter
with the browser-harness helpers pre-imported (``new_tab``, ``js``,
``fill_input``, ``click_at_xy``, ``cdp``, ...) and the standard library at
hand. One tool therefore reads pages, fills and submits forms, and can run a
shell command. By its name alone the guard could not tell these apart.

The code is parsed, never run, and judged by an allow-list:

- **read**: only the helpers that navigate, wait and look (``new_tab``,
  ``goto_url``, ``page_info``, ``capture_screenshot``, ...), ``js`` with a
  literal expression that changes nothing, ``cdp`` with a literal method that
  only reads, plus plain Python over the results (variables, loops,
  comprehensions, ``print``, ``json``, ``re``, ...);
- **acts on the page** (``EXTERNAL_WRITE``): typing, clicking, key presses,
  file uploads, and ``js`` / ``cdp`` calls that are not shown to only read;
- **runs anything** (``EXECUTION``): every other name or module (``os``,
  ``subprocess``, ``open``, ``Path``, ``urllib``, functions from the
  workspace's ``agent_helpers.py``), any import outside a few data modules,
  any attribute that starts with ``_``, and code that does not parse.

Unknown means asked, not allowed: an allow-list fails towards a question.
What it costs is that code using something the list does not know is asked
about after outside content, like a shell command.

stdlib-only.
"""

from __future__ import annotations

import ast
import importlib
import re
from typing import Dict, Iterable, Optional, Set

from .types import ActionTier

# Helpers that navigate, wait or look. A new tab or a navigation fetches a
# page: reading, whatever the page then contains.
_READ_HELPERS = frozenset({
    "new_tab", "goto_url", "wait_for_load", "wait", "wait_for_element",
    "wait_for_network_idle", "page_info", "capture_screenshot", "list_tabs",
    "current_tab", "activate_tab", "switch_tab", "close_tab", "ensure_real_tab",
    "iframe_target", "scroll", "drain_events", "http_get",
})

# Helpers that act on the page: what a user does with keyboard and mouse.
_ACT_HELPERS = frozenset({
    "fill_input", "type_text", "click_at_xy", "press_key", "dispatch_key",
    "upload_file",
})

# Plain Python over data. Nothing here reaches files, processes or the network.
_SAFE_BUILTINS = frozenset({
    "print", "len", "str", "int", "float", "bool", "list", "dict", "set",
    "frozenset", "tuple", "range", "enumerate", "zip", "sorted", "reversed",
    "min", "max", "sum", "any", "all", "abs", "round", "isinstance", "map",
    "filter", "repr", "format", "divmod", "chr", "ord", "hash", "slice",
    "True", "False", "None",
    "Exception", "ValueError", "KeyError", "IndexError", "TypeError",
    "TimeoutError", "RuntimeError", "AttributeError", "StopIteration",
})

# Modules for data only, importable and usable by name. Their attributes are
# allowed except those that are modules themselves (``json.codecs`` would
# reach ``codecs.open``).
# ``operator``, ``functools`` and ``string`` are left out: ``attrgetter`` and
# ``Formatter`` reach attributes by a name in a string, past the check below.
_DATA_MODULES = frozenset({
    "json", "re", "math", "time", "datetime", "collections", "itertools",
    "statistics", "textwrap", "html", "base64", "urllib.parse",
})

# Attributes that lead from a plain value to the interpreter's internals
# without a leading underscore: a generator's frame, a frame's globals.
_INTERNAL_ATTRIBUTES = frozenset({
    "gi_frame", "gi_code", "gi_yieldfrom", "cr_frame", "cr_code", "cr_await",
    "ag_frame", "ag_code", "ag_await", "f_globals", "f_locals", "f_builtins",
    "f_back", "f_code", "tb_frame", "tb_next", "co_code", "mro",
})

# Names the harness pre-imports that are data functions.
_DATA_NAMES = frozenset({"urlparse", "urljoin", "quote", "unquote", "urlencode"})

# ``js()`` expressions: anything that changes the page, sends, or runs more
# code. Declarations (``const x = ...``) and comparisons are not assignments.
_JS_DECLARATION = re.compile(r"\b(?:const|let|var)\s+[\w$]+\s*=")
_JS_ASSIGNMENT = re.compile(r"(?<![=!<>])=(?![=>])|\+\+|--|[-+*/%&|^]=")
_JS_ACTS = re.compile(
    r"\.(?:click|submit|requestSubmit|focus|blur|reset|select|remove|append|"
    r"prepend|before|after|replaceWith|replaceChildren|insert\w*|set\w*|"
    r"removeAttribute|dispatchEvent|write\w*|open|postMessage|assign|replace|"
    r"reload|pushState|replaceState|showModal|play|execCommand|"
    r"setItem|removeItem|clear)\s*\(|"
    r"\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|EventSource|eval|Function|"
    r"import|setTimeout|setInterval|clipboard|serviceWorker)\b",
)

# ``cdp()`` methods that only read or navigate. Everything else, Input.*,
# Runtime.evaluate and every DOM.set* among them, acts.
_CDP_READ = re.compile(
    r"^(?:DOM|CSS|Accessibility|Page|Target|Network|Log|Performance|Browser|"
    r"Emulation|Overlay|DOMSnapshot|LayerTree)\."
    r"(?:get\w*|describe\w*|query\w*|resolve\w*|capture\w*|navigate|enable|"
    r"disable|activateTarget|attachToTarget|createTarget|bringToFront|"
    r"requestNode|pushNodesByBackendIdsToFrontend|snapshot\w*)$"
)


def browser_code_tier(code: object) -> Optional[ActionTier]:
    """``EXECUTION``, ``EXTERNAL_WRITE`` or ``None`` for code that only reads."""
    if not isinstance(code, str):
        return ActionTier.EXECUTION if code is not None else None
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return ActionTier.EXECUTION
    return _Judge(tree).tier()


class _Judge:
    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.nodes = list(ast.walk(tree))
        self.local = self._bound_names()
        self.modules: Dict[str, str] = {}
        self.acts = False
        self.runs = False

    def tier(self) -> Optional[ActionTier]:
        for node in self.nodes:
            self._look(node)
            if self.runs:
                return ActionTier.EXECUTION
        return ActionTier.EXTERNAL_WRITE if self.acts else None

    # -- what the code defines itself ------------------------------------

    def _bound_names(self) -> Set[str]:
        names: Set[str] = set()
        for node in self.nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                names.add(node.name)
        return names

    # -- each node -------------------------------------------------------

    def _look(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                self._import(alias.name, alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in _DATA_MODULES:
                self.runs = True
                return
            for alias in node.names:
                if alias.name == "*" or self._is_module(node.module, alias.name):
                    self.runs = True
                self.local.add(alias.asname or alias.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal, ast.ClassDef, ast.Lambda)):
            # Lambdas are fine in themselves, but class bodies and scope
            # tricks are not what page code needs.
            if not isinstance(node, ast.Lambda):
                self.runs = True
        elif isinstance(node, ast.Attribute):
            self._attribute(node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self._name(node.id)
        elif isinstance(node, ast.Call):
            self._call(node)

    def _import(self, module: str, bound: str) -> None:
        if module not in _DATA_MODULES:
            self.runs = True
            return
        self.modules[bound] = module
        self.local.add(bound)

    def _name(self, name: str) -> None:
        if name.startswith("__"):
            self.runs = True
        elif name in self.local or name in _SAFE_BUILTINS or name in _DATA_NAMES:
            return
        elif name in _READ_HELPERS or name in ("js", "cdp"):
            return
        elif name in _ACT_HELPERS:
            self.acts = True
        elif name in _DATA_MODULES:
            # Pre-imported by the harness (``json``, ``time``, ``math``).
            self.modules.setdefault(name, name)
        else:
            self.runs = True

    def _attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("_") or node.attr in _INTERNAL_ATTRIBUTES:
            self.runs = True
            return
        if node.attr in _SUBMODULE_NAMES:
            # ``json.codecs``, also through an alias (``j = json; j.codecs``).
            self.runs = True
            return
        base = node.value
        if isinstance(base, ast.Name) and base.id in self._module_names():
            module = self.modules.get(base.id, base.id)
            if self._is_module(module, node.attr):
                self.runs = True

    def _call(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Name):
            return
        if func.id == "capture_screenshot" and (node.args or node.keywords):
            self.acts = True  # writes the image wherever the path points
        elif func.id == "js":
            if not _reads_only_js(_literal_text(node.args[0] if node.args else None)):
                self.acts = True
        elif func.id == "cdp":
            method = _literal_text(node.args[0] if node.args else None)
            if method is None or not _CDP_READ.match(method):
                self.acts = True

    def _module_names(self) -> Iterable[str]:
        return set(self.modules) | _DATA_MODULES

    @staticmethod
    def _is_module(module: str, attr: str) -> bool:
        try:
            value = getattr(importlib.import_module(module), attr, None)
        except Exception:
            return True
        return type(value).__name__ == "module"


def _submodule_names() -> Set[str]:
    names: Set[str] = set()
    for module in _DATA_MODULES:
        try:
            loaded = importlib.import_module(module)
        except Exception:
            continue
        for attr in dir(loaded):
            if type(getattr(loaded, attr, None)).__name__ == "module":
                names.add(attr)
    return names


_SUBMODULE_NAMES = frozenset(_submodule_names())


def _literal_text(node: Optional[ast.AST]) -> Optional[str]:
    """The text of a literal string argument; None for anything computed."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _reads_only_js(expression: Optional[str]) -> bool:
    if expression is None:
        return False
    text = _JS_DECLARATION.sub(" ", expression)
    return not _JS_ASSIGNMENT.search(text) and not _JS_ACTS.search(text)
