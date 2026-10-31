"""Every module task passes only options the installed module accepts.

Syntax checks and ansible-lint do not catch an unknown option (e.g. a
parameter that exists on a sibling module); the module only fails on the host.
"""
import json
import subprocess

import yaml

from test_render import ROOT

TASK_FILES = sorted(
    {*ROOT.glob("roles/*/tasks/*.yml"), *ROOT.glob("roles/*/handlers/*.yml"),
     *ROOT.glob("playbooks/*.yml"), *ROOT.glob("playbooks/tasks/*.yml"),
     *ROOT.glob("tests/integration/*.yml")})
NESTED = ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers")
MODULE_PREFIXES = ("ansible.builtin.", "ansible.posix.", "community.")
# Modules whose arguments are arbitrary names.
FREE_FORM = {"ansible.builtin.set_fact", "ansible.builtin.set_stats"}


def _tasks(items, origin):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        for key in NESTED:
            if isinstance(item.get(key), list):
                yield from _tasks(item[key], origin)
        for key, value in item.items():
            if key.startswith(MODULE_PREFIXES) and key not in FREE_FORM and isinstance(value, dict):
                yield origin, item.get("name", "?"), key, set(value)


def _all_module_uses():
    uses = []
    for path in TASK_FILES:
        doc = yaml.safe_load(path.read_text())
        uses.extend(_tasks(doc if isinstance(doc, list) else [], path.relative_to(ROOT)))
    return uses


def _options(modules):
    out = subprocess.run(["ansible-doc", "-j", *sorted(modules)], cwd=ROOT, check=True,
                         capture_output=True, text=True).stdout
    result = {}
    for name, data in json.loads(out).items():
        opts = data["doc"].get("options") or {}
        names = set(opts)
        for opt in opts.values():
            names.update(opt.get("aliases") or [])
        result[name] = names
    return result


def test_module_args_exist():
    uses = _all_module_uses()
    assert uses, "no module tasks found"
    options = _options({m for _, _, m, _ in uses})
    bad = [f"{origin}: '{task}' {module}: {sorted(args - options[module])}"
           for origin, task, module, args in uses
           # raw-params modules (command/shell) take free-form args
           if module in options and args - options[module] - {"_raw_params", "cmd", "argv"}]
    assert not bad, "unknown module options:\n" + "\n".join(bad)
