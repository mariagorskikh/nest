# SPDX-License-Identifier: Apache-2.0
"""Built-in scenario YAML files shipped inside the nest-core wheel.

These helpers expose the bundled reference scenarios (``marketplace``,
``auction``, ``voting``, ``consensus``, ``supply_chain``, ``reputation``,
``shell_marketplace``, ``delegated_auth``) so users
can run them without cloning the repo:

    nest run marketplace
    nest scenarios list
    nest scenarios show marketplace
    nest scenarios cp marketplace ./

Example::

    from nest_core.builtin_scenarios import list_builtin, builtin_path
    for name in list_builtin():
        print(name, builtin_path(name))
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

_PACKAGE = "nest_core.scenarios_builtin.yaml"


def list_builtin() -> list[str]:
    """Return the sorted list of built-in scenario names.

    Example::

        names = list_builtin()  # ["auction", "consensus", ...]
    """
    out: list[str] = []
    for entry in resources.files(_PACKAGE).iterdir():
        name = entry.name
        if name.endswith(".yaml"):
            out.append(name[: -len(".yaml")])
    out.sort()
    return out


def is_builtin(name: str) -> bool:
    """Check whether ``name`` is the name of a built-in scenario.

    Example::

        if is_builtin("marketplace"): ...
    """
    return name in list_builtin()


def builtin_path(name: str) -> Path:
    """Return a filesystem path to the bundled YAML for ``name``.

    Raises ``KeyError`` if no built-in scenario is named ``name``.

    Example::

        path = builtin_path("marketplace")
        config = ScenarioConfig.from_yaml(path)
    """
    if not is_builtin(name):
        raise KeyError(name)
    # resources.files() returns a Traversable that may be a real path or a
    # zip-internal pointer.  For a wheel install on Python 3.12, hatchling
    # ships the YAMLs uncompressed, so str() resolves to a real filesystem
    # path.  If anyone ever zips us, this still works -- we copy through
    # `as_file` in the consumers that need a real path.
    ref = resources.files(_PACKAGE).joinpath(f"{name}.yaml")
    return Path(str(ref))


def builtin_text(name: str) -> str:
    """Return the raw YAML text for built-in scenario ``name``.

    Example::

        print(builtin_text("marketplace"))
    """
    if not is_builtin(name):
        raise KeyError(name)
    return resources.files(_PACKAGE).joinpath(f"{name}.yaml").read_text(encoding="utf-8")
