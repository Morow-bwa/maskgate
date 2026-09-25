from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).parents[1]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_responses_module_does_not_depend_on_chat_implementation() -> None:
    imports = _imports(APP / "responses" / "orchestrator.py")

    assert all(not module.startswith("app.chat") for module in imports)
    assert "app.api" in imports


def test_transport_and_privacy_modules_do_not_import_route_orchestrators() -> None:
    checked = [
        *sorted((APP / "proxy").glob("*.py")),
        APP / "privacy" / "pipeline.py",
        APP / "privacy" / "wire.py",
    ]

    for path in checked:
        imports = _imports(path)
        assert all(
            not module.startswith(("app.chat", "app.responses")) for module in imports
        ), path
