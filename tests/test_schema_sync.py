import json
from pathlib import Path

from nandatown.schemas import export_schemas


def test_checked_in_schemas_match_exported_contracts(tmp_path):
    generated = [Path(path) for path in export_schemas(str(tmp_path))]
    committed = Path(__file__).resolve().parents[1] / "schemas"
    assert {path.name for path in generated} == {
        path.name for path in committed.glob("*.schema.json")}
    for path in generated:
        assert json.loads(path.read_text()) == json.loads(
            (committed / path.name).read_text()), f"regenerate schemas: {path.name} drifted"
