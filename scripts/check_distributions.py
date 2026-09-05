"""Check the artifacts, not the checkout, for runtime and shipped-test data.

Usage: python scripts/check_distributions.py dist
"""

from pathlib import Path
import sys
import tarfile
import zipfile


def check(directory: Path) -> None:
    wheels = list(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise SystemExit("expected exactly one wheel and one sdist")
    root = Path(__file__).resolve().parents[1]
    runtime = {
        str(path.relative_to(root / "src"))
        for pattern in ("src/nandatown/sim/scenarios/*.yaml",
                        "src/nandatown/skills/builtin/*.md")
        for path in root.glob(pattern)
    }
    test_data = {
        str(path.relative_to(root))
        for pattern in ("tests/fixtures/**/*", "schemas/*.json")
        for path in root.glob(pattern) if path.is_file()
    }
    with zipfile.ZipFile(wheels[0]) as wheel:
        missing = runtime - set(wheel.namelist())
        if missing:
            raise SystemExit(f"wheel missing runtime data: {sorted(missing)}")
    with tarfile.open(sources[0]) as source:
        names = {name.partition("/")[2] for name in source.getnames()}
        expected = test_data | {f"src/{name}" for name in runtime}
        missing = expected - names
        if missing:
            raise SystemExit(f"sdist missing data: {sorted(missing)}")
    print(f"Distribution data verified: {len(runtime)} runtime files,"
          f" {len(test_data)} fixture/schema files")


if __name__ == "__main__":
    check(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
