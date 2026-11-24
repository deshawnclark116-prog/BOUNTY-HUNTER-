"""Convert only upstream public fixture manifests to JSON for local evaluation."""
import json
import pathlib
import sys
import yaml

root = pathlib.Path(sys.argv[1])
rows = []
for label in ("pass", "fail"):
    folder = root / label
    files = sorted(folder.glob("*.yaml"))
    if not files:
        raise SystemExit(f"No upstream fixtures in {folder}")
    for file in files:
        if file.stat().st_size > 2 * 1024 * 1024:
            raise SystemExit("Oversized fixture")
        manifest = yaml.safe_load(file.read_text(encoding="utf-8"))
        rows.append({"id": f"{label}/{file.name}", "expectedFail": label == "fail", "manifest": manifest})
print(json.dumps(rows))
