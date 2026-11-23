"""Collect dependency notices for the local macOS installer."""
import json
import subprocess
import sys
from pathlib import Path


def main(destination: Path) -> None:
    metadata = subprocess.check_output([
        "cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", "core/Cargo.toml", "--filter-platform", sys.argv[2],
    ])
    packages = json.loads(metadata)["packages"]
    with destination.open("w", encoding="utf-8") as output:
        for package in sorted(packages, key=lambda item: (item["name"], item["version"])):
            if package["source"] is None:
                continue

            root = Path(package["manifest_path"]).parent
            files = {path for path in root.iterdir() if path.is_file()
                     and path.name.upper().startswith(("LICENSE", "COPYING", "UNLICENSE", "NOTICE"))}
            if package["license_file"]:
                files.add(root / package["license_file"])
            if package["name"] == "boring-sys":
                files.add(root / "deps/boringssl/LICENSE")

            print(package["name"], package["version"], package["license"] or "", file=output)
            for path in sorted(files):
                print(path.read_text(encoding="utf-8", errors="replace"), file=output)
            print(file=output)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
