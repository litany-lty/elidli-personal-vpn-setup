#!/usr/bin/env python3
"""Build the public, installable ZIP from an explicit list of redistributable files."""
from __future__ import annotations

import argparse
import os
import stat
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "elidli-personal-vpn-setup"
PUBLIC_FILES = (
    ".gitignore", ".github/workflows/smoke.yml", "README.md", "LICENSE", "SKILL.md", "agents/openai.yaml",
    "references/data-sources.md", "references/deployment.md", "references/purchase.md",
    "references/providers.csv", "references/offer-id-aliases.json", "references/offer-identities.md",
    "references/fx.json", "scripts/client_config.py", "scripts/deploy.py", "scripts/order.py",
    "scripts/public_host.py", "scripts/recommend.py", "scripts/resolve_offer.py",
    "scripts/package_release.py", "tests/test_smoke.py",
)


def build(destination: Path) -> None:
    if destination.suffix.lower() != ".zip":
        raise ValueError("The output path must end in .zip")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".tmp", delete=False) as temporary:
        staging = Path(temporary.name)
    try:
        with zipfile.ZipFile(staging, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for name in PUBLIC_FILES:
                source = ROOT / name
                if source.resolve() != source or not source.is_file():
                    raise ValueError(f"Expected a regular public file: {name}")
                entry = zipfile.ZipInfo(f"{NAME}/{name}")
                entry.create_system = 3
                mode = 0o755 if name.endswith(".py") else 0o644
                entry.external_attr = (stat.S_IFREG | mode) << 16
                bundle.writestr(entry, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.chmod(staging, 0o644)
        os.replace(staging, destination)
    finally:
        staging.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / f"{NAME}.zip")
    args = parser.parse_args()
    try:
        build(args.output)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Packaging failed: {error}\n")
    print(f"Built {args.output} ({len(PUBLIC_FILES)} public files)")


if __name__ == "__main__":
    main()
