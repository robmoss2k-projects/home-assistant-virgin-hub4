"""Release layout and published metadata checks; no Hub interactions."""

from importlib.resources import files
import json
from os import environ
from pathlib import Path
import re
from struct import unpack

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "custom_components" / "virgin_hub4"


def test_release_metadata_and_brand_dimensions():
    store = json.loads((ROOT / "hacs.json").read_text(encoding="utf-8"))
    manifest = json.loads((PACKAGE / "manifest.json").read_text(encoding="utf-8"))
    assert store["name"] == manifest["name"]
    assert store["country"] == "GB"
    assert manifest["domain"] == PACKAGE.name
    assert manifest["categories"] == ["computers_network.routers_network"]
    assert manifest["config_flow"]
    assert (PACKAGE / "translations" / "en.json").is_file()
    assert (ROOT / "LICENSE").is_file()
    packages = {p.parent.name for p in (ROOT / "custom_components").glob("*/manifest.json")}
    assert packages == {PACKAGE.name}
    for name, width, height in (
        ("icon", 256, 256),
        ("logo", 576, 160),
        ("dark_logo", 576, 160),
    ):
        for scale, suffix in ((1, ""), (2, "@2x")):
            data = (PACKAGE / "brand" / f"{name}{suffix}.png").read_bytes()
            assert data.startswith(b"\x89PNG\r\n\x1a\n")
            assert unpack("!II", data[16:24]) == (width * scale, height * scale)
            assert data[25] == 6  # RGBA, including transparent padding.


def test_actual_marketplace_manifest_loader_accepts_package():
    marketplace = pytest.importorskip(
        "homeassistant.components.marketplace.repositories.integration"
    )
    # Home Assistant 2026.11's post-install manifest check, without contacting GitHub
    # or installing onto any real Home Assistant instance.
    marketplace._check_loadable_manifest(PACKAGE, PACKAGE.name)
    core = files("homeassistant")
    assert not (core / "components" / PACKAGE.name).is_dir()
    taxonomy = json.loads((core / "generated" / "integration_categories.json").read_text())
    assert any(
        group["slug"] == "computers_network"
        and any(sub["slug"] == "routers_network" for sub in group["subcategories"])
        for group in taxonomy
    )


def test_marketplace_minimum_matches_tested_core_and_tag_matches_package():
    """Validate the supported baseline; a release tag must name this exact version."""
    store = json.loads((ROOT / "hacs.json").read_text(encoding="utf-8"))
    manifest = json.loads((PACKAGE / "manifest.json").read_text(encoding="utf-8"))
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
    assert [line for line in requirements if re.match(r"^homeassistant\b", line)] == [
        f"homeassistant=={store['homeassistant']}"
    ]
    if environ.get("GITHUB_REF_TYPE") == "tag":
        assert environ["GITHUB_REF_NAME"] == manifest["version"], (
            "The release tag must exactly match the Home Assistant manifest version"
        )
