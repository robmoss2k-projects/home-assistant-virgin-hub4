"""Rehearse actual Marketplace disk install/update logic using local archives."""

from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "custom_components" / "virgin_hub4"
RUNTIME_SUFFIXES = {".py", ".json", ".yaml", ".png"}


def _release(version: str | None, ref: str) -> bytes:
    """Make the same top-level-directory shape as a GitHub tag archive."""
    archive = BytesIO()
    prefix = f"home-assistant-virgin-hub4-{ref}/"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipfile:
        for name in ("hacs.json", "README.md", "LICENSE"):
            zipfile.write(ROOT / name, prefix + name)
        for source in sorted(PACKAGE.rglob("*")):
            if source.suffix not in RUNTIME_SUFFIXES or not source.is_file():
                continue
            target = prefix + source.relative_to(ROOT).as_posix()
            if source.name == "manifest.json":
                manifest = json.loads(source.read_text(encoding="utf-8"))
                if version is None:
                    del manifest["version"]
                else:
                    manifest["version"] = version
                zipfile.writestr(target, json.dumps(manifest))
            else:
                zipfile.write(source, target)
    return archive.getvalue()


@pytest.mark.asyncio
async def test_marketplace_fresh_install_upgrade_and_failed_replacement(tmp_path):
    from awesomeversion import AwesomeVersion
    from homeassistant.components.marketplace.exceptions import MarketplaceError
    from homeassistant.components.marketplace.repositories.base import RepositoryArchive
    from homeassistant.components.marketplace.repositories.integration import IntegrationRepository
    from homeassistant.core import HomeAssistant

    store_json = json.loads((ROOT / "hacs.json").read_text(encoding="utf-8"))
    manifest_json = json.loads((PACKAGE / "manifest.json").read_text(encoding="utf-8"))
    old = manifest_json["version"]
    a, b, c = map(int, old.split("-", 1)[0].split("."))
    new = f"{a}.{b}.{c + 1}"
    bad = f"{a}.{b}.{c + 2}"
    first_release = _release(old, old)
    downloads = AsyncMock(side_effect=[first_release, _release(new, new), _release(None, bad)])
    ha = HomeAssistant(str(tmp_path))
    marketplace = SimpleNamespace(
        hass=ha,
        core=SimpleNamespace(config_path=str(tmp_path)),
        version=AwesomeVersion("2026.11.2"),
        configuration=SimpleNamespace(plugin_path="www/community", theme_path="themes"),
        repositories=SimpleNamespace(list_installed=[]),
        async_download_file=downloads,
        async_dispatch=Mock(),
    )
    repo = IntegrationRepository(marketplace, "fixture/home-assistant-virgin-hub4")
    archive = RepositoryArchive(first_release)
    repo.repository_manifest = repo.repository_manifest.from_dict(
        json.loads(archive.read("hacs.json"))
    )
    repo._check_minimum_version(repo.repository_manifest)
    assert repo.repository_manifest.homeassistant == AwesomeVersion(store_json["homeassistant"])
    repo.tree = archive.tree
    repo.treefiles = [entry.path for entry in repo.tree]
    assert repo.try_resolve_content()
    repo.resolve_content()
    assert repo.content.path.remote == PACKAGE.relative_to(ROOT).as_posix()
    repo._use_integration_manifest(
        json.loads(archive.read(f"{repo.content.path.remote}/manifest.json"))
    )
    repo.content.path.local = repo.localpath

    installed = Path(repo.localpath)
    assert installed == tmp_path / "custom_components" / "virgin_hub4"
    storage = tmp_path / ".storage"
    storage.mkdir()
    fixture = storage / "fixture-configuration"
    fixture.write_bytes(b"synthetic user data, not a Hub configuration backup")
    try:
        repo.ref = f"tags/{old}"
        await repo._async_write_content(repo.download_repository_zip)
        assert (installed / "config_flow.py").is_file()
        assert (installed / "brand" / "icon.png").read_bytes() == (
            PACKAGE / "brand" / "icon.png"
        ).read_bytes()
        assert json.loads((installed / "manifest.json").read_text())["version"] == old
        assert not (installed / "hacs.json").exists()
        assert not (installed / "__pycache__").exists()

        repo.data.installed = True
        repo.ref = f"tags/{new}"
        await repo._async_write_content(repo.download_repository_zip)
        assert json.loads((installed / "manifest.json").read_text())["version"] == new

        repo.ref = f"tags/{bad}"
        with pytest.raises(MarketplaceError) as failure:
            await repo._async_write_content(repo.download_repository_zip)
        assert failure.value.translation_key == "installed_manifest_without_version"
        assert json.loads((installed / "manifest.json").read_text())["version"] == new
        assert fixture.read_bytes() == b"synthetic user data, not a Hub configuration backup"
        assert downloads.await_count == 3
        assert all(
            f"/tags/{version}" in str(call.args[0])
            for version, call in zip((old, new, bad), downloads.await_args_list, strict=True)
        )
    finally:
        await ha.async_stop(force=True)
