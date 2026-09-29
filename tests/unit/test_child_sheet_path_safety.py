from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from kicad_mcp.tools import schematic, validation


def test_sheet_discovery_skips_network_sheetfile_before_exists(
    monkeypatch, tmp_path: Path
) -> None:
    hierarchy = {"root": {"children": [{"name": "unsafe", "filename": r"\\attacker\share\x.kicad_sch"}]}}
    fake = SimpleNamespace(sheets=SimpleNamespace(get_sheet_hierarchy=lambda: hierarchy))
    monkeypatch.setattr(schematic, "_load_kicad_schematic", lambda _path: fake)

    with patch.object(Path, "exists", side_effect=AssertionError("exists must not run")):
        discovered = schematic._iter_child_sheet_paths(tmp_path / "root.kicad_sch")

    assert discovered == []


def test_empty_sheet_gate_skips_network_sheetfile_before_exists(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        validation,
        "_sheet_contracts",
        lambda _path: [{"name": "unsafe", "filename": r"\\attacker\share\x.kicad_sch", "pins": []}],
    )

    with patch.object(Path, "exists", side_effect=AssertionError("exists must not run")):
        ignored = validation._empty_child_sheet_ids(tmp_path / "root.kicad_sch")

    assert ignored == set()
