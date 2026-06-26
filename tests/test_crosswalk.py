"""Tests for the NIST AI RMF <-> ISO 42001 crosswalk MCP."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("xwalk", Path(__file__).resolve().parents[1] / "server.py")
srv = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(srv)


def test_list_crosswalk_nonempty_and_signed():
    r = srv.list_crosswalk()
    assert r["count"] == len(srv.CROSSWALK) >= 15
    assert r["sigil"]
    for row in r["rows"]:
        assert row["nist"] and row["iso"]


def test_map_nist_exact():
    m = srv.map_nist_to_iso("GOVERN-1.1")
    assert m.count >= 1
    assert any("A.2" in row.iso for row in m.matches)


def test_map_nist_by_function():
    m = srv.map_nist_to_iso("MEASURE")
    assert m.count >= 3  # several MEASURE rows
    assert all(row.nist.startswith("MEASURE") for row in m.matches)


def test_map_iso_to_nist():
    m = srv.map_iso_to_nist("A.6.2.4")
    assert m.count >= 1
    assert all("A.6.2.4" in row.iso for row in m.matches)


def test_coverage_all_four_functions():
    c = srv.coverage_report()
    assert c["all_functions_covered"] is True
    assert set(c["by_nist_function"]) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_unknown_nist_returns_empty_not_error():
    m = srv.map_nist_to_iso("NOPE-9.9")
    assert m.count == 0 and m.matches == []
