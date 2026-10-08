#!/usr/bin/env python3
"""
NIST AI RMF <-> ISO/IEC 42001 Crosswalk MCP — CSOAI Layer-0.

The named mapping auditors and lawyers actually search for: which NIST AI RMF
function/category corresponds to which ISO 42001 clause/Annex-A control, and
vice-versa. Representative, source-aligned crosswalk (expandable toward the full
~70-row set); each lookup is attestable (SIGIL).

Tools: list_crosswalk · map_nist_to_iso · map_iso_to_nist · coverage_report
"""
from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("NIST-ISO42001 Crosswalk", instructions="Map NIST AI RMF <-> ISO/IEC 42001, both directions, governed + signed.")

# ── SIGIL ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "crosswalk_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

# Representative crosswalk rows: NIST AI RMF (function.category) <-> ISO/IEC 42001 (clause / Annex A).
# Source-aligned to NIST AI 600-1 + NIST AIRC crosswalk + ISO/IEC 42001:2023. Expandable.
CROSSWALK: List[Dict[str, str]] = [
    {"nist": "GOVERN-1.1", "nist_title": "Legal/regulatory requirements understood & managed", "iso": "A.2 / 4.1", "iso_title": "AI policy; context of the organization"},
    {"nist": "GOVERN-1.2", "nist_title": "Trustworthy-AI characteristics in org policy", "iso": "A.2 / 5.2", "iso_title": "AI policy"},
    {"nist": "GOVERN-2.1", "nist_title": "Roles & responsibilities documented", "iso": "5.3 / A.3", "iso_title": "Roles, responsibilities & authorities"},
    {"nist": "GOVERN-3.2", "nist_title": "Workforce diversity & accountability", "iso": "7.2 / A.4.6", "iso_title": "Competence; human oversight resourcing"},
    {"nist": "GOVERN-4.1", "nist_title": "Risk culture & safety-first mindset", "iso": "A.6.1.2", "iso_title": "AI risk management process"},
    {"nist": "GOVERN-5.1", "nist_title": "Stakeholder feedback mechanisms", "iso": "A.9.3", "iso_title": "Interested-party concerns / reporting"},
    {"nist": "GOVERN-6.1", "nist_title": "Third-party / supply-chain risk policy", "iso": "A.10", "iso_title": "Third-party & supplier relationships"},
    {"nist": "MAP-1.1", "nist_title": "Context & intended purpose established", "iso": "A.6.2.2", "iso_title": "AI system requirements & specification"},
    {"nist": "MAP-2.3", "nist_title": "Scientific validity / TEVV documented", "iso": "A.6.2.4", "iso_title": "AI system verification & validation"},
    {"nist": "MAP-3.1", "nist_title": "Benefits & impacts characterized", "iso": "A.5.2 / A.5.4", "iso_title": "AI system impact assessment"},
    {"nist": "MAP-4.1", "nist_title": "Risks from third-party data/models mapped", "iso": "A.7.2 / A.10.2", "iso_title": "Data for AI; supplier components"},
    {"nist": "MEASURE-1.1", "nist_title": "Approaches & metrics identified", "iso": "9.1 / A.6.2.4", "iso_title": "Monitoring, measurement, analysis"},
    {"nist": "MEASURE-2.3", "nist_title": "System performance & validity evaluated", "iso": "A.6.2.4", "iso_title": "Verification & validation"},
    {"nist": "MEASURE-2.7", "nist_title": "Security & resilience evaluated", "iso": "A.6.2.6 / A.8", "iso_title": "AI system operation & security"},
    {"nist": "MEASURE-2.11", "nist_title": "Fairness & bias evaluated", "iso": "A.5.4 / A.7.4", "iso_title": "Impact assessment; data quality for bias"},
    {"nist": "MEASURE-3.1", "nist_title": "Mechanisms to track risks over time", "iso": "9.1 / A.6.2.5", "iso_title": "Ongoing monitoring; deployment controls"},
    {"nist": "MANAGE-1.2", "nist_title": "Risks treated & prioritized", "iso": "6.1 / A.6.1.3", "iso_title": "Actions to address risks; risk treatment"},
    {"nist": "MANAGE-2.2", "nist_title": "Mechanisms to sustain value & manage risk", "iso": "8.1 / A.6.2.5", "iso_title": "Operational planning & control"},
    {"nist": "MANAGE-3.1", "nist_title": "Third-party risks managed & monitored", "iso": "A.10.3", "iso_title": "Supplier monitoring"},
    {"nist": "MANAGE-4.1", "nist_title": "Post-deployment monitoring & response", "iso": "A.6.2.6 / 10.2", "iso_title": "Operation; nonconformity & corrective action"},
    {"nist": "MANAGE-4.3", "nist_title": "Incidents & errors communicated", "iso": "A.9.2 / A.8.4", "iso_title": "Incident reporting; event logging"},
]


class Row(BaseModel):
    nist: str
    nist_title: str
    iso: str
    iso_title: str


class Mapping(BaseModel):
    query: str
    direction: str
    matches: List[Row] = Field(default_factory=list)
    count: int = 0
    sigil: str = ""


CROSSWALK_TOOLS_DOC = "NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE) <-> ISO/IEC 42001:2023 (clauses + Annex A)."


@mcp.tool()
def list_crosswalk() -> Dict[str, Any]:
    """Return the full NIST AI RMF <-> ISO/IEC 42001 crosswalk (representative, expandable)."""
    return {"standard_a": "NIST AI RMF (AI 100-1 / 600-1)", "standard_b": "ISO/IEC 42001:2023",
            "rows": CROSSWALK, "count": len(CROSSWALK), "note": CROSSWALK_TOOLS_DOC,
            "sigil": _sigil("XWALK", f"list|{len(CROSSWALK)}")}


@mcp.tool()
def map_nist_to_iso(nist_id: str) -> Mapping:
    """Given a NIST AI RMF id (e.g. GOVERN-1.1, MEASURE-2.11) or function (GOVERN/MAP/MEASURE/MANAGE), return matching ISO 42001 controls."""
    q = nist_id.strip().upper()
    matches = [Row(**r) for r in CROSSWALK if r["nist"].upper() == q or r["nist"].upper().startswith(q + "-") or r["nist"].upper().startswith(q)]
    return Mapping(query=nist_id, direction="nist->iso", matches=matches, count=len(matches), sigil=_sigil("XWALK", f"n2i|{q}"))


@mcp.tool()
def map_iso_to_nist(iso_id: str) -> Mapping:
    """Given an ISO/IEC 42001 clause or Annex-A control (e.g. A.6.2.4, 9.1, A.10), return matching NIST AI RMF subcategories."""
    q = iso_id.strip().upper()
    matches = [Row(**r) for r in CROSSWALK if q in r["iso"].upper()]
    return Mapping(query=iso_id, direction="iso->nist", matches=matches, count=len(matches), sigil=_sigil("XWALK", f"i2n|{q}"))


@mcp.tool()
def coverage_report() -> Dict[str, Any]:
    """Coverage summary: how many crosswalk rows touch each NIST function + whether all four functions are represented."""
    funcs = {"GOVERN": 0, "MAP": 0, "MEASURE": 0, "MANAGE": 0}
    for r in CROSSWALK:
        fn = r["nist"].split("-")[0].upper()
        if fn in funcs:
            funcs[fn] += 1
    return {"by_nist_function": funcs, "all_functions_covered": all(v > 0 for v in funcs.values()),
            "total_rows": len(CROSSWALK), "sigil": _sigil("XWALK", "coverage")}


# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When nist-iso42001-crosswalk-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def http_app():
    """ASGI app for HTTP exposure, wrapped in the 2026-07-28 wire shim.

    stdio (``mcp.run()``) needs no shim; this is the enable path once the
    server is fronted by an HTTP transport. Bodies are buffered, so responses
    are requested in JSON mode rather than SSE.
    """
    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    return ShimASGI(
        mcp.streamable_http_app(json_response=True),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": "nist-iso42001-crosswalk-mcp", "version": "0.1.0"},
        ),
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
