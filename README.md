# nist-iso42001-crosswalk-mcp

The named mapping auditors search for: **NIST AI RMF ↔ ISO/IEC 42001:2023**, both directions, governed + SIGIL-signed. CSOAI Layer-0.

## Tools
- `list_crosswalk()` — the full crosswalk (NIST function.category ↔ ISO clause/Annex-A)
- `map_nist_to_iso(nist_id)` — e.g. `GOVERN-1.1` or `MEASURE` → ISO 42001 controls
- `map_iso_to_nist(iso_id)` — e.g. `A.6.2.4`, `9.1` → NIST AI RMF subcategories
- `coverage_report()` — rows per NIST function

Representative, source-aligned (NIST AI 100-1/600-1 + ISO/IEC 42001:2023), expandable. Apache-2.0.
