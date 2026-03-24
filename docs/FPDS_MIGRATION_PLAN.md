# FPDS → SAM.gov Migration Update Plan

**Created:** 2026-03-24
**Status:** IN PROGRESS
**Context:** FPDS.gov was fully decommissioned on February 24, 2026. All references must be updated to reflect the SAM.gov Contract Awards system.

---

## Migration Facts (Source of Truth)

| Old | New |
|-----|-----|
| FPDS.gov / ezSearch | `sam.gov/contract-data` and `sam.gov/search` |
| FPDS login / manage awards | `sam.gov/contracting` |
| FPDS ATOM feed (XML, no auth) | SAM.gov Contract Awards API — `api.sam.gov/contract-awards/v1/search` (JSON, API key required) |
| FPDS reports / Data Bank | SAM.gov Data Bank (migrated 2020) |
| Transition/help page | `sam.gov/fpds` |
| API docs | `open.gsa.gov/api/contract-awards/` |

### Key Changes for Practitioners
1. **Authentication now mandatory** — API key required (free, from SAM.gov profile)
2. **XML → JSON** — ATOM feed replaced by REST/JSON API
3. **Rate limits tighter** — 10 req/day (no SAM role), 1,000/day (with role), 10,000/day (system accounts)
4. **Field names changed** — variance doc at `open.gsa.gov/api/contract-awards/v1/FPDSvsSAM-ContractDataAPI.pdf`
5. **DoD 90-day embargo** on "unrevealed" contract data
6. **Bulk extract** replaces ATOM pagination — up to 1M records in JSON/CSV
7. **USAspending remains valid** — still no API key required, covers same underlying data

### Style Guide for Updates
- Use **"SAM.gov Contract Data (formerly FPDS-NG)"** on first mention in each file
- Use **"SAM.gov Contract Data"** or **"SAM.gov"** on subsequent mentions
- Keep historical context where it aids understanding (e.g., "records dating back to FPDS-NG's 2004 inception")
- Do NOT delete references where FPDS is used as a historical data source name in code comments or variable names that would break code

---

## Files to Update (28+ references across 14 files)

### Priority 1: Chapter 03 — Data Acquisition (Heaviest Impact)

#### File: `chapters/03-data-acquisition/README.md`
| Line | Current | Action |
|------|---------|--------|
| 11 | "FPDS has contract action records going back to 2004" | Update: "SAM.gov Contract Data (formerly FPDS-NG) has contract action records going back to 2004" |
| 17 | Lists "FPDS" in API list | Replace with "SAM.gov Contract Awards API" |
| 80–84 | Full "### FPDS-NG" subsection describing ATOM feed, fpds.gov, legacy web interface | **REWRITE** entire subsection to describe SAM.gov Contract Awards API. Mention FPDS-NG retirement date (Feb 24, 2026). Describe new JSON API, auth requirements, rate limits. Keep as ### heading. |
| 263 | "common in FPDS and some DoD financial system exports" | Update: "common in legacy FPDS exports and some DoD financial system exports" |
| 276 | Code comment `# Common in FPDS and DoD financial exports` | Update: `# Common in legacy FPDS and DoD financial exports` |
| 439 | "use the public FPDS and USAspending APIs" | Update: "use the SAM.gov Contract Awards API and USAspending API" |

#### File: `chapters/03-data-acquisition/exercises/exercises.md`
| Line | Current | Action |
|------|---------|--------|
| 69 | "exported from FPDS for Navy IT contracts" | Update: "exported from SAM.gov Contract Data (formerly FPDS) for Navy IT contracts" |

#### File: `chapters/03-data-acquisition/exercises/solutions/solutions.md`
| Line | Current | Action |
|------|---------|--------|
| 190 | "FPDS contract award data" | Update: "SAM.gov contract award data (formerly FPDS)" |
| 194 | "FPDS data is published publicly at fpds.gov" | **REWRITE**: "Contract award data is published publicly through SAM.gov (formerly at fpds.gov, retired Feb 2026) and through the USAspending API under the DATA Act." |
| 198 | "querying internal FPDS-NG via a government system" | Update: "querying contract data via SAM.gov on a government system" |

#### File: `chapters/03-data-acquisition/code-examples/python/02_government_data_sources.py`
| Line | Current | Action |
|------|---------|--------|
| 184 | "FPDS Award Details PDFs" | Update: "SAM.gov Contract Award Details (formerly FPDS)" |

#### File: `chapters/03-data-acquisition/code-examples/python/03_platform_data_catalogs.py`
| Line | Current | Action |
|------|---------|--------|
| 577 | "from FPDS feed" | Update: "from SAM.gov contract data feed (formerly FPDS)" |

### Priority 2: Chapter 04 — Data Wrangling

#### File: `chapters/04-data-wrangling/README.md`
| Line | Current | Action |
|------|---------|--------|
| 75 | "appears in the agency's contracting system, in FPDS-NG, and in the USASpending.gov aggregation" | Update: "appears in the agency's contracting system, in SAM.gov Contract Data (formerly FPDS-NG), and in the USASpending.gov aggregation" |
| 79 | Code comment `# In FPDS/USASpending: contract_award_unique_key + modification_number` | Update: `# In SAM.gov/USASpending (formerly FPDS): contract_award_unique_key + modification_number` |
| 463 | Code comment `# Source: OMB A-11 Appendix C, supplemented with FPDS agency codes` | Update: `# Source: OMB A-11 Appendix C, supplemented with FPDS agency codes` — **KEEP AS-IS** (historical reference to code system origin) |

#### File: `chapters/04-data-wrangling/exercises/exercises.md`
| Line | Current | Action |
|------|---------|--------|
| 11 | "DoD contract modification export from FPDS-NG" | Update: "DoD contract modification export from SAM.gov (formerly FPDS-NG)" |

### Priority 3: Other Chapters

#### File: `chapters/07-unsupervised-ml/README.md`
| Line | Current | Action |
|------|---------|--------|
| 34 | Contains FPDS reference in context | Update with "(formerly FPDS-NG)" parenthetical if describing current data access; keep as-is if historical |

#### File: `chapters/08-deep-learning/code-examples/python/03_transformer_nlp.py`
| Line | Current | Action |
|------|---------|--------|
| 68 | "Mimics the language and structure of real FPDS/USASpending contract descriptions" | Update: "Mimics the language and structure of real SAM.gov/USASpending contract descriptions (formerly FPDS)" |

#### File: `chapters/10-visualization/README.md`
| Line | Current | Action |
|------|---------|--------|
| 362 | Code comment `// Table 1: Contract awards from FPDS-NG (via Advana data catalog)` | Update: `// Table 1: Contract awards from SAM.gov Contract Data (formerly FPDS-NG), via Advana data catalog` |

#### File: `chapters/10-visualization/code-examples/python/03_platform_dashboards.py`
| Line | Current | Action |
|------|---------|--------|
| 205 | `// Source: FPDS-NG data via Advana data catalog` | Update: `// Source: SAM.gov contract data (formerly FPDS-NG) via Advana data catalog` |

#### File: `chapters/10-visualization/exercises/solutions/solutions.md`
| Line | Current | Action |
|------|---------|--------|
| 705 | "USASpending feeds, FPDS-NG" | Update: "USASpending feeds, SAM.gov Contract Data (formerly FPDS-NG)" |
| 718 | "If FPDS-NG data in Advana lags by 30+ days" | Update: "If SAM.gov contract data in Advana lags by 30+ days" |

### Priority 4: Platform Guides

#### File: `platform-guides/advana/README.md`
| Line | Current | Action |
|------|---------|--------|
| 105 | "**FPDS-NG** — Federal Procurement Data System. Contract and procurement data across all DoD components." | Update: "**SAM.gov Contract Data (formerly FPDS-NG)** — Federal procurement and contract data across all DoD components. Migrated from FPDS.gov in February 2026." |
| 167 | `FROM advana_catalog.procurement.fpds_awards_fy2024` | **KEEP AS-IS** — this is a table name in Advana's catalog; changing it would make the query incorrect. Add a comment noting the table name reflects the legacy FPDS source. |

### Priority 5: Documentation

#### File: `docs/QA_REPORT.md`
| Line | Current | Action |
|------|---------|--------|
| 44 | "FPDS-NG" listed as technically accurate | **KEEP AS-IS** — this is a historical QA record |

---

## Execution Phases

### Phase 1: Execute Updates (Sonnet Agent)
- Apply all changes listed above
- Preserve code functionality (do not rename variables or table names)
- Follow the style guide for first/subsequent mentions

### Phase 2: Gap Analysis (Opus Agent)
- Re-scan all files for any missed FPDS references
- Verify accuracy of all updates against migration facts
- Check for consistency in terminology across files
- Identify any broken cross-references or contextual issues
- Check code examples still make sense with updated comments
- Findings appended to this document

### Phase 3: Fix Gaps (Opus Agent)
- Address all issues identified in Phase 2

---

## Gap Analysis Findings

**Performed:** 2026-03-24 by Opus agent (Phase 2)

### A. Missed References

1. **`chapters/07-unsupervised-ml/README.md`, line 34** — "FPDS has 150 million contract action records" was NOT updated. The plan (Priority 3) flagged this line and instructed: add "(formerly FPDS-NG)" parenthetical if describing current data access; keep as-is if historical. This sentence uses "FPDS" as a reference to a current data volume claim and reads as though FPDS is still an active system. **Recommended fix:** Change to "SAM.gov Contract Data (formerly FPDS-NG) has 150 million contract action records" to match the first-mention style guide and clarify that FPDS is no longer the active system.

No other missed references were found outside the plan's scope. All 15 files containing "FPDS" were accounted for.

### B. Accuracy Check — Verifying All 11 Updated Files

**Priority 1 files:**

2. **`chapters/03-data-acquisition/README.md`, line 11** — PASS. First mention uses "SAM.gov Contract Data (formerly FPDS-NG)". Reads naturally.

3. **`chapters/03-data-acquisition/README.md`, line 17** — PASS. "SAM.gov Contract Awards API" listed in the API list. However, "SAM" also appears separately in the same list ("USAspending, data.gov, SAM, SAM.gov Contract Awards API"), which creates mild redundancy — SAM.gov entity registration and SAM.gov Contract Awards API are now both SAM.gov endpoints. This is not an error (they are distinct APIs) but may confuse readers. **Recommended fix (optional):** Consider clarifying as "SAM Entity API, SAM.gov Contract Awards API" to distinguish them. Low priority.

4. **`chapters/03-data-acquisition/README.md`, lines 80–86** — PASS. The rewritten subsection includes all required elements: heading changed to "### SAM.gov Contract Awards API (formerly FPDS-NG)"; retirement date (February 24, 2026); JSON API endpoint (`api.sam.gov/contract-awards/v1/search`); API key requirement; rate limits (10/1,000/10,000 per day by tier); bulk extract option; USAspending alternative; field name variance document link; DoD 90-day embargo. Thorough and well-written.

5. **`chapters/03-data-acquisition/README.md`, line 265** — PASS. "legacy FPDS exports" correctly marks FPDS as historical.

6. **`chapters/03-data-acquisition/README.md`, line 278** — PASS. Code comment uses "legacy FPDS" — correct historical framing.

7. **`chapters/03-data-acquisition/README.md`, line 441** — PASS. "SAM.gov Contract Awards API and USAspending API" — correctly updated.

8. **`chapters/03-data-acquisition/exercises/exercises.md`, line 69** — PASS. "SAM.gov Contract Data (formerly FPDS)" — first mention with parenthetical.

9. **`chapters/03-data-acquisition/exercises/solutions/solutions.md`, line 190** — PASS. "SAM.gov contract award data (formerly FPDS)" — correctly updated.

10. **`chapters/03-data-acquisition/exercises/solutions/solutions.md`, line 194** — PASS. Rewritten sentence correctly describes SAM.gov as current source, notes fpds.gov retirement (Feb 2026), mentions USAspending and DATA Act.

11. **`chapters/03-data-acquisition/exercises/solutions/solutions.md`, line 198** — PASS. "querying contract data via SAM.gov on a government system" — reads naturally.

12. **`chapters/03-data-acquisition/code-examples/python/02_government_data_sources.py`, line 184** — PASS. "SAM.gov Contract Award Details (formerly FPDS)" in a docstring comment list item. No code broken.

13. **`chapters/03-data-acquisition/code-examples/python/03_platform_data_catalogs.py`, line 577** — PASS. Print string updated to "from SAM.gov contract data feed (formerly FPDS)". No code logic affected.

**Priority 2 files:**

14. **`chapters/04-data-wrangling/README.md`, line 75** — PASS. "SAM.gov Contract Data (formerly FPDS-NG)" — correct first mention.

15. **`chapters/04-data-wrangling/README.md`, line 79** — PASS. Code comment "In SAM.gov/USASpending (formerly FPDS)" — correct subsequent mention with historical context.

16. **`chapters/04-data-wrangling/README.md`, line 463** — PASS. Kept as-is per plan: "supplemented with FPDS agency codes" — historical reference to code system origin.

17. **`chapters/04-data-wrangling/exercises/exercises.md`, line 11** — PASS. "from SAM.gov (formerly FPDS-NG)" — correct first mention.

**Priority 3 files:**

18. **`chapters/07-unsupervised-ml/README.md`, line 34** — FAIL. See finding #1 above.

19. **`chapters/08-deep-learning/code-examples/python/03_transformer_nlp.py`, line 68** — PASS. Docstring updated to "SAM.gov/USASpending contract descriptions (formerly FPDS)". No code broken.

20. **`chapters/10-visualization/README.md`, line 362** — PASS. Qlik comment updated to "SAM.gov Contract Data (formerly FPDS-NG), via Advana data catalog".

21. **`chapters/10-visualization/code-examples/python/03_platform_dashboards.py`, line 205** — PASS. Comment updated to "SAM.gov contract data (formerly FPDS-NG) via Advana data catalog".

22. **`chapters/10-visualization/exercises/solutions/solutions.md`, line 705** — PASS. "SAM.gov Contract Data (formerly FPDS-NG)" — correct first mention.

23. **`chapters/10-visualization/exercises/solutions/solutions.md`, line 718** — PASS. "SAM.gov contract data in Advana" — correct subsequent mention without repeated parenthetical.

**Priority 4 files:**

24. **`platform-guides/advana/README.md`, line 105** — PASS. Full first-mention format used. Includes migration note (February 2026).

25. **`platform-guides/advana/README.md`, line 167** — PASS. Table name `fpds_awards_fy2024` correctly kept as-is with explanatory SQL comment: "table name reflects legacy FPDS source; do not rename".

**Priority 5 files:**

26. **`docs/QA_REPORT.md`, line 44** — PASS. Kept as-is per plan. Historical QA record referencing "FPDS-NG" in an accuracy assessment is appropriate.

### C. Consistency Check

27. **First-mention parenthetical style is consistent across all updated files.** All files use one of: "SAM.gov Contract Data (formerly FPDS-NG)", "SAM.gov contract award data (formerly FPDS)", or "SAM.gov (formerly FPDS-NG)" — minor capitalization and wording variations that are contextually appropriate (e.g., headings vs. inline prose vs. code comments). No file uses a conflicting or confusing style.

28. **Subsequent mentions correctly drop the parenthetical.** No file repeats "(formerly FPDS-NG)" after the first occurrence. Confirmed in Ch03 README (uses "SAM.gov Contract Awards API" in subsequent mentions), Ch04 README (second reference uses code comment style), and Ch10 solutions (line 718 drops parenthetical).

29. **The only bare "FPDS" references remaining (without "formerly" or "legacy" context) are:**
    - `chapters/07-unsupervised-ml/README.md` line 34 — **NEEDS FIX** (see finding #1)
    - `chapters/04-data-wrangling/README.md` line 463 — correctly kept as-is (historical code-origin reference per plan)
    - `chapters/03-data-acquisition/README.md` lines 82, 86 — acceptable; these are within the rewritten FPDS-NG retirement subsection where FPDS is explicitly identified as the former system
    - `docs/QA_REPORT.md` line 44 — correctly kept as-is (historical QA record per plan)
    - `platform-guides/advana/README.md` line 167 — correctly kept as table name with explanatory comment

### D. Contextual Correctness

30. All updated paragraphs read naturally. No broken sentences, awkward phrasing, or factual errors introduced by the migration updates.

31. **`chapters/03-data-acquisition/README.md`, lines 80–86** — The rewritten FPDS-NG subsection reads well and maintains the practitioner voice of the handbook. The transition from the USAspending subsection above it is smooth.

32. **`chapters/03-data-acquisition/exercises/solutions/solutions.md`, line 194** — The rewritten sentence about public data availability is factually correct and reads naturally in context.

33. No redundancies or contradictions were introduced in any file.

### E. Code Example Check

34. **`chapters/03-data-acquisition/code-examples/python/02_government_data_sources.py`** — PASS. Only a docstring was changed (line 184). No executable code modified.

35. **`chapters/03-data-acquisition/code-examples/python/03_platform_data_catalogs.py`** — PASS. Only a print statement string was changed (line 577). No logic affected.

36. **`chapters/04-data-wrangling/README.md`** — PASS. Code comment on line 79 updated; code on line 80 (`pk_cols = [...]`) untouched. Line 463 kept as-is.

37. **`chapters/08-deep-learning/code-examples/python/03_transformer_nlp.py`** — PASS. Only a docstring was changed (line 68). Function logic untouched.

38. **`chapters/10-visualization/code-examples/python/03_platform_dashboards.py`** — PASS. Only a Qlik script comment was changed (line 205). No executable Python or Qlik logic affected.

39. **`platform-guides/advana/README.md`** — PASS. SQL table name `fpds_awards_fy2024` preserved. Only the bold label on line 105 was changed, and a SQL comment was added on line 167.

40. **No variable names, function names, table names, or import statements were modified in any file.** All code remains functional.

### Summary

| Category | Result |
|----------|--------|
| Missed references | **1 found** — Ch07 line 34 |
| Accuracy of updates | **All correct** except Ch07 (not updated) |
| Consistency | **Consistent** across all updated files |
| Contextual correctness | **No issues** — all paragraphs read naturally |
| Code examples | **No breakage** — only comments/docstrings changed |
| Optional improvement | Ch03 line 17 — "SAM" vs "SAM.gov Contract Awards API" mild redundancy (low priority) |

**Phase 3 action items:**
1. **(Required)** Update `chapters/07-unsupervised-ml/README.md` line 34: change "FPDS has" to "SAM.gov Contract Data (formerly FPDS-NG) has"
2. **(Optional)** Clarify `chapters/03-data-acquisition/README.md` line 17 API list to distinguish SAM Entity API from SAM.gov Contract Awards API

---

## Phase 3 Fixes Applied

**Performed:** 2026-03-24 by Opus agent

1. **`chapters/07-unsupervised-ml/README.md`, line 34** — Changed "FPDS has 150 million contract action records" to "SAM.gov Contract Data (formerly FPDS-NG) has 150 million contract action records". This was the only missed reference from Phase 1.

2. **`chapters/03-data-acquisition/README.md`, line 17** — Changed "SAM" to "SAM Entity API" in the API list to distinguish it from the "SAM.gov Contract Awards API" that appears in the same list. Eliminates reader confusion about two SAM.gov endpoints.
