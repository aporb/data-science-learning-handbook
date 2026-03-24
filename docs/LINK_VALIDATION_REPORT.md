# Link Validation Report
**Generated:** 2026-03-24
**Scope:** 13 chapter READMEs + 5 platform guide READMEs
**Validator:** Cross-reference and link validation agent

---

## Summary

| Check | Status |
|---|---|
| Chapter sequential flow (01–13) | PASS — every chapter correctly references the next |
| File links to exercises/exercises.md | PASS — all exercise links resolve |
| File links to code-examples/ | FAIL — `code-examples/python/` directory is empty (.gitkeep only); multiple chapters reference non-existent .py files |
| Internal cross-references (chapter-to-chapter) | MOSTLY PASS — 3 issues noted below |
| Chapter 14 reference | ISSUE — Ch13 references a "Chapter 14" that does not exist |
| Platform guide sequential flow | PARTIAL — some guides reference a "next guide/chapter" that is not clearly defined |
| Duplicate content | LOW — some expected overlap on CAC/Collibra/data-tier content; one issue in Ch05 |
| Character name consistency | ISSUE — "Priya" has different last names across Ch02/Ch03/Ch04/Ch05 |

---

## 1. Chapter Sequential Flow ("What comes next")

Each chapter's close section was checked to confirm it correctly names the immediately following chapter.

| Chapter | What it says comes next | Correct target | Status |
|---|---|---|---|
| Ch01 | "Chapter 02 covers Python and R…" | Ch02 | PASS |
| Ch02 | "Chapter 03 covers data acquisition…" | Ch03 | PASS |
| Ch03 | "Chapter 04 covers the mechanics of data wrangling…" (stated twice, once inline and once in the close) | Ch04 | PASS |
| Ch04 | "Chapter 05 covers exploratory data analysis…" | Ch05 | PASS |
| Ch05 | "Chapter 06 covers supervised machine learning…" | Ch06 | PASS |
| Ch06 | "Chapter 07 covers unsupervised learning…" | Ch07 | PASS |
| Ch07 | "Chapter 08 covers deep learning…" | Ch08 | PASS |
| Ch08 | "Chapter 09 covers MLOps…" | Ch09 | PASS |
| Ch09 | "Chapter 10 covers visualization and dashboards…" | Ch10 | PASS |
| Ch10 | "Chapter 11 covers deployment and scaling…" | Ch11 | PASS |
| Ch11 | "Chapter 12 covers ethics, governance, and compliance…" | Ch12 | PASS |
| Ch12 | "Chapter 13 covers generative AI, RAG pipelines, and large language models…" | Ch13 | PASS |
| Ch13 | "Chapter 14 brings everything together — building a capstone project…" | **Ch14 DOES NOT EXIST** | **FAIL** |

**Issue Ch13-1 (BROKEN REFERENCE):** Ch13's "What comes next" section (line 406) references "Chapter 14" as a capstone chapter. No `chapters/14-*/` directory exists in the repository. This is either a planned chapter that was never created, or the series ends at Ch13 and this close section needs to be revised or removed.

---

## 2. File Links in Chapter READMEs

### 2a. exercises/exercises.md links

All chapters that link to their exercises file were verified:

| Chapter | Link text | Target path | File exists? |
|---|---|---|---|
| Ch02 | `[exercises/](./exercises/exercises.md)` | chapters/02-python-r-foundations/exercises/exercises.md | PASS |
| Ch03 | `[exercises/exercises.md](exercises/exercises.md)` | chapters/03-data-acquisition/exercises/exercises.md | PASS |
| Ch04 | `[exercises](./exercises/exercises.md)` | chapters/04-data-wrangling/exercises/exercises.md | PASS |
| Ch06 | `[exercises/exercises.md](./exercises/exercises.md)` | chapters/06-supervised-ml/exercises/exercises.md | PASS |
| Ch07 | `[exercises/exercises.md](exercises/exercises.md)` | chapters/07-unsupervised-ml/exercises/exercises.md | PASS |
| Ch08 | `[exercises](./exercises/exercises.md)` | chapters/08-deep-learning/exercises/exercises.md | PASS |
| Ch09 | `` `exercises/exercises.md` `` (backtick, not hyperlink) | chapters/09-mlops/exercises/exercises.md | PASS (file exists; not a hyperlink) |
| Ch12 | `[exercises/exercises.md](./exercises/exercises.md)` | chapters/12-ethics-governance/exercises/exercises.md | PASS |

**Note:** Ch01, Ch05, Ch10, Ch11, Ch13 refer to exercises in prose ("See the `exercises/` directory") without a markdown link. The exercises files exist for all 13 chapters, so no broken links; the prose-only references are acceptable but inconsistent in style.

### 2b. code-examples/ references

Multiple chapters reference Python files under `code-examples/python/`. The `code-examples/` directory contains only a `.gitkeep` file — **no Python files exist**.

| Chapter | File referenced | Exists? |
|---|---|---|
| Ch03 | `code-examples/python/01_api_connections.py` | **MISSING** |
| Ch04 | `code-examples/python/03_palantir_pipeline_builder.py` | **MISSING** |
| Ch05 | `01_statistical_profiling.py` (relative, no path prefix) | **MISSING** |
| Ch05 | `03_platform_eda_workflows.py` (relative, no path prefix) | **MISSING** |
| Ch07 | `code-examples/python/01_clustering.py` | **MISSING** |
| Ch07 | `code-examples/python/03_topic_modeling.py` | **MISSING** |
| Ch08 | `code-examples/python/01_neural_network_fundamentals.py` | **MISSING** |
| Ch08 | `code-examples/python/02_cnn_image_classification.py` | **MISSING** |
| Ch08 | `code-examples/python/03_transformer_nlp.py` | **MISSING** |
| Ch08 | `code-examples/python/04_operational_inference_pipeline.py` | **MISSING** (referenced twice) |
| Ch09 | `code-examples/python/01_experiment_tracking.py` | **MISSING** |
| Ch09 | `code-examples/python/02_model_registry_deployment.py` | **MISSING** |
| Ch09 | `code-examples/python/03_pipeline_orchestration.py` | **MISSING** (referenced twice) |
| Ch13 | `code-examples/python/02_rag_pipeline.py` | **MISSING** (referenced twice) |
| Ch13 | `code-examples/python/01_llm_integration.py` | **MISSING** |

**Issue CODE-1 (BROKEN REFERENCES — WIDESPREAD):** The `code-examples/python/` directory is empty. All 15 code-example references across 8 chapters point to non-existent files. These are in-prose references (backtick or `see X for implementation`), not hyperlinks, so they don't generate 404s in rendered markdown, but they fail the reader's expectation. This is a significant content gap.

**Note on Ch05 paths:** The two references in Ch05 use bare filenames (`01_statistical_profiling.py`, `03_platform_eda_workflows.py`) without a `code-examples/python/` prefix. If these are intended to be local to the chapter directory, the files also do not exist there. If they are intended to match the `code-examples/python/` convention used elsewhere, the naming follows a different numbering scheme (01_, 03_) that suggests a sub-directory per chapter may have been planned.

---

## 3. Internal Cross-References (Chapter-to-Chapter)

### 3a. Confirmed valid cross-references

| Location | Reference | Referenced content exists? | Accurate? |
|---|---|---|---|
| Ch05, line 178 | "The Qlik SSE pattern from Chapter 01" | Ch01 has SSE content at line 125 | PASS |
| Ch08, line 42 | "Chapter 06 covers the cases where traditional ML wins" | Ch06 is supervised ML | PASS |
| Ch11, line 97 (comment) | "see Chapter 06 for the full training pattern" | Ch06 covers training patterns | PASS |
| Ch12, line 473 | "Every Transform declares its inputs and outputs explicitly (see Chapter 02)" | Ch02 covers Foundry Transforms at line ~225 | PASS |
| Ch13, line 396 | "Have you run the relevant training data through your data quality checks from Chapter 4?" | Ch04 covers data quality | PASS |
| Ch13, lines 410 | Cross-references to Ch08 (Deep Learning), Ch09 (MLOps), Ch12 (Ethics) | All correct | PASS |

### 3b. Issues with cross-references

**Issue XREF-1 (INCORRECT REFERENCE):** Ch09's "What comes next" section (line 440) says:
> "the monitoring patterns that tell you when Kevin's vehicle detection model needs to be retrained"

This references Kevin Okafor from Ch08 (Deep Learning). However, Ch09 itself (MLOps) does not feature Kevin as a character — it features Sarah Chen. The reference to "Kevin's model" across a chapter boundary assumes reader continuity that is logical, but Kevin is never mentioned in Ch09's body, making the closing cross-reference feel like it refers to a story thread that was dropped. This is a narrative continuity issue, not a factual error.

**Issue XREF-2 (WEAK/MISSING CROSS-REFERENCE):** Ch05 (EDA) at line 178 references "the Qlik SSE pattern from Chapter 01" for embedding Isolation Forest results in a Qlik dashboard. However, Chapter 01 describes SSE only conceptually — it does not provide a pattern or code example. The actual SSE implementation guidance lives in the Qlik platform guide. This cross-reference is technically not wrong (Ch01 does mention SSE), but it directs readers to the wrong source for implementation guidance. A reference to the Qlik platform guide or Ch10 (Visualization) would be more useful.

**Issue XREF-3 (MISSING CROSS-REFERENCE — OPPORTUNITY):** Ch09 (MLOps) covers model monitoring and drift detection in detail, including concepts like data drift, feature drift, and retraining triggers. Ch06 (Supervised ML) trains models but has no forward reference to Ch09's monitoring discipline. A reader building their first classification model in Ch06 has no indication that production monitoring (Ch09) is a required follow-on. A brief note in Ch06's "What comes next" or a forward pointer to Ch09's drift management section would close this gap.

---

## 4. Chapter Flow Narrative Evaluation

The sequential chapter flow is logical and consistent:

- **Ch01 → Ch02:** Platform orientation → coding environment. Natural first step.
- **Ch02 → Ch03:** Environment setup → data acquisition. Correct prerequisite order.
- **Ch03 → Ch04:** Data acquisition → data wrangling. Correct: you get the data then clean it.
- **Ch04 → Ch05:** Data wrangling → EDA. Correct: clean first, then explore.
- **Ch05 → Ch06:** EDA → supervised ML. Correct: EDA is the prerequisite.
- **Ch06 → Ch07:** Supervised → unsupervised ML. Logical pair.
- **Ch07 → Ch08:** Unsupervised ML → deep learning. Sensible escalation in complexity.
- **Ch08 → Ch09:** Deep learning → MLOps. Correct: production concerns follow model building.
- **Ch09 → Ch10:** MLOps → visualization. The link is slightly forced — Ch09 ends with "models need to be seen" as justification, which works.
- **Ch10 → Ch11:** Visualization → deployment. Logical: dashboards need to run somewhere.
- **Ch11 → Ch12:** Deployment → ethics/governance. Good arc: after "how to deploy" comes "what you're responsible for."
- **Ch12 → Ch13:** Ethics/governance → GenAI. Good framing: ethics applies at least as much to LLMs.
- **Ch13 → Ch14:** **BROKEN** — Ch14 does not exist (see Issue Ch13-1 above).

---

## 5. Duplicate Content Analysis

### 5a. Expected overlap (not a problem)

Several topics appear across multiple chapters by design:

- **CAC/PIV authentication** — Covered in Ch01 (introductory), Ch02 (code-level), Ch03 (CAC in API calls), and the platform guides. The coverage is appropriately additive: each chapter adds a new dimension rather than repeating the same content.
- **Bronze/Silver/Gold data tiers** — Referenced in Ch01, Ch02, Ch03, Ch04, Ch05, and the Navy Jupiter guide. The tier concept is fundamental enough that repeated reminders are justified.
- **Collibra data catalog** — Ch01 introduces it, Ch02 references checking it before writing code, Ch03 covers it in depth, Ch05 references it. Appropriate progressive coverage.
- **DD Form 2875** — Mentioned in Ch01, Ch02, Ch03, and the platform guides. Each mention adds context (Ch01 introduces it, Ch02 references it for service accounts, Ch03 explains it in the access workflow).

### 5b. Substantive duplication issues

**Issue DUP-1 (MODERATE):** Ch03 (Data Acquisition) and Ch04 (Data Wrangling) both cover the mechanics of reading malformed government file formats. Ch03's section "Working with Messy Government File Formats" (pipe-delimited CSVs, FOIA PDFs, fixed-width files) and Ch04's "Pandas: The First Line of Defense" section (null handling in government CSVs, deduplication, type coercion) cover overlapping ground. The distinction intended is Ch03 = "getting the data in" vs Ch04 = "cleaning once it's in," but the defensive CSV read pattern with `encoding="latin-1"`, `na_values`, and `dtype=str` appears in both. This is navigable but worth noting — a reader doing both chapters sequentially will encounter the same file-reading caveats twice.

**Issue DUP-2 (LOW):** The five-platform comparison table appears in both Ch01 (as the "Platform Comparison" section) and in Ch02 (as a condensed version). The Ch02 version focuses on Python environment specifics rather than platform capabilities, so the overlap is partial rather than identical. Low priority, but worth a review to ensure Ch02's table is sufficiently differentiated.

---

## 6. Missing Cross-References (Opportunities)

Beyond Issue XREF-3 listed above, the following cross-references are absent and would strengthen the handbook:

| Location | Missing reference | Rationale |
|---|---|---|
| Ch06 (Supervised ML) | No reference to Ch09 (MLOps) | Ch06 ends at "model is registered"; Ch09 is the required follow-on for production. The connection should be explicit in Ch06's close. |
| Ch09 (MLOps) | No reference to Ch12 (Ethics/Governance) | MLOps audit trails and model cards are also governance artifacts. Ch09 discusses ATO reviewers but never sends readers to Ch12's model card framework. |
| Ch09 (MLOps) | No reference to Ch11 (Deployment) | MLOps and deployment are treated as separate chapters but are tightly coupled. Ch09 references Databricks Model Serving but Ch11 covers it in depth. A mutual forward/back reference would help. |
| Ch10 (Visualization) | No reference to Ch06 (Supervised ML) or Ch09 (MLOps) | The SHAP visualization pattern and model monitoring dashboards covered in Ch10 depend on ML outputs from Ch06/Ch09. No explicit link exists. |
| Ch11 (Deployment) | No reference to Ch09 (MLOps) | Ch11 covers deploying models; Ch09 covers monitoring them post-deployment. These are sequential operational concerns with no cross-link. |
| Ch13 (GenAI) | No reference to Ch03 (Data Acquisition) | RAG pipeline chunking and document ingestion in Ch13 is a specialized form of data acquisition. Ch03's classification handling and catalog practices apply directly to RAG data sources. |

---

## 7. Platform Guide: Sequential Flow

The five platform guides are standalone references, not a sequential tutorial. However, each includes a "What comes next" section that implies a reading order:

| Guide | What it says comes next | That guide exists? | Status |
|---|---|---|---|
| Advana | "The next guide covers Databricks as a standalone Federal analytics environment" | Databricks guide exists | PASS |
| Databricks | "The next chapter covers how Unity Catalog integrates with agency identity providers — specifically DoD's CAC/PIV authentication infrastructure" | **No such guide exists** | **ISSUE** |
| Navy Jupiter | "The Advana platform guide covers the DoD-wide data sources…" | Advana guide exists | PASS |
| Palantir | "The next section covers Workshop application design…" | **No Workshop section/guide exists** | **ISSUE** |
| Qlik | "The next guide covers how [Qlik and Databricks] work together in government environments" | **No Qlik+Databricks integration guide exists** | **ISSUE** |

**Issue PG-1 (BROKEN REFERENCE):** The Databricks platform guide's "What comes next" (line 544) references a chapter covering Unity Catalog + CAC/PIV identity provider integration. No such guide exists in the repository.

**Issue PG-2 (BROKEN REFERENCE):** The Palantir platform guide's "What comes next" (line 480) references a "next section" on Workshop application design. No Workshop section or separate Workshop guide exists.

**Issue PG-3 (BROKEN REFERENCE):** The Qlik platform guide's "What comes next" (line 625) references a guide on Qlik + Databricks integration in government. No such guide exists.

---

## 8. Character Name Consistency Issues

The handbook uses composite characters across chapters. Several inconsistencies were found:

**Issue CHAR-1 (MODERATE):** The character "Priya" appears across Ch02, Ch03, Ch04, and Ch05 but with different last names:
- Ch02: "Priya" (no last name given)
- Ch03: "Priya" (no last name given)
- Ch04: **"Priya Menon"**
- Ch05: **"Priya Sharma"**

These are explicitly noted as composite characters, so different surnames technically don't contradict the disclaimers. However, the inconsistency may confuse readers who follow Priya's arc across chapters 2–5 and suddenly see a different surname. Recommend standardizing to one name or ensuring both Ch04 and Ch05 include the composite-character disclaimer that Ch05 has but Ch04 does not.

**Issue CHAR-2 (LOW):** "Sarah Okafor" appears in three contexts with different ranks/roles:
- Navy Jupiter platform guide: "Commander Sarah Okafor"
- Ch12 (Ethics): "Dr. Sarah Okafor"
- Ch13 (GenAI): "Lieutenant Colonel Sarah Okafor"

These are clearly different characters using the same name — the composite character pattern is applied consistently with disclaimers. However, reusing the surname "Okafor" across three separate characters (plus "Kevin Okafor" in Ch08, "Danielle Okafor" in Ch10) creates a named family that may or may not be intentional. If unintentional, one of the secondary characters should receive a different surname.

---

## 9. Complete Issue Index

| ID | Severity | Location | Description |
|---|---|---|---|
| Ch13-1 | HIGH | Ch13 "What comes next" | References "Chapter 14" which does not exist |
| CODE-1 | HIGH | Ch03, Ch04, Ch05, Ch07, Ch08, Ch09, Ch13 | `code-examples/python/` directory is empty; 15 referenced .py files are missing |
| PG-1 | MEDIUM | Databricks platform guide "What comes next" | References a Unity Catalog + CAC/PIV guide that does not exist |
| PG-2 | MEDIUM | Palantir platform guide "What comes next" | References a Workshop section/guide that does not exist |
| PG-3 | MEDIUM | Qlik platform guide "What comes next" | References a Qlik+Databricks integration guide that does not exist |
| XREF-1 | LOW | Ch09 "What comes next" | References "Kevin's vehicle detection model" — Kevin does not appear in Ch09's body; minor narrative discontinuity |
| XREF-2 | LOW | Ch05, line 178 | "Qlik SSE pattern from Chapter 01" — Ch01 mentions SSE conceptually but has no pattern; Qlik platform guide or Ch10 is the right reference |
| XREF-3 | LOW | Ch06 Chapter Close | No forward reference to Ch09 (MLOps) for production monitoring of models trained in Ch06 |
| DUP-1 | LOW | Ch03 and Ch04 | Both cover defensive CSV reading patterns for government file formats; partial duplication |
| DUP-2 | LOW | Ch01 and Ch02 | Both contain five-platform comparison tables; Ch02's is differentiated (Python-specific) but overlap is visible |
| CHAR-1 | LOW | Ch04 and Ch05 | "Priya" given different last names: Menon (Ch04) vs Sharma (Ch05); Ch04 lacks composite-character disclaimer |
| CHAR-2 | INFO | Ch08, Ch10, Ch12, Ch13, Navy Jupiter guide | Surname "Okafor" shared across five different characters (Kevin, Danielle, Dr. Sarah, Lt. Col. Sarah, Commander Sarah) — may be intentional family; clarify intent |

---

## 10. Recommended Actions (Priority Order)

1. **Create or remove Ch14 reference (Ch13-1).** Either create a `chapters/14-capstone/` directory with a capstone chapter, or revise Ch13's chapter close to end the series at Ch13 without referencing a chapter that doesn't exist.

2. **Create code-examples/python/ files or revise references (CODE-1).** Either populate the `code-examples/python/` directory with the 15 referenced .py files, or revise in-prose references to use inline code blocks. The current state creates a misleading impression of complete examples that don't exist.

3. **Revise platform guide "What comes next" sections (PG-1, PG-2, PG-3).** Either create the referenced guides/sections or revise the closing text to accurately describe what is available.

4. **Standardize Priya's last name across Ch04 and Ch05 (CHAR-1).** Pick one (Menon or Sharma) and apply consistently. Also add the composite-character disclaimer to Ch04 if it is missing.

5. **Add Ch06 → Ch09 cross-reference (XREF-3).** Ch06 builds models; Ch09 operates them. A forward reference in Ch06's close would close the most significant missing link in the narrative arc.

6. **Clarify Okafor family structure (CHAR-2).** If the five "Okafor" characters are intentionally members of a family appearing across the handbook, add a note to that effect. If not, rename at least two of the secondary characters.

---

*Report end. All 13 chapter READMEs and 5 platform guide READMEs were reviewed. No chapter was skipped.*
