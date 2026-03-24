# Data Science Learning Handbook — Implementation Plan

**Created:** 2026-03-23
**Status:** IN PROGRESS
**Orchestrator:** Claude Opus (main session)
**Default Agent Model:** Sonnet (Opus reserved for heavy planning/review)

---

## Project Vision

A standalone, publishable-quality educational resource teaching data science practitioners how to build solutions on 5 federal government platforms:

1. **Advana** (DoD Enterprise Data Analytics)
2. **Qlik** (Business Intelligence)
3. **Databricks** (Unified Analytics)
4. **Navy Jupiter** (Department of Navy)
5. **Palantir AIP/Foundry** (NEW — added 2026-03-23)

13 chapters + platform guides + infrastructure. Content must NOT sound AI-generated. Matches author's practitioner voice from "Shrink-Wrap It."

---

## Current State (Pre-Execution Snapshot)

| Task | Status | Subtask Completion |
|---|---|---|
| 1. Project Setup & Infrastructure | DONE | 8/8 (100%) |
| 2. Multi-Platform Auth & Security | IN PROGRESS | 25/36 (69%) |
| 3. Platform Integration APIs | PENDING | 0/20 (0%) |
| 4. Core Data Pipeline/ETL | PENDING | 0/11 (0%) |
| 5. Content Management & Templates | DONE | 8/8 (100%) |
| 6. Interactive Code Examples | PENDING | 0/9 (0%) |
| 7. MLOps & Model Lifecycle | PENDING | 0/11 (0%) |
| 8. Advanced Analytics/AI | PENDING | 0/12 (0%) |
| 9. Visualization & Dashboards | PENDING | 0/9 (0%) |
| 10. Deployment & Monitoring | PENDING | 0/11 (0%) |
| **13 Chapters of Content** | NOT TRACKED | 0% |
| **Palantir AIP/Foundry** | NOT TRACKED | 0% |
| **PRD** | MISSING | — |

---

## Phase A: Foundation (Hours 0-2)

### Tasks

| # | Task | Agent | Model | Status |
|---|---|---|---|---|
| A1 | Research AI writing anti-patterns + analyze author voice → Style Guide | subagent | Sonnet | PENDING |
| A2a | Research Advana platform (2025-2026 landscape) | subagent | Sonnet | PENDING |
| A2b | Research Qlik platform (2025-2026 landscape) | subagent | Sonnet | PENDING |
| A2c | Research Databricks platform (2025-2026 landscape) | subagent | Sonnet | PENDING |
| A2d | Research Navy Jupiter platform (2025-2026 landscape) | subagent | Sonnet | PENDING |
| A2e | Research Palantir AIP/Foundry (2025-2026 landscape) | subagent | Sonnet | PENDING |
| A3 | Create comprehensive PRD (after A1 + A2 complete) | subagent | Opus | PENDING |
| A4 | Update tasks.json with chapters + Palantir tasks | subagent | Sonnet | PENDING |

### QA Gate A: Foundation Review

**Trigger:** All A-tasks report complete
**Agent:** Opus (this requires judgment)
**Checklist:**

- [ ] Style guide exists and contains: anti-patterns list, voice characteristics, formatting standards, example passages
- [ ] All 5 platform research reports exist with current (2025-2026) information
- [ ] PRD covers all 13 chapters, 5 platforms, infrastructure tasks, and acceptance criteria
- [ ] tasks.json updated with new tasks and correct dependencies
- [ ] No contradictions between PRD, style guide, and existing repo content

**Actions on failure:**
- Missing/thin research → re-run specific platform research agent with more targeted queries
- Style guide incomplete → extend with additional book analysis
- PRD gaps → patch PRD with missing sections
- Update this plan doc with findings before proceeding

**QA Gate A Results:** _(to be filled during execution)_

---

## Phase B: Infrastructure Completion (Hours 2-8)

### Tasks

| # | Task | Agent | Model | Status |
|---|---|---|---|---|
| B1 | Complete Task 2: remaining 11 security subtasks | subagent | Sonnet | PENDING |
| B2 | Task 3: Platform Integration APIs (incl. Palantir AIP/Foundry) | subagent | Sonnet | PENDING |
| B3 | Task 4: Core Data Pipeline/ETL | subagent | Sonnet | PENDING |
| B4 | Task 6: Interactive Code Examples framework | subagent | Sonnet | PENDING |
| B5 | Task 7: MLOps & Model Lifecycle | subagent | Sonnet | PENDING |
| B6 | Add Palantir platform guide structure + integration config | subagent | Sonnet | PENDING |

### QA Gate B: Infrastructure Review

**Trigger:** All B-tasks report complete
**Agent:** Sonnet (code review focused)
**Checklist:**

- [ ] Task 2 (Security): All 36 subtasks marked done, code files exist and are non-trivial
- [ ] Task 3 (APIs): All 20 subtasks done, Palantir AIP/Foundry API client exists
- [ ] Task 4 (ETL): All 11 subtasks done, pipeline code functional
- [ ] Task 6 (Code Examples): Framework exists, at least one working example per platform
- [ ] Task 7 (MLOps): All 11 subtasks done, MLflow integration functional
- [ ] Palantir platform directory structure matches other 4 platforms
- [ ] No broken imports or missing dependencies in requirements.txt
- [ ] Docker compose still builds (if modified)

**Gap Analysis Procedure:**
1. Run `find` on each task directory to verify files exist
2. Check Python files for syntax errors (`python3 -m py_compile`)
3. Verify each new module has at least basic structure (classes, functions, docstrings)
4. Cross-reference subtask list against actual files created
5. Flag any subtask marked "done" with no corresponding file changes

**Actions on failure:**
- Missing files → re-run specific subtask agent
- Broken code → fix agent with targeted error context
- Incomplete Palantir integration → extend B6 with gap details
- Update this plan doc with findings

**QA Gate B Results:** _(to be filled during execution)_

---

## Phase C: Chapter Content Creation (Hours 2-18)

### Batch 1: Foundational Chapters (Hours 2-8)

| Chapter | Title | Agent | Model | Status |
|---|---|---|---|---|
| 01 | Introduction to Data Science in Government | subagent | Sonnet | PENDING |
| 02 | Python & R Foundations | subagent | Sonnet | PENDING |
| 03 | Data Acquisition & Wrangling | subagent | Sonnet | PENDING |
| 04 | Data Wrangling & Cleaning | subagent | Sonnet | PENDING |

#### QA Gate C1: Batch 1 Review

**Trigger:** All 4 chapters report complete
**Agent:** Opus (quality + voice judgment)
**Checklist:**

- [ ] Each chapter has README.md with substantive content (>2000 words)
- [ ] Content does NOT contain AI anti-patterns (check against style guide)
- [ ] Voice matches author's practitioner style (narrative, direct, operational)
- [ ] Each chapter has working code examples (Python at minimum)
- [ ] Each chapter covers all 5 platforms where applicable
- [ ] Mermaid diagrams present where appropriate
- [ ] Exercises directory exists with hands-on problems
- [ ] No placeholder text ("TODO", "TBD", "lorem ipsum", "[insert X]")
- [ ] Cross-references to other chapters use correct paths
- [ ] Technical accuracy spot-check (pick 3 claims per chapter, verify)

**Drift Detection:**
- Compare chapter scope against PRD chapter descriptions
- Flag any chapter that drifted into adjacent chapter's territory
- Check for redundant content across chapters

**Actions on failure:**
- AI voice detected → rewrite flagged sections with explicit anti-pattern guidance
- Missing platform coverage → targeted platform-specific additions
- Thin content (<1500 words) → expand with more examples/narrative
- Technical inaccuracies → correct with sourced information
- Update this plan doc with findings, adjust Batch 2 guidance based on learnings

**QA Gate C1 Results:** _(to be filled during execution)_

---

### Batch 2: Core ML Chapters (Hours 8-14)

| Chapter | Title | Agent | Model | Status |
|---|---|---|---|---|
| 05 | Exploratory Data Analysis | subagent | Sonnet | PENDING |
| 06 | Supervised Machine Learning | subagent | Sonnet | PENDING |
| 07 | Unsupervised Machine Learning | subagent | Sonnet | PENDING |
| 08 | Deep Learning & Neural Networks | subagent | Sonnet | PENDING |

#### QA Gate C2: Batch 2 Review

**Trigger:** All 4 chapters report complete
**Agent:** Opus (quality + voice + technical accuracy)
**Checklist:**

- [ ] Same quality checklist as QA Gate C1 (all items)
- [ ] ML chapters include realistic government/defense use cases (not generic Iris/Titanic datasets)
- [ ] Code examples use platform-specific APIs (not just generic scikit-learn)
- [ ] Algorithms explained with practitioner framing ("when to use X vs Y on your DoD project")
- [ ] Batch 2 incorporates lessons learned from QA Gate C1

**Actions on failure:** Same as C1, plus apply any C1 learnings that were missed

**QA Gate C2 Results:** _(to be filled during execution)_

---

### Batch 3: Advanced & Operations Chapters (Hours 14-20)

| Chapter | Title | Agent | Model | Status |
|---|---|---|---|---|
| 09 | MLOps & Production Pipelines | subagent | Sonnet | PENDING |
| 10 | Visualization & Dashboards | subagent | Sonnet | PENDING |
| 11 | Deployment & Scaling | subagent | Sonnet | PENDING |
| 12 | Ethics, Governance & Compliance | subagent | Sonnet | PENDING |
| 13 | Advanced Topics (GenAI, RAG, LLMs on Federal Platforms) | subagent | Sonnet | PENDING |

#### QA Gate C3: Batch 3 Review

**Trigger:** All 5 chapters report complete
**Agent:** Opus (quality + voice + technical accuracy)
**Checklist:**

- [ ] Same quality checklist as QA Gate C1 (all items)
- [ ] Chapter 09 (MLOps) aligns with infrastructure built in Phase B Task 7
- [ ] Chapter 10 (Viz) references actual dashboard frameworks from Phase B Task 9
- [ ] Chapter 11 (Deployment) aligns with Docker/deployment infra in repo
- [ ] Chapter 12 (Ethics) covers DoD-specific compliance (8570, 800-53, FedRAMP)
- [ ] Chapter 13 (Advanced) covers Palantir AIP, RAG at IL5, current GenAI landscape
- [ ] Batch 3 incorporates lessons from QA Gates C1 and C2
- [ ] No orphaned cross-references to chapters not yet written

**Actions on failure:** Same as previous batches

**QA Gate C3 Results:** _(to be filled during execution)_

---

## Phase D: Platform Guides & Remaining Tasks (Hours 14-20)

### Tasks

| # | Task | Agent | Model | Status |
|---|---|---|---|---|
| D1 | Advana platform guide — complete content | subagent | Sonnet | PENDING |
| D2 | Qlik platform guide — complete content | subagent | Sonnet | PENDING |
| D3 | Databricks platform guide — complete content | subagent | Sonnet | PENDING |
| D4 | Navy Jupiter platform guide — complete content | subagent | Sonnet | PENDING |
| D5 | Palantir AIP/Foundry platform guide — NEW | subagent | Sonnet | PENDING |
| D6 | Task 8: Advanced Analytics/AI framework code | subagent | Sonnet | PENDING |
| D7 | Task 9: Visualization & Dashboard framework code | subagent | Sonnet | PENDING |
| D8 | Task 10: Deployment & Monitoring framework code | subagent | Sonnet | PENDING |

### QA Gate D: Platform & Framework Review

**Trigger:** All D-tasks report complete
**Agent:** Sonnet (cross-platform consistency check)
**Checklist:**

- [ ] All 5 platform guides follow consistent structure (setup, auth, data access, analytics, deployment)
- [ ] Each platform guide has working code examples
- [ ] Palantir guide covers: AIP overview, Foundry data integration, Ontology, Pipeline Builder, AIP Logic/Functions
- [ ] Platform guides reference chapter content correctly
- [ ] Task 8 (Analytics): All 12 subtasks done
- [ ] Task 9 (Viz): All 9 subtasks done
- [ ] Task 10 (Deployment): All 11 subtasks done
- [ ] Cross-platform comparison table exists showing feature parity

**Gap Analysis Procedure:**
1. Compare platform guide structures side-by-side
2. Identify any platform missing a section that others have
3. Verify code examples use each platform's actual API conventions
4. Check that platform-specific compliance requirements are documented

**Actions on failure:**
- Structural inconsistency → standardize against the best guide
- Missing Palantir sections → extend with additional research
- Update this plan doc with findings

**QA Gate D Results:** _(to be filled during execution)_

---

## Phase E: Integration, Polish & Final QA (Hours 20-24)

### Tasks

| # | Task | Agent | Model | Status |
|---|---|---|---|---|
| E1 | Cross-reference all chapters (links, dependencies, forward/back refs) | subagent | Sonnet | PENDING |
| E2 | Run validation frameworks on all content | subagent | Sonnet | PENDING |
| E3 | Update README with complete project dashboard | subagent | Sonnet | PENDING |
| E4 | Update CLAUDE.md with new scope/tasks | subagent | Sonnet | PENDING |
| E5 | Create final PRD reflecting completed state | subagent | Sonnet | PENDING |
| E6 | Voice/style consistency review across ALL chapters | subagent | Opus | PENDING |
| E7 | Final commit organization and project status | subagent | Sonnet | PENDING |

### QA Gate E: Final Comprehensive Review

**Trigger:** All E-tasks report complete
**Agent:** Opus (final sign-off)
**Checklist:**

**Content Completeness:**
- [ ] All 13 chapters exist with >2000 words each
- [ ] All 5 platform guides exist with consistent structure
- [ ] All code examples directory populated
- [ ] All exercises directories populated
- [ ] No placeholder/stub content remains anywhere

**Quality Standards:**
- [ ] Zero AI anti-pattern violations across all content
- [ ] Voice consistency score: author's practitioner style maintained throughout
- [ ] Technical accuracy verified (spot-check 2 claims per chapter)
- [ ] Mermaid diagrams render correctly

**Infrastructure Completeness:**
- [ ] All 10 Task Master tasks marked DONE with all subtasks
- [ ] requirements.txt reflects all dependencies used in code examples
- [ ] Docker compose builds without errors (if modified)
- [ ] CI/CD pipeline config is valid YAML

**Documentation:**
- [ ] README reflects actual project state
- [ ] CLAUDE.md updated for new scope
- [ ] PRD reflects completed deliverables
- [ ] This plan document fully updated with all QA gate results

**Cross-Cutting Concerns:**
- [ ] No broken internal links between chapters
- [ ] No references to classified/sensitive information
- [ ] All external links point to real, accessible resources
- [ ] Consistent formatting across all markdown files

**Final Gap Analysis:**
1. Generate file inventory: every expected file vs actual files
2. Word count per chapter: flag any under 1500 or over 8000
3. Platform coverage matrix: which chapters cover which platforms
4. Code language coverage: Python required, R optional but preferred

**Actions on failure:**
- Critical gaps → targeted fix agents
- Minor issues → document for follow-up
- Update this plan doc with final status

**QA Gate E Results:** _(to be filled during execution)_

---

## Monitoring: /loop Configuration

**Interval:** Every 10 minutes
**Monitor checks:**
1. Agent completion status (which agents are done, which are running)
2. Task Master progress (subtask completion counts)
3. File creation progress (new files since last check)
4. Error detection (any agent failures or blocked work)
5. Phase gate readiness (is current phase complete enough to trigger QA?)

**Escalation rules:**
- Agent idle >20 min with no output → investigate and restart
- Same error 3 times → ask user via AskUserQuestion
- Phase QA fails same item twice → escalate to Opus for root cause

---

## Autoresearch Methodology (Applied from Karpathy's autoresearch)

Key patterns adopted from Andrej Karpathy's autonomous research framework:

1. **Immutable evaluation harness**: `STYLE_GUIDE.md` + `CHAPTER_WRITING_SPEC.md` are the fixed quality bars. Agents cannot modify them. Quality is judged against these docs, preventing reward hacking.
2. **Anti-pause instruction**: Chapter agents are explicitly told NEVER to stop and ask. They produce complete chapters autonomously.
3. **Keep/discard via git**: Good chapters get committed. Failed QA = fix and retry, don't advance.
4. **Fixed scope per agent**: Each agent gets exactly one chapter or one platform guide. No scope creep.
5. **Single scalar quality check**: Each QA gate has a binary pass/fail against the checklist.
6. **Nudge watcher**: The /loop monitor detects idle agents and restarts work every 10 minutes.
7. **Results tracking**: `IMPLEMENTATION_PLAN.md` execution log serves as the experiment ledger.
8. **Simplicity criterion**: Prefer clear, direct content over bloated text. Removing unnecessary content while maintaining quality is a win.

### Key Files (Autoresearch-Inspired)
- `docs/CHAPTER_WRITING_SPEC.md` — The "program.md" equivalent for chapter writers (immutable)
- `docs/STYLE_GUIDE.md` — The "prepare.py" equivalent (immutable quality harness)
- `docs/IMPLEMENTATION_PLAN.md` — The "results.tsv" equivalent (experiment ledger)

---

## Execution Log

_(Updated as phases complete)_

| Timestamp | Event | Details |
|---|---|---|
| 2026-03-23 ~T00 | Plan created | Full implementation plan with QA gates |
| 2026-03-23 ~T01 | Phase A launched | 5 agents: style guide, Palantir research, Advana/Jupiter, Databricks/Qlik, autoresearch exploration |
| 2026-03-23 ~T02 | Autoresearch explorer complete | Methodology captured and applied to plan |
| 2026-03-23 ~T02 | Chapter Writing Spec created | `docs/CHAPTER_WRITING_SPEC.md` — immutable agent instruction set |
| 2026-03-23 ~T03 | Style Guide complete | 401-line guide with voice analysis + AI anti-patterns |
| 2026-03-23 ~T03 | Databricks research complete | 390 lines, comprehensive gov platform analysis |
| 2026-03-23 ~T03 | Additional agents launched | Code auditor + PRD creator running parallel with research |
| 2026-03-23 ~T04 | Monitor check #1 | 4/9 Phase A deliverables done. 5 agents active. No stuck agents. |
| 2026-03-23 ~T05 | All platform research complete | Palantir (667L), Advana (250L), Navy Jupiter (285L), Databricks (390L), Qlik (421L) |
| 2026-03-23 ~T06 | Code Audit complete | 267 lines. Key finding: 249K lines of real Python code, not stubs. |
| 2026-03-23 ~T06 | PRD complete | 1,397 lines. Comprehensive PRD at .taskmaster/docs/prd.txt |
| 2026-03-23 ~T06 | **QA GATE A: PASS** | All 10 deliverables verified. Style guide, research, PRD, code audit all pass. |
| 2026-03-23 ~T07 | Agent team created | `handbook-builders` team with orchestrator lead |
| 2026-03-23 ~T07 | Phase C1 launched | 4 chapter writer teammates spawned (Ch 01-04, Sonnet, agent team) |
| 2026-03-23 ~T08 | Monitor check #2 | Teammates reading research docs. 0/4 chapters started yet. Normal — reading phase. |
| 2026-03-24 ~T09 | Ch01 complete | 5,127 words, 0 banned words, all files. chapter-01-writer reassigned to Ch05. |
| 2026-03-24 ~T09 | Ch02 complete | 4,908 words, 0 banned words, all 6 files. chapter-02-writer reassigned to Ch06. |
| 2026-03-24 ~T10 | Ch03 complete | 5,614 words, 0 banned words, all 6 files. chapter-03-writer reassigned to Ch07. |
| 2026-03-24 ~T10 | Monitor check #3 | 3/13 chapters complete. 21 new files. Ch04 nearly done. Ch05 writer stuck — spawned fresh chapter-05-writer. |
| 2026-03-24 ~T10 | Tasks 9-13 created | All 13 chapter tasks now in shared task list. |
| 2026-03-24 ~T11 | Ch04 complete | 5,174 words, all 6 files. Batch 1 (Ch1-4) fully complete. |
| 2026-03-24 ~T12 | Monitor check #4 | 4/13 done. Ch05-07 READMEs written. Ch08 starting. 10 new files. |
| 2026-03-24 ~T13 | Ch06 complete | 4,371 words, all 6 files. chapter-02-writer → Ch12. |
| 2026-03-24 ~T13 | Ch08 complete | 4,324 words, 7 files (4 py). chapter-04-writer → Ch13 (final chapter). |
| 2026-03-24 ~T14 | Monitor check #5 | 8/13 done. Ch09-11 finishing. Ch12 starting. 25 new files. |
| 2026-03-24 ~T15 | Ch09, Ch10, Ch11 complete | All confirmed with full files. 11/13 done. |
| 2026-03-24 ~T15 | Commits pushed | 4 commits: Ch01-04, Ch05-08, Ch09-13, docs update. All pushed to origin. |
| 2026-03-24 ~T15 | Idle writers shut down | ch01-writer, ch03-writer, ch09-writer shut down. |
| 2026-03-24 ~T16 | Ch13 writer spawned | Fresh chapter-13-writer for capstone GenAI/RAG chapter. |
| 2026-03-24 ~T17 | Monitor check #6 | 11/13 done. Ch12 and Ch13 in progress. 21 new files. |
| 2026-03-24 ~T18 | Ch12 complete | 5,722 words, 3 py, exercises + solutions. DoD AI Ethics, NIST AI RMF, bias audit. |
| 2026-03-24 ~T18 | 12/13 chapters done | Only Ch13 (GenAI/RAG/LLMs) remains. README 4,922w + 1 py written. |
| 2026-03-24 ~T18 | Writers shut down | ch01, ch02, ch04, ch05 shut down. Only ch13-writer + commit-agent active. |
| 2026-03-24 ~T19 | Monitor check #7 | 12/13 done. Ch13 has README+3py+exercises. Only solutions.md remaining. |
| 2026-03-24 ~T20 | **CH13 COMPLETE** | 4,923 words, 3 py, exercises + solutions. GenAI/RAG/LLMs capstone. |
| 2026-03-24 ~T20 | **ALL 13 CHAPTERS PASS QA** | 67,826 total words, 41 Python files, 13/13 exercise sets. Zero banned words. |
| 2026-03-24 ~T20 | Final commit + push | `82ed711` feat(chapters): Complete all 13 handbook chapters |
| 2026-03-24 ~T20 | Team shutdown | All writers + commit-agent shut down. Phase C COMPLETE. |
| | | |

---

## Risk Register

| Risk | Mitigation |
|---|---|
| Content sounds AI-generated | Style guide created first; Opus voice review at end |
| Palantir info limited (classified) | Focus on publicly documented AIP/Foundry features only |
| Chapter drift / scope creep | QA gates check chapter boundaries against PRD |
| Infrastructure breaks during chapter writing | Phases B and C run in parallel but on different files |
| Agent context overflow on large chapters | Break chapters into sections, reassemble |
| /loop session timeout | User keeps terminal open; plan doc serves as recovery point |
| Stale research (8-month gap) | All platform research refreshed in Phase A |
