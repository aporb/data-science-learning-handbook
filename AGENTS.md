# Agent Guide — Federal Data Science Handbook

## What This Repo Is

A completed reference handbook for data science on five federal government platforms (Advana, Databricks, Navy Jupiter, Palantir AIP/Foundry, Qlik). 13 chapters, 43 Python code examples, 5 platform guides, and a reference security implementation covering CAC/PIV auth, RBAC, encryption, and compliance.

This is not a project to build or deploy. It is a knowledge base. Use it to answer questions, generate compliant code, and teach federal data science concepts.

## For Any AI Agent: How To Approach This Repo

### Orientation (read first)
1. `CLAUDE.md` — root context with content map and usage modes
2. `README.md` — human-readable overview and table of contents
3. This file — agent workflows and suggested prompts

### Answering "How do I do X on [platform]?"
1. Check the content map in `CLAUDE.md` to find the relevant chapter
2. Read the chapter README: `chapters/NN-name/README.md`
3. Check for matching code examples: `chapters/NN-name/code-examples/python/`
4. If platform-specific: also read `platform-guides/PLATFORM/README.md`

### Answering "Write me code for [task]"
1. Read `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` for the standard platform detection pattern
2. Find the most relevant existing code example as a template (see content map)
3. Apply platform constraints from chapter 02
4. Use the docstring header format: `Platform:` and `Usage:` fields
5. Never hardcode credentials — use env vars or platform secret management

### Answering "Explain [concept]"
1. Map the concept to its chapter (see content map in `CLAUDE.md`)
2. Read the chapter README — it opens with a narrative scene, not a definition
3. Walk through the narrative → conceptual explanation → code example progression
4. Anchor in federal context (clearances, Impact Levels, platform constraints)

## Pre-Built Agent Workflows

### 1. Compliance Checker
Reviews code against federal security and compliance requirements.

**What it reads**: `security-compliance/security-policy.md`, `security-compliance/compliance/`, `chapters/12-ethics-governance/README.md`, `chapters/11-deployment/README.md`

**What it checks**: Data classification handling, auth patterns, encryption, DoD AI Ethics, NIST 800-53 controls, FedRAMP requirements, IL-appropriate data handling

**Output**: Structured findings report with severity, violated standard, and remediation pointing to specific handbook sections

### 2. Federal Code Generator
Generates platform-appropriate Python following handbook patterns.

**What it reads**: `chapters/02-python-r-foundations/` (platform constraints), relevant chapter code examples as templates, `security-compliance/auth/` if auth is involved

**What it enforces**: Correct docstring headers, platform-specific import patterns, no external API calls at IL4+, no hardcoded credentials, self-hosted models for classified environments

**Output**: Python code with handbook-format docstring header, inline comments, and pointers to related handbook sections

### 3. Interactive Tutor
Walks through handbook content using the narrative + code teaching pattern.

**What it reads**: Target chapter README (for narrative and concepts), corresponding code examples (for hands-on demonstrations), chapter exercises (for practice)

**What it does**: Opens with the chapter's narrative hook, presents learning objectives as a checklist, walks through concepts with code, tracks which objectives have been covered

**Output**: Conversational teaching session with pauses for questions and code walkthroughs

## Platform-Specific Setup

### Claude Code
Agent context files are auto-loaded. Pre-built commands available:
- `/compliance-check` — review code for federal compliance
- `/generate-federal-code` — generate platform-appropriate Python
- `/teach` — interactive tutor mode

Commands defined in `.claude/commands/`.

### Cursor
`.cursorrules` is auto-loaded on project open. Contains code generation constraints, platform rules, and sensitivity rules. Agent workflows from this file can be invoked conversationally.

### OpenCode
Configuration at `.opencode/config.yaml`. Defines context files, custom instructions, and workflow definitions mirroring the three agent workflows above.

### Cline
Project rules in `.clinerules/rules.md`. Three workflows available in `.clinerules/workflows/`:
- `/compliance-check.md` — step-by-step compliance review with pause points
- `/generate-federal-code.md` — guided code generation with platform/IL selection prompts
- `/teach.md` — interactive tutor with topic selection and concept-by-concept pacing

Type `/` in chat to see and invoke workflows.

### Other Agents
Any agent that reads Markdown can use this repo. Start with `CLAUDE.md` for the content map and this file for workflow instructions. The key constraint: never modify QA-signed-off content (chapter READMEs, platform guides, exercises).

## Suggested Prompts by Use Case

### Getting Started
- "I'm new to federal data science. Walk me through chapter 1."
- "What are the five platforms and when do I use each one?"
- "How is federal data science different from commercial data science?"

### Environment Setup
- "How do I set up Python on [Databricks/Foundry/Advana]?"
- "What packages are pre-installed on [platform] clusters?"
- "Show me the platform-specific import pattern for [platform]."

### Building Models
- "Generate a classification pipeline for [use case] on Databricks at IL4."
- "How do I track experiments with MLflow on a federal platform?"
- "Show me the anomaly detection pattern from chapter 7."

### Deployment and Compliance
- "Review my code for federal compliance." (→ compliance checker)
- "How does ATO work for deploying an ML model?"
- "What are the DoD AI Ethics requirements for my model?"

### GenAI and LLMs
- "How do I build a RAG pipeline that stays within IL5?"
- "What LLMs are authorized at each Impact Level?"
- "Show me the Palantir AIP Logic integration pattern."

### Cross-Platform
- "Compare Databricks and Palantir for my [use case]."
- "I'm moving from [platform A] to [platform B] — what changes?"
- "Which platform supports [specific capability]?"

## Directory Structure

Agents discover project structure by reading code. Key paths:

- `chapters/01-introduction/` through `chapters/13-advanced-topics/` — each has `README.md`, `code-examples/python/`, `exercises/`
- `platform-guides/advana/`, `platform-guides/databricks/`, `platform-guides/navy-jupiter/`, `platform-guides/palantir-aip-foundry/`, `platform-guides/qlik/` — each has `README.md`, `cac-piv-integration.md`, `config/`, `scripts/`
- `security-compliance/` — 14 modules: `auth/`, `rbac/`, `encryption/`, `compliance/`, `audits/`, `api-gateway/`, `sessions/`, `credential-management/`, `monitoring/`, `multi-classification/`, `penetration-testing/`, `security-testing/`, `backup/`, `tls/`
- `docs/` — `STYLE_GUIDE.md`, `CHAPTER_WRITING_SPEC.md`, `LOCAL_ENVIRONMENT.md`
- `docker/` — 8 Dockerfiles for Jupyter, MLflow, PostgreSQL, Redis, Nginx, Vault, CAC-auth, security

## Cross-Repo Reference

**Companion site**: `../site/` (submodule) → https://aporb.github.io/federal-ds-handbook-site/
- Rendered HTML versions of all chapters and platform guides
- Hand-rolled HTML/CSS/JS — no build step, no framework
- Site has its own `CLAUDE.md` and `AGENTS.md` for agents working on the site

When switching between repos, read the target repo's `CLAUDE.md` first — the two repos have different conventions and constraints.
