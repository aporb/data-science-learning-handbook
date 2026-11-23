# Federal Data Science Handbook — Cline Rules

This is a completed reference handbook (96K+ words, 43 Python examples, 13 chapters, 5 platform guides). Preserve the teaching structure. Allow sourced accuracy corrections, safety fixes, and tested example repairs. Mirror prose changes to the companion site.

Read `CLAUDE.md` for the full content map. Read `AGENTS.md` for agent workflows.

## Code Generation Rules

1. Always read `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` before generating platform-specific code
2. Every generated file must include the docstring header: Title, Description, `Platform:`, `Usage:`
3. Platform constraints:
   - Databricks: No pip install in cells. Use cluster libraries. Use dbutils.secrets.
   - Foundry: Use palantir_models for publishing. No direct file I/O.
   - Advana/Jupiter: JupyterHub shared cluster. No sudo. Conda environments.
4. Security code must reference patterns in `security-compliance/` — do not invent compliance patterns
5. Use only endpoints approved for the exact data, offering, region or network, and system authorization. Reject unauthorized public endpoints. Self-hosting alone does not authorize a model.
6. Never hardcode tokens, passwords, or credentials

## Sensitivity Rules

- Never send nonpublic government data to an unapproved endpoint.
- Use only approved embedding and inference services within the system boundary.
- Use the chapter 13 deployment checklist and obtain program confirmation. The handbook does not authorize a model.

## Available Workflows

- `/compliance-check.md` — Review code against federal compliance rules
- `/generate-federal-code.md` — Generate platform-appropriate Python
- `/teach.md` — Interactive tutor walking through handbook content
