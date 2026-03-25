# Federal Data Science Handbook — Cline Rules

This is a completed reference handbook (96K+ words, 43 Python examples, 13 chapters, 5 platform guides). Content is QA-signed-off and frozen. Do NOT modify chapter READMEs, platform guides, or exercise files.

Read `CLAUDE.md` for the full content map. Read `AGENTS.md` for agent workflows.

## Code Generation Rules

1. Always read `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` before generating platform-specific code
2. Every generated file must include the docstring header: Title, Description, `Platform:`, `Usage:`
3. Platform constraints:
   - Databricks: No pip install in cells. Use cluster libraries. Use dbutils.secrets.
   - Foundry: Use palantir_models for publishing. No direct file I/O.
   - Advana/Jupiter: JupyterHub shared cluster. No sudo. Conda environments.
4. Security code must reference patterns in `security-compliance/` — do not invent compliance patterns
5. At IL4+: no external API calls with data, self-hosted models only
6. Never hardcode tokens, passwords, or credentials

## Sensitivity Rules

- Never suggest sending government data to external APIs
- RAG at IL4+ must use self-hosted embeddings
- Check the LLM authorization matrix in chapter 13 before recommending any model

## Available Workflows

- `/compliance-check.md` — Review code against federal compliance rules
- `/generate-federal-code.md` — Generate platform-appropriate Python
- `/teach.md` — Interactive tutor walking through handbook content
