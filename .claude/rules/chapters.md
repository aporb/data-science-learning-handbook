# Chapters — Federal Data Science Handbook

Content in `chapters/` is QA-signed-off and frozen. Do NOT modify any `README.md` file or any file under `exercises/`.

## When generating code for chapters

1. Read `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` first — it defines the platform detection pattern
2. Every generated file MUST include the docstring header with `Platform:` and `Usage:` fields
3. Check the content map in `chapters/CLAUDE.md` for which code examples exist in each chapter

## Platform constraints by chapter

- Chapters 01-02: Environment setup, platform-specific imports — applies to all 5 platforms
- Chapters 03-04: Data acquisition and wrangling — Advana, Jupiter, Foundry primary
- Chapters 06-07: ML — Databricks and Advana primary platforms
- Chapter 08: Deep learning — Databricks and local Docker
- Chapter 09: MLOps — Databricks and Foundry for MLflow/registries
- Chapter 10: Visualization — Qlik and Advana dashboards
- Chapter 13: GenAI/LLMs — Foundry (AIP Logic) and Databricks

## Security rules

- IL4+: no external API calls with data, self-hosted models only, self-hosted embeddings for RAG
- Never hardcode credentials — use env vars or platform secret management
- CAC/PIV auth required for all federal systems — see `platform-guides/*/cac-piv-integration.md`
