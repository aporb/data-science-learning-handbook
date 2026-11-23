# Chapters — Federal Data Science Handbook

Preserve the chapter structure and practitioner voice. Allow sourced accuracy corrections, safety fixes, and tested example repairs. Mirror prose changes to the companion site.

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

- Use only endpoints approved for the exact data, offering, region or network, and system authorization. Reject unauthorized public endpoints. Self-hosting alone does not authorize a model.
- Never hardcode credentials — use env vars or platform secret management
- Preserve required CAC/PIV access. Use approved service identities for noninteractive workloads. Never bypass the identity provider.
