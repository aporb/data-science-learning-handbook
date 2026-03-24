# Top-Level Code Examples

This directory is intentionally minimal. It serves as a home for
**cross-chapter** or **standalone** code examples that do not belong to any
single chapter.

Chapter-specific code lives in `chapters/<chapter-name>/code-examples/`.

---

## What belongs here vs. in chapters/

| Use case | Location |
|----------|----------|
| Code that directly supports a specific chapter | `chapters/<N>/code-examples/python/` |
| Utility helpers used by multiple chapters | `code-examples/utils/` |
| End-to-end pipeline demos spanning chapters | `code-examples/pipelines/` |
| Standalone scripts referenced from docs | `code-examples/` |

---

## Current Contents

This directory currently contains only this README. Cross-chapter code examples
will be added here as the handbook content matures.

---

## Adding Examples

When adding a cross-chapter example:

1. Create a descriptive subdirectory: `code-examples/<topic>/`
2. Include a `README.md` explaining what the example demonstrates and which
   chapters it relates to
3. Follow the naming convention used in chapter code examples:
   `01_topic_name.py`, `02_next_topic.py`, etc.
4. Reference the example from the relevant chapter READMEs

---

## Relationship to chapter code-examples

All chapter directories contain their own `code-examples/python/` and
`code-examples/r/` subdirectories. See any chapter README for the local
structure, e.g.:

```
chapters/
  06-supervised-ml/
    code-examples/
      python/
        01_linear_regression.py
        02_decision_trees.py
        03_model_evaluation.py
      r/
        (R examples — contributions welcome)
```
