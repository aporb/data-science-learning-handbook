# Interactive Handbook Tutor

Walk through Federal Data Science Handbook content interactively with narrative and code.

## Step 1: Identify the topic

<ask_followup_question>
<question>What would you like to learn about?</question>
<options>["Getting started (CAC, platforms, ATO)", "Python/R environment setup", "Data acquisition (USASpending, APIs)", "ML on federal platforms", "MLOps and MLflow", "Deployment and ATO", "Ethics and compliance", "GenAI/RAG/LLMs at IL5", "Pick a specific chapter (1-13)"]</options>
</ask_followup_question>

## Step 2: Map topic to chapter

Use this mapping to find the right chapter:
- CAC, Impact Level, ATO, onboarding → `01-introduction`
- pip, conda, environment, imports → `02-python-r-foundations`
- USASpending, SAM.gov, data access → `03-data-acquisition`
- pandas, PySpark, Delta Lake, wrangling → `04-data-wrangling`
- EDA, profiling → `05-exploratory-analysis`
- Classifier, XGBoost, supervised ML → `06-supervised-ml`
- Anomaly detection, clustering → `07-unsupervised-ml`
- CNN, PyTorch, deep learning → `08-deep-learning`
- MLflow, model registry, MLOps → `09-mlops`
- Qlik, dashboards, visualization → `10-visualization`
- Deployment, containers, ATO → `11-deployment`
- Bias, ethics, NIST RMF → `12-ethics-governance`
- LLM, RAG, GenAI, AIP → `13-advanced-topics`

## Step 3: Load the chapter content

Read the target chapter README and scan the code examples:
- Read `chapters/[NN-name]/README.md` for the full prose content
- Read docstring headers of all files in `chapters/[NN-name]/code-examples/python/`

## Step 4: Open with the narrative hook

The chapter READMEs open with a scene — a real person, a specific place, a problem in progress. Share the opening scene (first ~200 words) to draw the learner in. This is the handbook's storytelling approach — use it.

Then present the "What You'll Build" learning objectives as a checklist for this session.

## Step 5: Teach the first major concept

Explain the first major concept from the chapter. Ground it in federal context — why this matters specifically in DoD/government environments, not just generically.

Then pause and ask:

<ask_followup_question>
<question>Want to see the code for this concept, or should I explain more first?</question>
<options>["Show me the code", "Explain more first", "Skip to next concept"]</options>
</ask_followup_question>

## Step 6: Walk through code (if requested)

When showing code:
1. Show the docstring header first (Platform, Usage)
2. Walk through the code in sections
3. Explain why each design decision makes sense in federal context
4. Highlight security-relevant patterns

## Step 7: Continue through concepts

For each remaining concept in the chapter, repeat the teach → pause → code pattern. Track which learning objectives have been covered.

Between concepts, ask:

<ask_followup_question>
<question>Ready for the next concept, or go deeper on this one?</question>
<options>["Next concept", "Go deeper", "Show related code", "Switch to a different topic"]</options>
</ask_followup_question>

## Step 8: Wrap up

Recap which learning objectives were covered (checklist with checkmarks). Point to exercises in `chapters/[NN-name]/exercises/` for hands-on practice. Suggest related chapters for going deeper.
