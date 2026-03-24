# Chapter 13 Exercises: GenAI, RAG, and LLMs on Federal Platforms

These exercises build on the patterns in this chapter. They are calibrated for someone who has a working knowledge of Python and has read Chapter 9 (MLOps) and Chapter 12 (Ethics and Governance). Each exercise has a clear deliverable, not just an open-ended "explore" prompt.

---

## Exercise 1: Authorization Audit — Know Before You Build

**Scenario:** Your program office is starting a new data analytics contract at IL4. A colleague has already built a prototype using direct calls to `api.openai.com` and wants to push it to the program environment.

**Your task:** Before anyone writes another line of code, conduct a quick authorization audit.

**Part A: Research (no coding required)**

Answer these four questions in writing (one paragraph each):

1. What is the difference between a FedRAMP Moderate, FedRAMP High, IL4, and IL5 authorization? What kinds of data is each appropriate for?

2. The Palantir FedRAMP High authorization was granted in December 2024 and covers "the entirety of Palantir's product offerings." What specific products does that include? Why does a single authorization covering multiple products matter for program teams?

3. Anthropic joined the Palantir FedStart program in April 2025. What does this mean practically for a team that wants to use Claude at IL5? What infrastructure does it require vs. what a direct Anthropic API call would require?

4. If a program operates at IL5 and wants to use a self-hosted Llama 3.3 model, what steps are generally required to get the model binary approved for use in that environment? (Research ATO processes, STIG compliance, and software supply chain security as they apply to open-weight models.)

**Part B: Risk Assessment**

Write a 200-word risk memo to your program manager explaining why the existing `api.openai.com` prototype cannot be deployed to the IL4 program environment as-is, and what the team's options are. Be specific about the data handling risk, not just "it's against the rules."

**Deliverables:**
- Four written answers (one paragraph each)
- One 200-word risk memo

---

## Exercise 2: Build a Government Document Chunker

**Scenario:** You have received 40 contract modifications from a Navy IDIQ vehicle. Your task is to build a chunker that correctly segments these documents for RAG ingestion.

**Setup:** Use the sample contract text in `02_rag_pipeline.py` as a starting point, or download a sample FAR clause document from acquisition.gov (the full FAR is publicly available at acquisition.gov).

**Part A: Clause-Boundary Chunker**

Extend or modify `chunk_government_contract()` in `02_rag_pipeline.py` to handle these edge cases:

1. A contract that has a preamble section before the first FAR clause number (common in award fee contracts)
2. A DFARS clause (prefix `252.`) appearing before any FAR clause (prefix `52.`)
3. An attached Statement of Work (SOW) that has no FAR clause numbers but is structured with numbered sections

For each edge case, write a test function that passes a sample text and asserts the expected number of chunks and their `section_reference` values.

**Part B: Metadata Quality Check**

Write a function `validate_chunk_metadata(chunks: list[DocumentChunk]) -> dict` that:
- Returns a dict with counts of chunks missing `section_reference`, missing `parent_section`, or with `text` shorter than 50 characters (likely a bad split)
- Prints a warning for any chunk where `section_reference` is "PREAMBLE" and the chunk contains a dollar amount (could indicate a price that wasn't properly attributed to a CLIN)

**Part C: Evaluation**

Chunk a real document (or the synthetic sample from the code file) and calculate:
- Average chunk length in tokens (estimate at 4 chars/token)
- Standard deviation of chunk lengths
- Percentage of chunks below 100 tokens (these are probably bad splits)

A good chunker produces chunks with low standard deviation and less than 5% below 100 tokens. Report your numbers and explain what you would change if they are outside those ranges.

**Deliverables:**
- Modified `chunk_government_contract()` with edge case handling
- `validate_chunk_metadata()` function
- Evaluation output with your three metrics and analysis

---

## Exercise 3: End-to-End RAG Pipeline

**Scenario:** A DoD program office has 15 policy memoranda in PDF format covering AI governance, data handling requirements, and software acquisition procedures. Analysts are spending 45 minutes per week searching these documents manually to answer compliance questions from program managers.

**Your task:** Build a working RAG pipeline that can answer natural-language questions about these policies in under 30 seconds.

**Part A: Document Preparation**

Since you may not have access to real DoD policy documents, create three synthetic policy memoranda covering:
1. AI system authorization requirements (minimum 500 words)
2. CUI handling procedures for data science environments (minimum 500 words)
3. Software development security requirements for federal contractors (minimum 500 words)

Write these as realistic policy documents with numbered paragraphs, effective dates, compliance deadlines, and points of contact.

**Part B: Build the Pipeline**

Using `02_rag_pipeline.py` as your base, implement a complete `GovernmentRAGPipeline` that:
1. Chunks all three policy documents using `chunk_policy_document()`
2. Creates embeddings using `GovernmentEmbeddingModel` (use `all-MiniLM-L6-v2` for speed during development)
3. Stores chunks in a `FAISSVectorStore`
4. Answers the following five test queries:

    - "What is the compliance deadline for LLM endpoint authorization?"
    - "Which organizations must comply with the AI system authorization requirements?"
    - "What are the CUI handling requirements for ML model training data?"
    - "What security review is required before deploying a software system?"
    - "Are there any waiver processes available for the AI authorization requirements?"

**Part C: Evaluate Retrieval Quality**

For each of the five queries, record:
- The top retrieved chunk (source document, section reference, retrieval score)
- Whether the answer in the response can be traced back to a specific chunk (yes/no)
- Any hallucination flags raised by `_check_grounding()`

Build a simple evaluation table:

| Query | Top Chunk Source | Top Score | Answer Grounded? | Hallucination Flags |
|---|---|---|---|---|

**Part D: Improve One Thing**

Look at your evaluation table. Identify the query with the lowest retrieval score or the one where the answer was not grounded. Change one thing — the chunking strategy, the embedding model, the `top_k` parameter, or the prompt — and re-run. Report what you changed and whether it helped.

**Deliverables:**
- Three synthetic policy documents
- Working RAG pipeline code
- Evaluation table for five queries
- Before/after comparison for your improvement

---

## Exercise 4: Human-in-the-Loop Workflow Design

**Scenario:** A GSA contracting office wants to use AI to assist with FOIA request processing. They receive approximately 200 FOIA requests per month. Each request requires reviewing 10-80 documents and deciding which portions to release, redact, or withhold under specific exemptions.

**Part A: Workflow Architecture**

Design a human-in-the-loop workflow for FOIA processing. Your design should include:

1. A decision tree showing which steps are automated, which require human review, and what triggers escalation to a senior records officer
2. A confidence threshold table: for each decision type, what confidence level is required for automation, what confidence level triggers optional review, and what confidence level triggers mandatory human review

Decision types to cover:
- PII detection (name, SSN, phone number, address)
- FOIA exemption classification (Exemptions 1 through 9 under 5 U.S.C. 552)
- Document relevance determination (is this document responsive to the request?)
- Segregability analysis (can responsive information be separated from exempt information?)

**Part B: Implement the Confidence Gates**

Extend `ContractRiskWorkflow` in `03_aip_agents.py` (or build a new `FOIAProcessingWorkflow` class) to implement at least four workflow steps with different confidence thresholds. Include:
- A step that is always automated (e.g., document format detection, page count)
- A step with a confidence gate at 0.85 (automated above, human review below)
- A step that is never automated regardless of confidence (the legal release decision)
- An audit log entry for every step, including whether it was human-reviewed

**Part C: Failure Mode Analysis**

Write a one-page analysis of the three most likely failure modes in your FOIA workflow design. For each failure mode, describe:
- What goes wrong
- What the legal or reputational consequence is
- What safeguard prevents or detects the failure

**Deliverables:**
- Decision tree diagram (Mermaid or drawn)
- Confidence threshold table
- Working workflow class with four steps and audit logging
- One-page failure mode analysis

---

## Exercise 5: Platform Comparison — GenAI Architecture Recommendation

**Scenario:** You are the lead data scientist on a new DoD program. The program will process unclassified acquisition data (CUI) from multiple military services to identify cost overrun patterns and generate quarterly risk reports. The program office has budget to acquire one platform and expects to scale to 50 analyst users within 18 months.

The program has three specific AI requirements:
1. A document Q&A system for analysts to query historical contract data
2. An automated risk scoring pipeline that runs weekly on new contract actions
3. A conversational assistant in the analysts' dashboard for ad-hoc questions

**Your task:** Write a platform recommendation memo (400-600 words) comparing at least three of the five platforms from this handbook (Advana/Databricks, Qlik, Databricks direct, Navy Jupiter, Palantir AIP/Foundry) for this specific use case.

Your memo must:
- Make a clear recommendation (not "it depends" — take a position)
- Support the recommendation with specific capability comparisons tied to the three AI requirements
- Acknowledge the strongest counter-argument and explain why you still recommend your choice
- Address the IL level, authorization status, and timeline to ATO for your recommended platform
- Be honest about what the recommended platform does poorly

**Format:** Professional memo, not a slide deck. Use the table format from the chapter's Platform Comparison section if helpful, but the recommendation and rationale must be in prose.

**Deliverables:**
- Platform recommendation memo (400-600 words)

---

## Stretch Exercise: Fine-Tune a Small Model for Contract Classification

This exercise requires access to a GPU (Colab, Databricks, or a local machine with NVIDIA GPU). It is optional but covers the most technically advanced material in this chapter.

**Task:** Fine-tune a small language model (Llama 3.1 8B or Mistral 7B) to classify government contracts by type (FFP, CPFF, T&M, IDIQ, BPA) and risk level (Low, Medium, High).

**Data:** Create a synthetic training dataset of at least 200 examples. Each example should be a short contract excerpt (2-5 paragraphs) with a label for contract type and risk level. Annotate 160 for training and 40 for evaluation.

**Steps:**
1. Format your dataset as JSONL with a `text` field and `label` field
2. Use `configure_lora_for_government_nlp()` from `01_llm_integration.py` to set LoRA parameters for the classification task
3. Fine-tune using QLoRA (to reduce memory requirements)
4. Evaluate on your held-out 40 examples — report accuracy per class
5. Compare against a zero-shot baseline: how does the fine-tuned model compare to prompting the base model with a few-shot example?

**Report:**
- Training configuration (model size, LoRA rank, epochs, learning rate)
- GPU memory usage and training time
- Evaluation accuracy (overall and per-class)
- Zero-shot vs. fine-tuned comparison table
- One observation about where fine-tuning helped most and one observation about where it did not help

**Deliverables:**
- Training dataset (JSONL file, 200 examples minimum)
- Fine-tuning script
- Evaluation report

---

*Solutions are in `exercises/solutions/solutions.md`. Attempt each exercise before reading the solutions.*
