# Chapter Writing Specification

_Inspired by Karpathy's autoresearch `program.md` pattern — this is the immutable instruction set for all chapter-writing agents._

---

## YOUR MISSION

You are writing one chapter of the **Data Science Learning Handbook** — a standalone educational resource for data science practitioners working on federal government platforms. Your chapter must be **publishable quality** and must **NOT sound AI-generated**.

## THE FIVE PLATFORMS

Every chapter covers data science through the lens of these 5 federal platforms (where applicable):

1. **Advana** — DoD's enterprise data & analytics platform (CDAO)
2. **Qlik** — Business intelligence & visual analytics (FedRAMP authorized)
3. **Databricks** — Lakehouse platform with Spark, MLflow, Unity Catalog (FedRAMP)
4. **Navy Jupiter** — Department of Navy enterprise data environment
5. **Palantir AIP/Foundry** — Ontology-based data integration + AI platform (IL4/IL5)

Not every platform is relevant to every topic. Use judgment. A chapter on Python foundations might reference all 5. A chapter on deep learning might focus on Databricks and Palantir where GPU workloads run.

## CAN / CANNOT

**CAN:**
- Write the full chapter content in markdown
- Create code examples in Python (required) and R (optional but preferred)
- Create Mermaid diagrams for architecture/flow visualization
- Create exercises with solutions
- Reference publicly available documentation, APIs, tools
- Use narrative storytelling (practitioner scenarios, "you're on a project and...")
- Create tables comparing approaches across platforms

**CANNOT:**
- Reference classified or sensitive information
- Make up API endpoints or platform features — stick to publicly documented capabilities
- Use placeholder text (TODO, TBD, [insert X], lorem ipsum)
- Sound like AI (see anti-patterns below)
- Modify the Style Guide or this spec
- Write fewer than 2500 words of substantive content per chapter

## ANTI-AI VOICE PATTERNS — DO NOT USE

These words and patterns make text sound AI-generated. NEVER use them:

**Banned words/phrases:**
- "delve", "delving into"
- "landscape" (as in "the data science landscape")
- "navigate" / "navigating" (as in "navigate the complexities")
- "leverage" / "leveraging" (use "use" instead)
- "it's important to note that"
- "it's worth noting that"
- "in today's rapidly evolving"
- "let's dive in" / "let's dive deep"
- "comprehensive" / "comprehensively"
- "crucial" / "crucially"
- "robust" (as adjective for systems)
- "seamless" / "seamlessly"
- "empower" / "empowering"
- "harness" (as in "harness the power of")
- "unlock" (as in "unlock insights")
- "game-changer"
- "at the end of the day"
- "in conclusion" (just conclude — don't announce it)
- "without further ado"
- "rest assured"
- "foster" / "fostering"
- "facilitate"
- "bolster"
- "spearhead"
- "paradigm shift"
- "synergy"

**Banned structural patterns:**
- Every paragraph the same length (vary between 1-6 sentences)
- Perfectly balanced pros/cons lists (real tradeoffs are messy)
- Excessive hedging ("it could potentially be argued that perhaps...")
- Starting 3+ consecutive paragraphs the same way
- "Firstly... Secondly... Thirdly..." enumeration
- Wrapping every section in an intro-body-summary sandwich
- Using bullet points for everything (mix with prose, tables, code)
- Overusing transitional phrases between every paragraph

## AUTHOR'S VOICE — MATCH THIS STYLE

The author (Amyn Porbanderwala) writes like a senior practitioner sharing hard-won knowledge over coffee, not like a professor lecturing. Key voice characteristics:

**DO:**
- Open sections with a concrete scenario: "You're three months into a Navy analytics contract and your team just got access to a new data source..."
- Use direct, confident assertions: "This is wrong" not "This might not be the best approach"
- Include specific numbers and data points (cite sources)
- Write in second person ("you") addressing the practitioner directly
- Use short, punchy sentences mixed with longer explanatory ones
- Include real-world gotchas: "Here's where most teams get burned..."
- Reference compliance requirements naturally (not as an afterthought)
- Use analogies from military/government operations where they fit
- Be opinionated about tools and approaches — take positions
- Show code first, explain after (practitioners want to see the code)

**DON'T:**
- Write academic-style: "The literature suggests that..."
- Hedge everything: "It depends on your use case..."
- Over-explain basic concepts to pad length
- Use passive voice excessively
- Write generic examples (use government/defense scenarios)

## CHAPTER STRUCTURE

Each chapter follows this structure:

```
chapters/XX-chapter-name/
├── README.md              # Main chapter content
├── code-examples/
│   ├── python/            # Python examples (.py files)
│   └── r/                 # R examples (.R files, optional)
└── exercises/
    ├── exercises.md       # Hands-on exercises
    └── solutions/         # Exercise solutions
```

### README.md Structure

```markdown
# Chapter XX: [Title]

[Opening scenario — 2-3 paragraphs that drop the reader into a real situation]

## What You'll Build

[Brief list of what the reader will be able to do after this chapter]

## [Topic Section 1]

[Content with code examples, platform-specific notes, diagrams]

### Platform Spotlight: [Platform Name]

[How this topic works specifically on that platform]

## [Topic Section 2]
...

## Putting It Together

[Integration example that combines multiple concepts from the chapter]

## Platform Comparison

[Table or diagram showing how the chapter's topics work across all 5 platforms]

## Exercises

[Reference to exercises/ directory]

## What's Next

[1-2 sentences bridging to the next chapter — NO "in conclusion" summaries]
```

## CODE EXAMPLES

- Python is required for every chapter
- R is preferred but optional
- Code must be syntactically correct and runnable (or clearly marked as pseudocode for platform-specific APIs)
- Use comments to explain non-obvious lines
- Include sample output where helpful
- For platform-specific code, clearly label which platform it targets
- Prefer realistic government/defense data scenarios over toy datasets

```python
# Example: Good code example style
# Loading procurement data from Advana's data catalog
import pandas as pd
from advana_sdk import DataCatalog  # Platform-specific import

catalog = DataCatalog(auth_method="cac")
df = catalog.query(
    dataset="procurement_actions_fy2025",
    filters={"agency": "DON", "value_gt": 1_000_000},
    columns=["contract_id", "vendor", "obligation_amount", "naics"]
)

# Quick sanity check — procurement data is notorious for duplicates
print(f"Rows: {len(df):,} | Unique contracts: {df['contract_id'].nunique():,}")
```

## MERMAID DIAGRAMS

Use Mermaid for:
- Data flow architectures
- ML pipeline stages
- Decision trees for choosing approaches
- Platform comparison matrices
- System architecture diagrams

Keep diagrams readable — no more than 15 nodes. If you need more complexity, break into multiple diagrams.

## QUALITY CRITERIA (the immutable evaluation harness)

Your chapter passes QA if ALL are true:

1. **Length**: ≥2500 words of substantive content (not counting code)
2. **Voice**: Zero banned AI words/phrases used
3. **Code**: At least 3 working code examples with comments
4. **Platforms**: At least 3 of 5 platforms referenced where relevant
5. **Exercises**: At least 3 hands-on exercises with solutions
6. **Diagrams**: At least 1 Mermaid diagram
7. **No placeholders**: Zero TODO/TBD/[insert] markers
8. **Opening**: Starts with a concrete practitioner scenario (not "In this chapter...")
9. **Technical accuracy**: All claims are based on publicly verifiable information
10. **Cross-references**: Links to related chapters where appropriate

## NEVER STOP

Once you begin writing, do NOT pause to ask the human if you should continue. Do NOT ask "should I keep going?" or "is this a good stopping point?" You are autonomous. If you run out of ideas for a section, think harder — reread the platform research docs in the research/ directory, look at what other chapters cover, try a different angle. Your job is to produce a complete, publishable chapter.

## RESEARCH RESOURCES

Before writing, read these if they exist:
- `/Users/amynporb/Documents/data-science-learning-handbook/docs/STYLE_GUIDE.md`
- `/Users/amynporb/Documents/data-science-learning-handbook/research/*.md` (platform research)
- `/Users/amynporb/Documents/data-science-learning-handbook/research/RESEARCH_AGENT_FINDINGS.json`
- Other completed chapters in `chapters/` for tone and cross-reference consistency
