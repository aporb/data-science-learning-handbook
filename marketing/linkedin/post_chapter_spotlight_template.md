# Chapter Spotlight Post Template
## For use across all 13 chapters

**Format:** Text-only (preferred) or text + carousel (for chapters with frameworks/visuals)
**Timing:** 2x per week cadence in post-launch campaign
**Target Length:** 1,200–1,600 characters
**Angle:** Practitioner (specific, useful, "here's what you need to know")

---

## HOW TO USE THIS TEMPLATE

1. Fill in every `[BRACKETED PLACEHOLDER]` with chapter-specific content
2. The hook must contain a number or a specific operational claim — no vague openers
3. The "what most people get wrong" section is mandatory — it creates tension and earns reads
4. The bullet list should have 3-5 items maximum. These are findings, not chapter headings.
5. End with one question to generate comments — make it answerable and specific

---

## TEMPLATE: TEXT POST

---

[HOOK — one of the following patterns:]

**Option A (Number Hook):**
Chapter [X] of the Federal Data Science Learning Handbook covers [TOPIC]. It took me [NUMBER] drafts to get it right, because [SPECIFIC REASON].

**Option B (Counterintuitive Hook):**
Most people learning [PLATFORM/TOPIC] start with [COMMON MISTAKE]. That's wrong. Here's why.

**Option C (Gap Hook):**
[SPECIFIC FRICTION POINT] is one of the most common struggles for analysts new to [PLATFORM]. I've never seen it documented well. Until now.

---

The chapter is called: **[CHAPTER TITLE]**

[2-3 sentence context paragraph explaining why this chapter exists. What operational problem does it address? Who specifically runs into this? Be concrete — avoid abstractions.]

What the chapter covers:

→ [SPECIFIC FINDING OR TECHNIQUE #1 — one sentence, actionable]
→ [SPECIFIC FINDING OR TECHNIQUE #2 — one sentence, actionable]
→ [SPECIFIC FINDING OR TECHNIQUE #3 — one sentence, actionable]
→ [SPECIFIC FINDING OR TECHNIQUE #4 — optional, only if genuinely distinct]

What most [AUDIENCE TYPE] get wrong about [TOPIC]:

[2-3 sentences. This should be a real misconception or gap — not a straw man. If you can't name a real one, replace this section with "What took me longest to figure out:" and answer honestly.]

The full chapter is free at [link in comments].

If you've worked on [PLATFORM/TOPIC], what's the one thing you wish had been documented when you started?

#FederalDataScience #GovCon #[PLATFORM-SPECIFIC HASHTAG]

---

## COMPLETED EXAMPLE — Chapter on Palantir Foundry Data Pipelines

---

The first time you build a pipeline in Palantir Foundry on a classified environment, you spend two days wondering why nothing in the commercial documentation applies.

Here's what changed when I finally figured it out.

Chapter 8 of the Federal Data Science Learning Handbook: **Data Pipeline Architecture in Palantir Foundry for Federal Environments**

This chapter exists because the delta between commercial Foundry documentation and what you actually encounter at IL4/IL5 is enormous. Vendors write docs for their general customer base. Your program's data environment is not their general customer base.

What the chapter covers:

→ Why dataset permissions behave differently in federal Foundry tenants than commercial deployments
→ How to structure transforms for environments with restricted compute access
→ The three pipeline failure modes that appear constantly in federal programs — and none of them are in the vendor docs
→ When to use Contour vs. custom transforms (and the IL-level consideration that changes this answer)

What most Foundry users get wrong early on:

They try to adapt commercial tutorials directly. The platform looks the same. The underlying environment is not. That gap costs weeks.

Full chapter at the link in the comments. Free, always.

What's the Foundry gotcha that cost your team the most time to figure out?

#FederalDataScience #GovCon #Palantir #DataEngineering

---

## CAROUSEL VERSION (For Chapters with Frameworks or Step-by-Step Content)

Use carousels when the chapter contains:
- A numbered process (5+ steps)
- A framework with components
- A comparison (platform A vs. platform B)
- Data or statistics worth visualizing

**Carousel Structure (7-9 slides recommended):**

| Slide | Content |
|-------|---------|
| 1 (Cover) | Chapter title + one-line hook. Bold text, minimal design. |
| 2 | The problem this chapter solves — 2-3 sentences |
| 3 | Key finding #1 — one concept per slide |
| 4 | Key finding #2 |
| 5 | Key finding #3 |
| 6 | Key finding #4 (if applicable) |
| 7 | "What most people get wrong" — the counterintuitive insight |
| 8 | "Where to go next" — point to the full chapter |
| 9 | About slide — Amyn Porbanderwala, HARBORGovCon.com |

**Caption for carousel post:**
Use the text template above, but shorten to 800 characters maximum. The slides carry the detail load.

---

## CHAPTER LINEUP — Post Schedule Suggestions

| Chapter | Suggested Hook Angle | Best Platform Tag |
|---------|---------------------|-------------------|
| Ch. 1: Introduction / Context | Challenger (gap framing) | #FederalDataScience |
| Ch. 2: Federal Data Environment Overview | Thought Leader | #DoD |
| Ch. 3: Python/R in Federal Contexts | Practitioner | #DataScience |
| Ch. 4: Advana Fundamentals | Practitioner | #FederalDataScience |
| Ch. 5: Databricks for Federal | Practitioner | #Databricks |
| Ch. 6: Qlik in Government | Practitioner | #GovCon |
| Ch. 7: Navy Jupiter | Thought Leader | #DoD |
| Ch. 8: Palantir Foundry | Practitioner | #Palantir |
| Ch. 9: Palantir AIP | Challenger | #AI #Palantir |
| Ch. 10: ML/AI in Federal Environments | Thought Leader | #AI |
| Ch. 11: Security & Classification | Challenger | #GovCon |
| Ch. 12: Data Governance for DoD | Challenger | #DoD |
| Ch. 13: Building a Federal DS Practice | Thought Leader | #GovCon |

*Adjust chapter titles and numbers to match actual handbook structure.*

---

## VARIATION: "Lessons Learned" Format (Use Every 3rd Chapter Post)

Instead of a structured overview, write as if you're telling a colleague what surprised you:

---

**Hook:** I rewrote Chapter [X] four times. Here's what I kept getting wrong.

[Tell the story of why the chapter was hard to write. What did you discover mid-draft? What changed your thinking? This format performs well because it's honest and unusual — most "thought leadership" is cleaned up retrospectively. This is real-time.]

The final version is [SPECIFIC CHARACTERIZATION — "the most practical thing in the handbook" or "the one chapter I'd hand to a PM who knows nothing about data science"].

Link in comments.

---

*Template authored for Amyn Porbanderwala | HARBORGovCon.com*
