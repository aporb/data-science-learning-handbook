# Platform Spotlight Thread Template
## Federal Data Science Learning Handbook

**Use this template to highlight specific federal platforms, tools, or environments
covered in the handbook (e.g., Azure Government, AWS GovCloud, Databricks on FedRAMP, etc.).**
**Rotate one platform spotlight per 2 weeks post-launch.**

---

## TEMPLATE STRUCTURE (6 tweets)

---

### Tweet 1 — HOOK

**Formula:** Name the platform + the friction + the promise of relief

```
[PLATFORM NAME] is [used by / mandated at / deployed across] [SCOPE].

Most data scientists working in federal environments have had to figure it out
entirely on their own.

Chapter [NUMBER] of the Federal Data Science Learning Handbook doesn't make you do that.

Here's what's in it: 🧵
```

**Alternate Hook (problem-first):**
```
Nobody documents what it's actually like to do data science on [PLATFORM]
in a federal context.

Not the vendor. Not the certifications. Nobody.

Until now.

Thread on what we cover in the handbook: 🧵
```

---

### Tweet 2 — THE PLATFORM CONTEXT

```
Quick context on [PLATFORM NAME]:

[1 sentence: what it is]
[1 sentence: why it's used in federal/DoD environments]
[1 sentence: who specifically uses it — which agencies, roles, or mission sets]

If that's your world, keep reading.
```

**Example (Azure Government):**
```
Quick context on Azure Government:

It's Microsoft's FedRAMP-authorized cloud — the default for many civilian agency
workloads. DoD shops often run the same workloads on Azure DoD or GovCloud.

If you're doing cloud-based data science in a federal environment,
there's a high chance this is your infrastructure. Keep reading.
```

---

### Tweet 3 — WHAT'S DIFFERENT ON THIS PLATFORM (vs. commercial/generic)

**This is the tweet that resonates hardest with practitioners.**

```
Here's what changes when you move from commercial [PLATFORM] to the federal version:

→ [Difference 1 — something the reader has personally hit]
→ [Difference 2]
→ [Difference 3]
→ [Difference 4]

The documentation doesn't warn you about this. The handbook does.
```

**Example (AWS GovCloud):**
```
Here's what changes in AWS GovCloud vs. commercial AWS:

→ Fewer available services (not everything is FedRAMP authorized)
→ IAM policies are more restrictive by default
→ Marketplace access is limited
→ Data egress has additional compliance layers

AWS's own docs don't emphasize this enough. We do.
```

---

### Tweet 4 — THE PRACTICAL CONTENT

```
What Chapter [NUMBER] covers on [PLATFORM]:

✅ [Specific capability or setup task 1]
✅ [Specific capability or setup task 2]
✅ [Common error or gotcha + how to handle it]
✅ [Integration or workflow specific to the platform]
✅ [Compliance or security consideration practitioners must know]

Written by someone who has actually done this work. Not a vendor guide.
```

---

### Tweet 5 — THE INSIGHT / PRACTITIONER TAKE

```
[PLATFORM]-specific insight most people learn the hard way:

[SHORT, SPECIFIC OBSERVATION — something true and surprising about working on this platform in federal environments]

[1 sentence follow-up that makes this concrete or stakes-relevant]
```

**Examples:**

For cloud platforms:
```
Databricks-on-FedRAMP insight most teams miss:

Your Unity Catalog governance controls need to be configured before you
touch production data — not after. Retrofitting it costs you 3x the time.

Chapter [X] walks you through getting it right the first time.
```

For on-prem/legacy platforms:
```
The most common failure mode on legacy federal data platforms:

Trying to run modern workflows (MLflow, Airflow, containerized pipelines)
on infrastructure designed for batch jobs from 2012.

Chapter [X] is about realistic modernization — not theoretical modernization.
```

---

### Tweet 6 — CTA

```
[PLATFORM NAME] data science in federal environments:
it's learnable, it's documented, and it's free.

Chapter [NUMBER] of the Federal Data Science Learning Handbook:
[SPECIFIC CHAPTER TITLE]

Full handbook (96K words, open source): [LINK]

Tag someone who's been fighting this battle alone.

#GovTech #[Platform-specific hashtag if applicable]
```

---

## PLATFORM-SPECIFIC HOOK EXAMPLES

### Azure Government / Azure DoD

```
Azure Government is the default cloud for dozens of federal civilian agencies.

The data science toolchain on it works differently than commercial Azure.
Different service availability. Different IAM defaults. Different support model.

Nobody writes about this clearly. We did. 🧵
```

### AWS GovCloud

```
AWS GovCloud powers some of the most sensitive federal workloads in the country.

It's also missing services you'd take for granted on commercial AWS.

If you're a data scientist on GovCloud, this thread is for you. 🧵
```

### On-Prem / Air-Gapped Environments

```
Hot take: air-gapped data science is a completely different discipline
from anything taught in bootcamps or university programs.

No Stack Overflow. No pip install. No real-time model APIs.

Here's how Chapter [X] of the handbook addresses the reality: 🧵
```

### Jupyter / JupyterHub on Federal Infra

```
JupyterHub is everywhere in federal data science.

It's also almost never configured the way the docs assume.

This thread is about doing real work in a federal JupyterHub environment
without wanting to quit. 🧵
```

### Databricks (FedRAMP)

```
Databricks became a major player in federal data engineering.

The federal version and the commercial version are not the same product.

Here's what data scientists and engineers need to know before assuming otherwise. 🧵
```

### Python on Locked-Down Federal Machines

```
Python on a federal workstation:
- Conda might work
- pip might not
- internet access is not guaranteed
- the version is probably not current

This isn't a complaint. It's the environment. Chapter [X] is built for it. 🧵
```

---

## POSTING CHECKLIST

- [ ] Hook names the specific platform — generic hooks underperform
- [ ] Tweet 3 (what's different) is specific enough to feel insider/practitioner
- [ ] Insight tweet (Tweet 5) is something the reader wouldn't find in vendor docs
- [ ] Link appears in the final tweet only
- [ ] 1–2 hashtags maximum (GovTech + platform-specific)
- [ ] Thread is 6 tweets (expandable to 8 if the platform warrants it)
- [ ] Platform name is in the hook (helps with search and algorithmic distribution)
- [ ] Posted Tue–Thu, 8–10 AM or 7–9 PM EST
- [ ] Engage replies within 30 minutes
