# Security boundaries for handbook examples

Last reviewed: November 23, 2026.

## Scope and authority

This is an educational reference, not an agency policy, security certification, or authorization to operate (ATO).
The repository and local lab accept only public or synthetic data.
Do not place CUI, classified data, actual credentials, or operational records in this repository or lab.

A CAC authenticates a person. It does not grant a clearance, need-to-know, data access, or permission to move data.
A cloud authorization does not authorize every service, model, region, or customer system.
Use the program's approved architecture and security plan. Confirm scope with the system owner, ISSO, and authorizing official.

## Data Classification Levels

| Data | Boundary considerations |
|------|-------------------------|
| Public information | Use approved public sources and synthetic fixtures for handbook exercises. Check licenses and privacy restrictions. |
| Controlled Unclassified Information (CUI) | CUI is unclassified. Use the system and services approved for the data category, mission, and contract. DoD IL4 and IL5 address unclassified workloads with different requirements. |
| Secret | Use a specifically authorized Secret environment. DoD cloud IL6 addresses workloads up to Secret. SIPRNet supports Secret communications. Ordinary AWS GovCloud and Azure Government offerings do not become classified environments through encryption or a CAC. |
| Top Secret / SCI | Use an environment explicitly authorized for that classification and compartments, such as the appropriate JWICS environment. IL6 is not a blanket Top Secret authorization. SIPRNet is not a Top Secret network. |

Classification follows authorized classification guidance, not the subject of an example.
A logistics or personnel dataset is not automatically Secret. Unclassified does not mean public.
Do not infer that an Advana, Jupiter, or vendor deployment on one network shares another deployment's authorization.

## Approved services and models

Do not send nonpublic government data to public chat, embedding, telemetry, or inference endpoints.
An approved managed service can be used only within the program's approved boundary.
Verify the exact offering, model version, endpoint, region or network, data handling terms, and permitted use.
Self-hosting is an implementation option, not an exemption from model import, licensing, supply-chain, or security review.
If authorization is unknown, stop the integration and obtain confirmation. Do not test with restricted data.

## Security Controls

Use least privilege, the approved identity provider, and service identities appropriate for each workload.
Preserve required CAC/PIV authentication for interactive users. Do not simulate a CAC as evidence of real identity validation.
Apply the system's required encryption configuration and validated cryptographic modules.
An algorithm name such as AES-256 or a TLS version does not establish FIPS validation.
Protect secrets through approved secret storage and rotation. Do not put secrets in source, prompts, screenshots, or logs.

Log security-relevant access and changes under the approved privacy and records-retention rules.
A hash chain alone does not make storage immutable or tamper-proof. Validate integrity, access control, and recovery separately.
Do not use example cross-domain code to transfer operational data. Use approved transfer mechanisms and release procedures.

## Data Encryption

NIST moved FIPS 140-2 validations to the historical list on September 21, 2026.
NIST supports continued purchase and use for existing systems subject to agency decisions.
For new deployments, confirm current agency requirements, module validation status, operating mode, and configuration.
Do not replace every reference to FIPS 140-2 mechanically or claim validation from a Python library name.

## Compliance Standards

Use the applicable version and scope of FISMA, NIST controls, CUI requirements, FedRAMP, and DoD cloud guidance.
FedRAMP certification and DoD impact levels are different programs. Neither replaces a system authorization.
Current FedRAMP 2026 rules use class-based terminology. Retain historical names when discussing historical authorizations.
Check the current offering record rather than applying a vendor-wide label.

For AI governance, distinguish binding agency policy from voluntary frameworks and recommended engineering practice.
OMB M-25-21 excludes AI used as a component of a National Security System. Other defense and intelligence policies apply there.
The NIST AI RMF is guidance. Do not describe a handbook checklist as proof that an AI system satisfies every legal requirement.

## Local lab and reference tools

Keep published container ports on loopback. Keep notebook authentication and XSRF protection enabled.
Use synthetic data even when the lab demonstrates authentication, classification, or audit concepts.
The reference stack is not a replica of an accredited environment.
Do not run penetration tests or security scanners against live systems without separate written authorization.
Parsing and unit tests do not establish operational security or production readiness.

## Incident response and contacts

If restricted information enters a prompt or lab, stop the activity and use the program's incident-reporting procedure.
Do not copy suspected restricted content into a public issue or attempt informal cross-domain cleanup.
This project does not operate a DoD security team, CISO approval process, or emergency hotline.
Report nonsensitive documentation defects through the repository issue tracker.
Use the actual program's security channels for operational incidents.

## Sources

- [DoD Cloud Computing Security](https://public.cyber.mil/dccs/): current cloud guidance and impact-level requirements.
- [AWS GovCloud FAQ](https://aws.amazon.com/govcloud-us/faqs/): GovCloud scope and compliance programs.
- [Databricks AWS GovCloud](https://docs.databricks.com/aws/en/security/privacy/gov-cloud): distinct offerings and NIPRNet IL5 environment.
- [NIST FIPS transition](https://csrc.nist.gov/projects/fips-140-3-transition-effort): historical validations and existing-system use.
- [FedRAMP 2026 Class D rules](https://www.fedramp.gov/2026/reference/rev5/d/): current rules and terminology.
- [OMB M-25-21](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf): AI use, governance, and applicability.
