# GenAI / LLM Threat Detection & Incident Response

A reproducible, end-to-end investigation of a security incident targeting an enterprise **AI assistant** — from raw multi-source logs through framework-mapped findings, production-ready detections, and executive reporting.

This project simulates a realistic compromise of a RAG-backed LLM assistant and works it the way a SOC would work a real one: correlate the evidence, prove what actually happened, build detections that catch it, and communicate it to both engineers and leadership.

---

## Why this project exists

Most detection content and IR playbooks were written for traditional infrastructure — endpoints, identities, network. LLM applications introduce a new attack surface that those playbooks don't cover: prompt injection, sensitive data pulled into model context through retrieval, system-prompt leakage, poisoned RAG sources, and token-flood resource abuse.

This investigation builds the missing layer. Every finding is mapped to **AI-specific frameworks** (MITRE ATLAS, OWASP LLM Top 10 2025) alongside traditional ATT&CK, and every number in the report is regenerated from raw logs by a single script — so the analysis is defensible line by line, not asserted.

---

## The scenario

An internal AI assistant exposes three correlated log sources:

| Source | What it captures |
|---|---|
| `chat_logs.json` | Every conversational turn — user, source IP, prompt, risk label, guardrail decision |
| `retrieval_logs.xlsx` | RAG retrievals — which documents reached the model, their sensitivity, and the action taken |
| `api_access_logs.xlsx` | API traffic — service accounts, endpoints, request volume, token usage, user agents |

The investigation reconstructs an attack that spans all three: external access using valid credentials, prompt-injection attempts against the assistant, sensitive documents reaching model context, poisoned retrieval sessions, and abnormal token consumption.

---

## Methodology

The analysis follows a structured, repeatable arc. Each phase is implemented in [`analyze_incident.py`](./analyze_incident.py) and prints its own evidence:

1. **Identity & IP anomalies** — flag accounts and service accounts reaching the assistant from outside corporate ranges (`10/8`, `172.16/12`, `192.168/16`).
2. **High-signal chat turns** — surface conversational turns labeled high/medium risk or stopped by a guardrail (the prompt-injection attempts).
3. **Sensitive retrievals** — group RAG activity by sensitivity and action, separating *blocked-after-retrieval* (data that already reached context) from genuinely blocked requests.
4. **Data at risk** — narrow to Restricted/Confidential documents that were actually **returned**, not merely requested.
5. **API baseline vs. attacker** — compare internal request/token baselines against the external client to quantify resource abuse and credential misuse.
6. **Unified timeline** — merge all three sources into one chronologically sorted sequence of events for the IR narrative.

> Run the script and you reproduce every figure in the written reports. The methodology *is* the audit trail.

---

## Detection engineering

Detections are authored in **Sigma** and compiled to multiple SIEM backends, with a custom processing pipeline that maps the bespoke AI log sources to their target table names.

### Custom Sigma pipeline
`AI_Logs_Pipeline` resolves AI-specific log sources to SIEM tables (`AIApiAccessLogs`, `AIRetrievalLogs`) so the same rule logic compiles cleanly across platforms instead of being hand-rewritten per tool.

### Rules

| Rule | Detects | Type |
|---|---|---|
| **External Source Address Reaching Internal AI APIs** | Requests to chat / RAG-retrieve / vector-search endpoints from outside the corporate network | Signature |
| **AI Service Account Used From Unexpected Address or Client** | Platform service accounts (`rag-prod`, `vector-reader`, `ai-assistant-api`) used from an unexpected IP or non-official user agent | Signature |
| **System Prompt Retrieval or Guardrail Block After Retrieval** | Retrieval of the assistant's system-prompt document, or a guardrail that fired only *after* a document was already in context | Signature |
| **Cross-Department Restricted Enumeration in a Single Session** | One session pulling Restricted documents across **3+ departments within 10 minutes** — enumeration, not normal use | Stateful correlation (`value_count`) |

The last rule is the notable one: it's **behavioral, not signature-based**. No single retrieval looks malicious; the *pattern* across a session does. That's the kind of detection that catches an attacker who stays under every individual threshold.

### SIEM targets
Rules are validated and convertible to **Splunk SPL**, **Microsoft Sentinel / Kusto (KQL)**, **Elastic ES|QL**, and **ElastAlert**.

---

## Framework mapping

Each finding is mapped across three frameworks — traditional, AI-adversarial, and AI-application-risk — so it's legible to any reviewer regardless of which taxonomy they work in.

| Finding | MITRE ATT&CK | MITRE ATLAS | OWASP LLM Top 10 (2025) |
|---|---|---|---|
| External / service-account access with valid creds | T1078 — Valid Accounts | AML.T0012 — Valid Accounts | — |
| Prompt-injection attempts in chat | — | AML.T0051 — LLM Prompt Injection | LLM01 — Prompt Injection |
| Restricted/Confidential docs returned to context | — | — | LLM02 — Sensitive Information Disclosure |
| Poisoned RAG retrieval sessions | — | — | LLM04 — Data & Model Poisoning |
| System-prompt document retrieval | — | AML.T0051 — LLM Prompt Injection | LLM07 — System Prompt Leakage |
| Vector / retrieval-channel abuse | — | — | LLM08 — Vector & Embedding Weaknesses |
| Abnormal token volume from external client | — | — | LLM10 — Unbounded Consumption |

---

## Detection validation

Detections were validated against benign baseline data, not just reviewed for logic. The goal was **precision** — alerts a SOC can trust enough to act on without drowning in false positives. Each rule also carries an explicit `falsepositives` section documenting the legitimate conditions that could trip it (sanctioned partner integrations, new workload hosts, authorized admin review), so triage starts with context already attached.

> _Headline validation metric to confirm before publishing: precision / false-positive rate across the test set._

---

## Repository structure

```
.
├── analyze_incident.py            # Reproducible analysis — regenerates every finding
├── chat_logs.json                 # Conversational logs
├── retrieval_logs.xlsx            # RAG retrieval logs
├── api_access_logs.xlsx           # API access logs
├── Sigma/                         # Detection rules + custom SIEM pipeline
├── AI_Incident_Executive_Brief.docx     # Leadership-facing summary
├── AI_Incident_Technical_Briefing.docx  # Engineer-facing deep dive
├── AI_Incident_Detection_Rules.docx     # Detection documentation
└── README.md
```

---

## Reproduce the analysis

```bash
# Setup
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install pandas openpyxl

# Drop chat_logs.json, retrieval_logs.xlsx, api_access_logs.xlsx in the working dir
python analyze_incident.py
```

The script reads `.xlsx` if present and falls back to `.csv`. Output walks the six phases above and ends with the unified timeline.

---

## Deliverables

The investigation is packaged for three different audiences:

- **Executive brief** — impact, exposure, and decisions, no jargon.
- **Technical briefing** — full evidence chain, methodology, and framework mapping for the defense team.
- **Detection rules documentation** — the Sigma content with logic, mappings, and false-positive handling for whoever operationalizes it.

---

## What this demonstrates

- AI/LLM security requires its **own threat-modeling layer** — ATLAS and OWASP LLM mapped alongside ATT&CK, not in place of it.
- Detection engineering should be **provably precise**, validated against real benign data rather than logic alone.
- Findings should be **reproducible end to end** — every claim regenerable from raw evidence, defensible under questioning.
- Security work has to **translate across audiences**, from a correlation rule to a one-paragraph executive impact statement.

============================================================================================================================================================================
Project Files:
- chat_logs.json: AI assistant prompts, responses, session metadata, risk labels, and guardrail decisions.
- retrieval_logs.csv: RAG document retrievals, sensitivity labels, and retrieval actions.
- api_access_logs.csv: LLM/RAG/vector service API activity.

The data contains normal employee usage mixed with a simulated attack. Identify suspicious behavior, build a timeline, assess impact, and propose detections and mitigations.
