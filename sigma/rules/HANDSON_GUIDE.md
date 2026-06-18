# Sigma Detection Engineering: Hands-On Guide

How these detections were built, converted, and validated, with the exact points to screenshot for the GitHub writeup. Follow it top to bottom and you will be able to explain the whole process confidently.

## Which tool to use, and when

You have several converters. Use them with intent rather than at random.

| Tool | Role here | Why |
|---|---|---|
| **sigma-cli** (local) | Source of truth | Reproducible, version controlled, runs in your venv, and is what serious teams use. Every query in CONVERSIONS.md came from this. Lead with it. |
| **sigconverter.io** | Primary web tool for screenshots | Shows the rule, the converted query, and the equivalent CLI command in one view. Best single visual for documentation. |
| **Uncoder.io** (SOC Prime) | Breadth shot | Widest platform list including Microsoft Defender XDR and EDR formats. Use for one screenshot that shows multi platform reach. |
| **Detection Studio** | Correlation shot | Handles correlation rules and shows a SIEM query output pane, good for the stateful Rule 4. |
| **sigmaio** | Backup | Equivalent to sigconverter if it is down. |

Recommendation: author and convert with sigma-cli as the reproducible record, then use sigconverter.io for the clearest screenshots and Uncoder.io for one breadth shot. That story, "I author in Sigma, convert with the official CLI, and cross check in the web tools," reads as senior.

## The process, step by step

**Step 1. Start from a behavior, not a tool.** Each rule began as a sentence about the incident. "An AI endpoint is reached from outside our network." "A service account appears from a strange place or client." "The system prompt is retrieved, or a block fires after the document was already pulled."

**Step 2. Pin the log source and fields.** Identify which log carries the evidence and the exact field names. Rules 1 and 2 use the API access log (`source_ip`, `service_account`, `endpoint`, `user_agent`). Rule 3 uses the retrieval log (`document_name`, `action`).

**Step 3. Write the detection block.** Express what to match as one or more `selection` keys, what to exclude as `filter` keys, and tie them together in `condition`. Sigma is space and case sensitive, so indent carefully.

**Step 4. Add the metadata that makes it credible.** `title`, a unique `id`, `status`, `description`, `references` (we cite MITRE ATLAS and ATT&CK), `tags`, `level`, `falsepositives`, and `fields`. The references and false positives are what separate a real rule from a snippet.

**Step 5. Validate before converting.** Run `sigma convert` against the rule. If it parses and emits a query, the syntax is sound. A parse error here is far cheaper than a broken rule in the SIEM.

**Step 6. Convert to each target.** Use the commands in CONVERSIONS.md. For our custom logs, pass the custom pipeline so the rules map to our tables.

**Step 7. Document logic, coverage, assumptions, and limitations.** For every rule, write those four. This is the graded part of the challenge and the part that shows judgment. CONVERSIONS.md has them.

**Step 8. Commit to git.** The rules and pipeline are detection as code. Version control them so changes are tracked, which is the reproducibility story interviewers like.

## Screenshot checkpoints for the GitHub writeup

Capture these in order. Each one proves a specific claim. Suggested filenames are in parentheses.

1. **VS Code with a rule file open** showing the full Sigma YAML, ideally Rule 1. Proves you authored the rule. (`01_rule_authoring.png`)
2. **Terminal: `sigma version` and `sigma list targets`** after install. Proves the toolchain is set up and which backends you have. (`02_sigma_cli_setup.png`)
3. **Terminal: a conversion command and its output**, for example the Splunk conversion of all three rules. Proves real, reproducible conversion. (`03_cli_conversion_splunk.png`)
4. **sigconverter.io with Rule 1 pasted**, target set to splunk, showing the rule on the left, the SPL on the right, and the CLI command at the top. This is your headline image. (`04_sigconverter_splunk.png`)
5. **sigconverter.io, same rule, target switched to Microsoft XDR (kusto)** so the output becomes KQL. Proves portability from one rule to many platforms. (`05_sigconverter_kql.png`)
6. **Uncoder.io with the same rule translated**, ideally to a platform you did not already show, such as Sentinel or Elastic. Proves breadth and shows the SOC Prime ecosystem. (`06_uncoder_breadth.png`)
7. **Terminal: the correlation rule converting to SPL and ES|QL.** Proves you can express a stateful detection, not just atomic ones. (`07_correlation_spl_esql.png`)
8. Optional. **Detection Studio with the correlation rule** in the editor and the SIEM query output pane populated. A nice extra for the stateful story. (`08_detection_studio_correlation.png`)

Put these in a `docs/screenshots/` folder in the repo and reference them from your README so the writeup walks a reader from authoring through conversion to validation.

## The one paragraph you can say out loud
"I wrote three Sigma detections from the incident, one for external access to the AI stack, one for service account abuse, and one for system prompt targeting, plus a stateful correlation rule for cross department enumeration. I explained the logic, coverage, assumptions, and limitations for each, then converted them to Splunk, Kusto for Microsoft Defender and Sentinel, and Elasticsearch using the sigma-cli toolchain with a custom pipeline that maps our bespoke AI logs to their tables. The rules live in git as detection as code, so one human readable rule deploys to any SIEM we run."
