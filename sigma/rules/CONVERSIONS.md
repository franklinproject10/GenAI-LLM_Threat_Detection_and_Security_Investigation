# Sigma to SIEM Conversions

Three atomic Sigma rules plus one stateful correlation rule, authored from the CentralReach AI assistant incident, converted to Splunk SPL, ES|QL, Elasticsearch Lucene, and Kusto (Microsoft Defender and Sentinel) with the official `sigma-cli` toolchain. Every query below is real tool output, not hand written.

## Toolchain and commands

```bash
# one time setup
python -m pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch pysigma-backend-kusto

# atomic rules, all four targets (custom pipeline maps our log tables)
sigma convert -t splunk  -p ./centralreach_ai_pipeline.yml rules/
sigma convert -t esql    -p ./centralreach_ai_pipeline.yml rules/
sigma convert -t lucene  -p ./centralreach_ai_pipeline.yml rules/
sigma convert -t kusto   -p microsoft_xdr -p ./centralreach_ai_pipeline.yml rules/

# stateful correlation rule (Splunk and ES|QL only)
sigma convert -t splunk  -p ./centralreach_ai_pipeline.yml rules/04_cross_dept_enumeration_correlation.yml
sigma convert -t esql    -p ./centralreach_ai_pipeline.yml rules/04_cross_dept_enumeration_correlation.yml
```

Why the custom pipeline matters: our logs are custom sources, not standard Windows or Sysmon categories. The Kusto backend needs to know which table each rule queries, so `centralreach_ai_pipeline.yml` maps the api_access source to the `AIApiAccessLogs` table and the retrieval source to `AIRetrievalLogs`. Without it, Kusto emits only the predicate with no table. This is the single most common real world snag, and showing you solved it with a pipeline is exactly the maturity a reviewer looks for.

---

## Rule 1. External source address reaching the AI APIs

**Logic.** Fires when one of the AI endpoints (`/v1/chat/completions`, `/rag/retrieve`, `/vector/search`) is hit from any address outside the corporate ranges. Written as a selection plus a "not internal" filter.
**Coverage.** Both external IPs in the incident, including the very first malicious request. Catches the interactive attacker and the API attacker at the network layer at once.
**Assumptions.** Corporate ranges are enumerated, VPN egress is known, and the API logs record `source_ip`.
**Limitations.** Blind to an attacker already inside the network. Note the Splunk output below renders the CIDR as a literal string match, so in production you replace it with `cidrmatch()`. ES|QL and Kusto emit true CIDR functions automatically.

```spl
# Splunk (adjust CIDR to cidrmatch in production)
endpoint IN ("/v1/chat/completions", "/rag/retrieve", "/vector/search") NOT (source_ip="10.0.0.0/8" OR source_ip="172.16.0.0/12" OR source_ip="192.168.0.0/16") | table source_ip,service_account,endpoint,user_agent
```
```sql
-- ES|QL
from * metadata _id, _index, _version | where (endpoint in ("/v1/chat/completions", "/rag/retrieve", "/vector/search")) and not (cidr_match(source_ip, "10.0.0.0/8") or cidr_match(source_ip, "172.16.0.0/12") or cidr_match(source_ip, "192.168.0.0/16"))
```
```kusto
// Kusto (Defender / Sentinel)
AIApiAccessLogs
| where (endpoint in~ ("/v1/chat/completions", "/rag/retrieve", "/vector/search")) and (not((ipv4_is_in_range(source_ip, "10.0.0.0/8") or ipv4_is_in_range(source_ip, "172.16.0.0/12") or ipv4_is_in_range(source_ip, "192.168.0.0/16"))))
```
```
# Lucene
(endpoint:(\/v1\/chat\/completions OR \/rag\/retrieve OR \/vector\/search)) AND (NOT (source_ip:10.0.0.0\/8 OR source_ip:172.16.0.0\/8 OR source_ip:192.168.0.0\/16))
```

---

## Rule 2. AI service account from unexpected address or client

**Logic.** Fires when an AI service account appears either from a non `10.` address or with a user agent that is not the official `ai-assistant/` client. The filter excludes only the known good combination, so anything else trips it.
**Coverage.** The `rag-prod` credential used from `45.83.64.21` by the `python-requests` batch client.
**Assumptions.** Service accounts have stable source hosts and a known user agent prefix, and the logs capture `service_account` and `user_agent`.
**Limitations.** A spoofed official user agent from a compromised internal host evades the user agent half. The `source_ip startswith "10."` check is coarse; Rule 1's CIDR is the more precise internal test. Keep the allowlist current.

```spl
# Splunk
service_account IN ("rag-prod", "vector-reader", "ai-assistant-api") NOT (source_ip="10.*" user_agent="ai-assistant/*") | table service_account,source_ip,user_agent,tokens_used
```
```sql
-- ES|QL
from * metadata _id, _index, _version | where (service_account in ("rag-prod", "vector-reader", "ai-assistant-api")) and not (starts_with(source_ip, "10.") and starts_with(user_agent, "ai-assistant/"))
```
```kusto
// Kusto (Defender / Sentinel)
AIApiAccessLogs
| where (service_account in~ ("rag-prod", "vector-reader", "ai-assistant-api")) and (not((source_ip startswith "10." and user_agent startswith "ai-assistant/")))
```

---

## Rule 3. System prompt retrieval or guardrail block after retrieval

**Logic.** Fires on any retrieval of `AI_Assistant_System_Prompt.txt`, or any `blocked_after_retrieval` action. Two selections joined by `1 of selection_*`.
**Coverage.** The jailbreak session and the indirect injection session that targeted the system prompt.
**Assumptions.** Retrieval logs record `document_name` and emit a distinct `blocked_after_retrieval` action, and the system prompt is a named artifact.
**Limitations.** This is atomic. The "two or more blocks in ten minutes" threshold from the original detection is a stateful extension (see Rule 4). Once retrieval time authorization exists, `blocked_after_retrieval` should disappear, which is the goal.

```spl
# Splunk
document_name="AI_Assistant_System_Prompt.txt" OR action="blocked_after_retrieval" | table session_id,user,document_name,sensitivity,action
```
```kusto
// Kusto (Defender / Sentinel)
AIRetrievalLogs
| where document_name =~ "AI_Assistant_System_Prompt.txt" or action =~ "blocked_after_retrieval"
```

---

## Rule 4. Cross-department restricted enumeration (stateful correlation)

**Logic.** A two part Sigma correlation. A base rule matches any Restricted retrieval, then a `value_count` correlation counts distinct departments per session over ten minutes and fires at three or more. This is the enumeration signal: one session reaching across HR, legal, and security.
**Coverage.** The bulk enumeration session that pulled documents from multiple departments.
**Assumptions.** Documents are tagged with `department` and `sensitivity`, and the SIEM supports aggregation.
**Limitations.** Sigma correlations currently convert only to Splunk SPL and Elasticsearch ES|QL, not to Kusto or Lucene. Sigma supports `event_count`, `value_count`, and `temporal` correlations, but not arithmetic sum of a field, which is why the token volume burst detection is better expressed directly in SPL.

```spl
# Splunk
sensitivity="Restricted"
| bin _time span=10m
| stats dc(department) as value_count by _time session_id
| search value_count >= 3
```
```sql
-- ES|QL
from * metadata _id, _index, _version | where sensitivity=="Restricted"
| eval timebucket=date_trunc(10minutes, @timestamp) | stats value_count=count_distinct(department) by timebucket, session_id
| where value_count >= 3
```

---

## What this demonstrates
One human readable rule in Sigma, converted to four query languages by tool, with a custom pipeline for our bespoke log sources and a stateful correlation for the detection that needs aggregation. This is detection as code: author once, deploy anywhere, version control the rules in git.
