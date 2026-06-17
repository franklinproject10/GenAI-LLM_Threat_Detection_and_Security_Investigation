#!/usr/bin/env python3
"""
AI Assistant Incident — reproducible analysis
=============================================
Run this to regenerate every finding in the report from the raw logs,
so you can defend each number yourself.

Setup:
    python3 -m venv venv
    source venv/bin/activate          (Windows: venv\\Scripts\\activate)
    pip install pandas openpyxl
    # drop chat_logs.json, retrieval_logs.xlsx, api_access_logs.xlsx in DATA_DIR
    python analyze_incident.py

It reads .xlsx if present, otherwise falls back to .csv (the original
challenge README referenced .csv files).
"""

import json, os, sys
from collections import defaultdict
import pandas as pd

DATA_DIR = os.environ.get("DATA_DIR", ".")
CORP_PREFIXES = ("10.", "172.16.", "192.168.")   # corporate ranges

def load_table(stem):
    """Load <stem>.xlsx if it exists, else <stem>.csv."""
    xlsx, csv = os.path.join(DATA_DIR, stem + ".xlsx"), os.path.join(DATA_DIR, stem + ".csv")
    if os.path.exists(xlsx):
        return pd.read_excel(xlsx)
    if os.path.exists(csv):
        return pd.read_csv(csv)
    sys.exit(f"Missing {stem}.xlsx / .csv in {DATA_DIR}")

def is_external(ip):
    return not str(ip).startswith(CORP_PREFIXES)

def banner(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)

# ---------- load ----------
with open(os.path.join(DATA_DIR, "chat_logs.json")) as f:
    chats = pd.DataFrame(json.load(f))
retr = load_table("retrieval_logs")
api  = load_table("api_access_logs")

# ---------- PHASE 1: identity / IP anomalies ----------
banner("1. IDENTITY AND IP ANOMALIES (who came from outside?)")
chats["external"] = chats["source_ip"].apply(is_external)
ext_chat = chats[chats["external"]]
print("External IPs seen in chat logs:", sorted(ext_chat["source_ip"].unique()))
for u in chats["user"].unique():
    ips = sorted(chats[chats["user"] == u]["source_ip"].unique())
    if any(is_external(i) for i in ips):
        print(f"  ACCOUNT USED EXTERNALLY: {u} -> {ips}")

# ---------- PHASE 1: attack sessions in chat ----------
banner("2. HIGH-SIGNAL CHAT TURNS (risk high/medium OR blocked)")
sus = chats[(chats["risk_label"].isin(["high", "medium"])) | (chats["guardrail_blocked"])]
for _, r in sus.iterrows():
    print(f"{r['timestamp']} | {r['user']} | {r['source_ip']} | risk={r['risk_label']} "
          f"blocked={r['guardrail_blocked']}\n   {r['prompt'][:90]}")

# ---------- PHASE 1: retrieval — what reached the model ----------
banner("3. SENSITIVE RETRIEVALS (note: blocked_after_retrieval = data already in context)")
print(retr.groupby(["sensitivity", "action"]).size().to_string())
print("\nRestricted/Confidential documents touched, by session:")
hi = retr[retr["sensitivity"].isin(["Restricted", "Confidential"])]
print(hi.groupby(["session_id", "document_name", "sensitivity"]).size()
        .reset_index(name="events").to_string(index=False))

# ---------- PHASE 1: data at risk (returned into context on UNBLOCKED turns) ----------
banner("4. DATA AT RISK (sensitive docs actually returned, action == retrieved)")
leaked = retr[(retr["sensitivity"].isin(["Restricted", "Confidential"])) &
              (retr["action"] == "retrieved")]
print(sorted(leaked["document_name"].unique()))

# ---------- PHASE 1+3: API baseline vs attacker ----------
banner("5. API VOLUME: BASELINE vs EXTERNAL CLIENT")
api["external"] = api["source_ip"].apply(is_external)
base, atk = api[~api["external"]], api[api["external"]]
def stat(df, col): return f"min={df[col].min()} max={df[col].max()} median={df[col].median():.0f} total={df[col].sum()}"
print("Baseline (internal):  req", stat(base, "request_count"), "| tok", stat(base, "tokens_used"))
print("Attacker (external):  req", stat(atk,  "request_count"), "| tok", stat(atk,  "tokens_used"))
print(f"Attacker token share: {100*atk['tokens_used'].sum()/api['tokens_used'].sum():.0f}% of all tokens")
print("Attacker IPs / accounts / agents:",
      sorted(atk["source_ip"].unique()), sorted(atk["service_account"].unique()),
      sorted(atk["user_agent"].unique()))
print("Service accounts seen from external IPs (credential abuse):",
      sorted(atk["service_account"].unique()))

# ---------- PHASE 1: unified timeline ----------
banner("6. UNIFIED TIMELINE (merge all three sources, sorted)")
events = []
for _, r in sus.iterrows():
    events.append((r["timestamp"], "CHAT", f"{r['user']}@{r['source_ip']} risk={r['risk_label']} blocked={r['guardrail_blocked']}"))
for _, r in atk.iterrows():
    events.append((r["timestamp"], "API ", f"{r['service_account']}@{r['source_ip']} {r['endpoint']} req={r['request_count']} tok={r['tokens_used']} http={r['http_status']}"))
for _, r in retr[retr["session_id"].astype(str).str.contains("evil|poison", case=False, na=False)].iterrows():
    events.append((r["timestamp"], "RETR", f"{r['document_name']} {r['sensitivity']} -> {r['action']}"))
for t, src, msg in sorted(events):
    print(f"{t} [{src}] {msg}")

banner("DONE — every number in the report is reproduced above")
