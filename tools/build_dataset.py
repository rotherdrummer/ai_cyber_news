"""Build the public Watchfloor dataset (items.json + CSVs) from the exported claude.ai store."""
import json, glob, os, csv, re, hashlib, sys
from urllib.parse import urlparse

DB = os.path.join(os.path.dirname(__file__), "db")
OUT = sys.argv[1]
COLLECTED = "2026-10-08"

def load(p):
    d = json.load(open(p)); return d.get("data", d)

PRIMARY_DOMAINS = ["aisi.gov.uk","ncsc.gov.uk","gov.uk","anthropic.com","openai.com","cloud.google.com",
  "metr.org","mitre.org","parliament.uk","deploymentsafety.openai.com","axios.com/2026/08/10"]
SECONDARY_HINTS = ["wikipedia.org","llm-stats.com","local-ai-zone","securityaffairs","lexisnexis","law-ai.org",
  "addleshawgoddard","qualio","ukauthority","infoworld","epoch.ai","digitalapplied","benchlm","axios.com"]

def source_type(url):
    u = (url or "").lower()
    if any(h in u for h in ["wikipedia.org","llm-stats.com","local-ai-zone","securityaffairs","lexisnexis","law-ai.org",
                            "addleshawgoddard","qualio","ukauthority","infoworld","epoch.ai","digitalapplied","benchlm","axios.com"]):
        return "Secondary"
    host = urlparse(u).netloc
    if any(host.endswith(d) for d in ["aisi.gov.uk","ncsc.gov.uk","gov.uk","anthropic.com","openai.com","cloud.google.com","metr.org","mitre.org","parliament.uk"]):
        return "Primary"
    return "Secondary"

# risk areas: manual judgement by title keyword (first match wins)
AREA_RULES = [
 ("Autonomous AI risk", ["unsanctioned","cheating behaviour","multi-agent","attributed to OpenAI's own","Hugging Face","pauses reinforcement",
    "agent behaviour","cover up","Senate on AI agent","secure environment for evaluating","Transect","Control Red Team","lie detectors",
    "preferences predict","Prefill awareness","RealityTest","Item response theory","optimal stopping","Optimal stopping","pre-deployment evaluation","cancellation of GPT-6.1 Astra"]),
 ("Secure AI adoption", ["agentic AI services","shadow AI","National Commission","AI Bill","EU AI Omnibus","Resilience Bill","lawsuit"]),
 ("Cross-cutting", ["DSIT","Taskforce","Germany","Export controls"]),
 ("AI-enabled cyber threats", [""]),
]
LANDSCAPE = ["DSIT","Taskforce","Germany","National Commission","Government response","Cyber Verification Program","Daybreak","Argon"]

def area(title):
    for a, keys in AREA_RULES:
        if any(k.lower() in title.lower() for k in keys): return a
    return "AI-enabled cyber threats"

def themes(title, cat, extra=""):
    t = (title + " " + extra).lower(); tags = []
    def add(x):
        if x not in tags: tags.append(x)
    if any(k in t for k in ["release","launched","generally available","preview","gpt-6","claude","gemini","mistral","model"]): add("model-release")
    if any(k in t for k in ["exploit","vulnerab","zero-day"]): add("vulnerability-research")
    if any(k in t for k in ["agent","autonom"]): add("agents")
    if any(k in t for k in ["evaluat","benchmark","assessment of","stopping","item response","transect"]): add("evaluation")
    if any(k in t for k in ["incident","intrusion","breach"]): add("incident")
    if any(k in t for k in ["threat report","threat tracker","misuse","att&ck","phishing","espionage","actor"]): add("threat-actor-reporting")
    if any(k in t for k in ["guidance","adoption","shadow ai","statement"]): add("guidance")
    if any(k in t for k in ["bill","act","omnibus","regulat","commission","lawsuit","export controls"]): add("regulation")
    if any(k in t for k in ["supply-chain","supply chain"]): add("supply-chain")
    if any(k in t for k in ["defender","verification program","daybreak","argon"]): add("defender-access")
    if any(k in t for k in ["open-weight","kimi"]): add("open-weight")
    if any(k in t for k in ["health","nhs","hospital"]): add("health")
    if any(k in title for k in LANDSCAPE): add("landscape-change")
    return tags

PUB_OVERRIDE = {
 "GPT-6 Sol and GPT-6 Luna: October 2026 update": "2026-10-07",
 "Government response to the National Commission on regulating AI in healthcare": "2026-10-06",
 "Expanding the Cyber Verification Program": "2026-10-06",
}

def pid(*parts):
    return "wf-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


# ---- RAG rating: potential importance, machine-assigned with fixed, published criteria ----
RAG_CRITERIA = {
 "Red": "Evidence of real-world AI-enabled malicious activity or AI agents acting beyond their sanction; a model rated at a critical cyber threshold; near-complete autonomous exploitation results; or an authoritative warning that the threat has materially changed.",
 "Amber": "A significant change that may matter soon: notable capability gains, new government guidance or warnings, changes to who can access cyber-capable models, or regulatory and institutional changes.",
 "Green": "Background: evaluation methods, general research, routine releases without cyber evidence, and commentary.",
}
RED_KEYS = ["intrusion","breach","Hugging Face","unsanctioned agent","Countering misuse","Threat Tracker","rated Critical",
            "performs unsanctioned supply-chain","accelerating vulnerability discovery","ExploitBench: GPT-6 Astra","AISI unsanctioned supply-chain attacks: GPT-6 Astra"]
GREEN_KEYS = ["Item response theory","optimal stopping","Optimal stopping","Transect","Prefill awareness","lie detectors","RealityTest",
              "preferences predict","Control Red Team","lawsuit","Export controls","UK AI Bill","Sonnet 5.5","Mistral Large 4",
              "pre-deployment evaluation","supply-chain attacks: GPT-5.5","Claude Opus 4.7"]
def rag(rec):
    t = rec["title"]
    if rec["item_type"] in ("Incident","Threat finding"): return "Red","Real-world malicious activity or incident"
    if any(k.lower() in t.lower() for k in RED_KEYS): return "Red","Material change in threat or agent behaviour"
    if any(k.lower() in t.lower() for k in GREEN_KEYS): return "Green","Background"
    return "Amber","Significant change to watch"

items = []
report_ids = {}
for f in sorted(glob.glob(os.path.join(DB, "register", "*.json"))):
    d = load(f)
    for it in d.get("items", []):
        title = it["title"]; pub = PUB_OVERRIDE.get(title, d["date"])
        iid = pid(it.get("url",""), title)
        typ = {"threat":"Report","gov":"Publication","research":"Research","capability":"Model or capability","policy":"Policy"}.get(it["cat"],"Other")
        if it["cat"] in ("threat","gov") and any(k in title.lower() for k in ["incident","intrusion","breach"]): typ = "Incident"
        rec = {"id":iid,"published":pub,"collected":COLLECTED,"item_type":typ,"title":title,"publisher":it.get("source",""),
               "url":it.get("url",""),"source_type":source_type(it.get("url","")),"source_says":it.get("summary",""),
               "key_findings":"","evidence_links":"","health_named":"Yes" if any(k in (title+it.get("summary","")).lower() for k in ["health","hospital"]) else "No",
               "tag_risk_area":area(title),"tag_themes":";".join(themes(title,it["cat"],it.get("summary",""))),
               "tag_significant":"Yes" if it.get("major") else "No","related_ids":""}
        items.append(rec)
        if it.get("url"): report_ids.setdefault(it["url"], iid)

# actor-level threat findings and incidents: separate findings, linked to their parent report
for f in sorted(glob.glob(os.path.join(DB, "threats", "*.json"))):
    t = load(f)
    parent = report_ids.get(t.get("url",""), "")
    iid = pid(t.get("url",""), t["title"])
    if t.get("kind") == "incident":  # incidents are already register items: skip to avoid duplicates
        continue
    findings = "; ".join(x for x in [t.get("actor") and "Actor: "+t["actor"], t.get("technique") and "Technique: "+t["technique"],
                                      t.get("sectors") and "Targets: "+t["sectors"]] if x)
    items.append({"id":iid,"published":t["date"],"collected":COLLECTED,"item_type":"Incident" if t.get("kind")=="incident" else "Threat finding",
        "title":t["title"],"publisher":t.get("publisher",""),"url":t.get("url",""),"source_type":source_type(t.get("url","")),
        "source_says":t.get("summary",""),"key_findings":findings,"evidence_links":"",
        "health_named":"Yes" if t.get("health") else "No",
        "tag_risk_area":"Autonomous AI risk" if t.get("kind")=="incident" else "AI-enabled cyber threats",
        "tag_themes":";".join(themes(t["title"],"threat",findings)+(["threat-actor-reporting"] if t.get("kind")!="incident" else [])),
        "tag_significant":"Yes" if t.get("health") else "No","related_ids":parent})

# evaluation results
for f in sorted(glob.glob(os.path.join(DB, "evidence", "*.json"))):
    e = load(f)
    if not isinstance(e.get("value"), (int, float)): continue  # non-numeric results duplicate register items
    title = f"{e['test']}: {e['model']} {e.get('result','')}".strip()
    parent = report_ids.get(e.get("url",""), "")
    note = e.get("note") or ""
    sr = "self-reported" in (e.get("evaluator","")).lower()
    items.append({"id":pid(e.get("url",""), title),"published":e["date"],"collected":COLLECTED,"item_type":"Evaluation result",
        "title":title,"publisher":e.get("evaluator",""),"url":e.get("url",""),"source_type":source_type(e.get("url","")),
        "source_says":f"{e['model']} scored {e.get('result','')} on {e['test']} ({e.get('unit','')})."+(" Self-reported by the developer." if sr else ""),
        "key_findings":note,"evidence_links":"","health_named":"No",
        "tag_risk_area":"Autonomous AI risk" if "unsanctioned" in e["test"].lower() else "AI-enabled cyber threats",
        "tag_themes":";".join(["evaluation"]+(["open-weight"] if e.get("weights")=="open" else [])+(["vulnerability-research"] if "exploit" in e["test"].lower() or "sec-bench" in e["test"].lower() else [])),
        "tag_significant":"No","related_ids":parent})

for r in items:
    r["tag_rating"], r["tag_rating_reason"] = rag(r)
    r.pop("tag_significant", None)

# de-duplicate exact ids, newest first
seen=set(); uniq=[]
for r in sorted(items, key=lambda r:(r["published"], r["title"]), reverse=True):
    if r["id"] in seen: continue
    seen.add(r["id"]); uniq.append(r)
items = uniq

COLS = ["id","published","collected","item_type","title","publisher","url","source_type","source_says","key_findings",
        "evidence_links","health_named","tag_risk_area","tag_themes","tag_rating","tag_rating_reason","related_ids"]

os.makedirs(os.path.join(OUT,"data"), exist_ok=True)
meta = {"name":"Watchfloor public AI cyber intelligence dataset","updated":COLLECTED,"item_count":len(items),
        "fields":{"source fields":COLS[:12],"machine-assigned tags":["tag_risk_area","tag_themes","tag_rating","tag_rating_reason","related_ids"]},"rating_criteria":RAG_CRITERIA,
        "note":"Public sources only. source_says and key_findings summarise what the source reports. tag_ fields are machine-assigned categorisation, not findings."}
json.dump({"meta":meta,"items":items}, open(os.path.join(OUT,"data","items.json"),"w"), ensure_ascii=False, indent=1)

def write_csv(path, rows):
    with open(path,"w",newline="",encoding="utf-8-sig") as fh:  # BOM so Excel opens UTF-8 cleanly
        w = csv.DictWriter(fh, fieldnames=COLS); w.writeheader(); [w.writerow(r) for r in rows]
write_csv(os.path.join(OUT,"data","items.csv"), items)
quarters = {}
for r in items:
    y,m = r["published"][:4], int(r["published"][5:7]); quarters.setdefault(f"{y}-Q{(m-1)//3+1}",[]).append(r)
for q,rows in quarters.items(): write_csv(os.path.join(OUT,"data",f"{q}.csv"), rows)
print(len(items),"items;", {q:len(r) for q,r in sorted(quarters.items())})
from collections import Counter
print(Counter(r["tag_risk_area"] for r in items)); print(Counter(r["tag_rating"] for r in items)); print(Counter(r["source_type"] for r in items))
