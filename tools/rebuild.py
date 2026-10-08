"""Rebuild every derived file from the master JSON in data/.

Master files (edited by hand or by the daily update):
  data/items.json       news items         -> items.csv, period-YYYY-MM.csv, periods.json
  data/models.json      frontier models    -> models.csv
  data/benchmarks.json  benchmark results  -> benchmarks.csv
  data/regulation.json  regulatory table   -> regulation.csv
  data/sources.json     sources and change log (no CSV)

For each item, blank fields are filled in (id, source_relation, source_category,
tag_risk_area, tag_themes, tag_rating, tag_rating_reason). Fields already set are kept,
so a hand correction is never overwritten. reporting_period is always recomputed.

Run from the repo root:  python3 tools/rebuild.py
Exits non-zero, writing nothing, if any item fails validation.
"""
import csv, datetime, hashlib, json, os, sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
TODAY = datetime.date.today().isoformat()

COLS = ["id","published","reporting_period","collected","item_type","title","publisher","url","source_relation",
        "source_category","source_says","key_findings","evidence_links","health_named","tag_risk_area","tag_themes",
        "tag_rating","tag_rating_reason","related_ids"]
ITEM_TYPES = ["Report","Publication","Research","Model or capability","Policy","Incident","Threat finding","Evaluation result","Other"]

# ---------- source labels ----------
ORIGINAL_HOSTS = ["aisi.gov.uk","ncsc.gov.uk","gov.uk","anthropic.com","openai.com","cloud.google.com","deepmind.google",
                  "metr.org","mitre.org","parliament.uk"]
THIRD_PARTY_HINTS = ["wikipedia.org","llm-stats.com","local-ai-zone","securityaffairs","lexisnexis","law-ai.org",
                     "addleshawgoddard","qualio","ukauthority","infoworld","epoch.ai","digitalapplied","benchlm","axios.com"]
SOURCE_CATEGORIES = [
 ("UK government", ["aisi.gov.uk","ncsc.gov.uk","gov.uk","parliament.uk"]),
 ("AI developer", ["anthropic.com","openai.com","cloud.google.com","deepmind.google"]),
 ("Independent evaluator", ["metr.org","mitre.org","epoch.ai"]),
 ("Legal and policy analysis", ["law-ai.org","addleshawgoddard","lexisnexis","qualio","ukauthority"]),
 ("News and model trackers", ["wikipedia.org","securityaffairs","infoworld","axios.com","llm-stats.com","local-ai-zone","digitalapplied","benchlm"]),
]
def source_relation(url):
    u = (url or "").lower()
    if any(h in u for h in THIRD_PARTY_HINTS): return "Third-party report"
    host = urlparse(u).netloc
    return "Original source" if any(host.endswith(d) for d in ORIGINAL_HOSTS) else "Third-party report"
def source_category(url):
    u = (url or "").lower()
    for name, keys in SOURCE_CATEGORIES:
        if any(k in u for k in keys): return name
    return "Other"

# ---------- risk area and themes ----------
AREA_RULES = [
 ("Autonomous AI risk", ["unsanctioned","cheating behaviour","multi-agent","attributed to OpenAI's own","Hugging Face","pauses reinforcement",
    "agent behaviour","cover up","Senate on AI agent","secure environment for evaluating","Transect","Control Red Team","lie detectors",
    "preferences predict","Prefill awareness","RealityTest","Item response theory","optimal stopping","pre-deployment evaluation",
    "cancellation of GPT-6.1 Astra","loss of control","self-exfiltrat","sandbag","rogue agent"]),
 ("Secure AI adoption", ["agentic AI services","shadow AI","National Commission","AI Bill","EU AI Omnibus","Resilience Bill","lawsuit",
    "guidance","secure by design","deployment"]),
 ("Cross-cutting", ["DSIT","Taskforce","Germany","Export controls"]),
]
LANDSCAPE = ["DSIT","Taskforce","Germany","National Commission","Government response","Cyber Verification Program","Daybreak","Argon"]
def area(title):
    t = title.lower()
    for a, keys in AREA_RULES:
        if any(k.lower() in t for k in keys): return a
    return "AI-enabled cyber threats"
def themes(title, extra=""):
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
    if any(k in t for k in [" bill"," act ","omnibus","regulat","commission","lawsuit","export controls"]): add("regulation")
    if any(k in t for k in ["supply-chain","supply chain"]): add("supply-chain")
    if any(k in t for k in ["defender","verification program","daybreak","argon"]): add("defender-access")
    if any(k in t for k in ["open-weight","open weight","kimi","deepseek","qwen"]): add("open-weight")
    if any(k in t for k in ["health","nhs","hospital"]): add("health")
    if any(k.lower() in title.lower() for k in LANDSCAPE): add("landscape-change")
    return tags

# ---------- rating (fixed, published criteria) ----------
RAG_CRITERIA = {
 "Red": "Evidence of real-world AI-enabled malicious activity or AI agents acting beyond their sanction; a model rated at a critical cyber threshold; near-complete autonomous exploitation results; or an authoritative warning that the threat has materially changed.",
 "Amber": "A significant change that may matter soon: notable capability gains, new government guidance or warnings, changes to who can access cyber-capable models, or regulatory and institutional changes.",
 "Green": "Background: evaluation methods, general research, routine releases without cyber evidence, and commentary.",
}
RED_KEYS = ["intrusion","breach","Hugging Face","unsanctioned agent","Countering misuse","Threat Tracker","rated Critical",
            "performs unsanctioned supply-chain","accelerating vulnerability discovery","ExploitBench: GPT-6 Astra",
            "AISI unsanctioned supply-chain attacks: GPT-6 Astra","Critical cyber","critical threshold"]
GREEN_KEYS = ["Item response theory","optimal stopping","Transect","Prefill awareness","lie detectors","RealityTest",
              "preferences predict","Control Red Team","lawsuit","Export controls","UK AI Bill","Sonnet 5.5","Mistral Large 4",
              "pre-deployment evaluation","supply-chain attacks: GPT-5.5","Claude Opus 4.7"]
def rag(rec):
    t = rec["title"].lower()
    if rec["item_type"] in ("Incident","Threat finding"): return "Red","Real-world malicious activity or incident"
    if any(k.lower() in t for k in RED_KEYS): return "Red","Material change in threat or agent behaviour"
    if any(k.lower() in t for k in GREEN_KEYS): return "Green","Background"
    return "Amber","Significant change to watch"

# ---------- reporting quarters: Jun-Aug, Sep-Nov, Dec-Feb, Mar-May ----------
MONS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
def reporting_quarter(d):
    y, m = int(d[:4]), int(d[5:7])
    sm = {6:6,7:6,8:6, 9:9,10:9,11:9, 12:12,1:12,2:12, 3:3,4:3,5:3}[m]
    sy = y - 1 if m in (1,2) else y
    em = (sm + 1) % 12 + 1
    ey = sy + 1 if sm == 12 else sy
    label = f"{MONS[sm-1]}-{MONS[em-1]} {ey}" if sy == ey else f"{MONS[sm-1]} {sy}-{MONS[em-1]} {ey}"
    return f"{sy}-{sm:02d}", label

def pid(url, title):
    return "wf-" + hashlib.sha1(f"{url}|{title}".encode()).hexdigest()[:10]

def valid_date(s):
    try: datetime.date.fromisoformat(s); return True
    except Exception: return False

def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # BOM so Excel reads UTF-8
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for r in rows: w.writerow(r)

def main():
    doc = json.load(open(os.path.join(DATA, "items.json"), encoding="utf-8"))
    errors, items, seen = [], [], set()
    for i, r in enumerate(doc["items"]):
        for c in COLS: r.setdefault(c, "")
        for c in ("title","url","published"):
            if not str(r[c]).strip(): errors.append(f"item {i} ({r.get('title','?')[:50]}): missing {c}")
        if not (r["source_says"].strip() or r["key_findings"].strip()):
            print(f"warning: item {i} ({r['title'][:50]}) has no summary")
        if r["url"] and not r["url"].startswith("https://"): errors.append(f"item {i}: url must be https")
        if "claude.ai" in r["url"]: errors.append(f"item {i}: url points at claude.ai")
        if r["published"] and not valid_date(r["published"]): errors.append(f"item {i}: bad published date {r['published']}")
        if r["item_type"] not in ITEM_TYPES: r["item_type"] = "Other"
        r["id"] = r["id"] or pid(r["url"], r["title"])
        r["collected"] = r["collected"] or TODAY
        r["source_relation"] = r["source_relation"] or source_relation(r["url"])
        r["source_category"] = r["source_category"] or source_category(r["url"])
        r["health_named"] = r["health_named"] or ("Yes" if any(k in (r["title"]+r["source_says"]).lower() for k in ["health","hospital","nhs"]) else "No")
        r["tag_risk_area"] = r["tag_risk_area"] or area(r["title"])
        r["tag_themes"] = r["tag_themes"] or ";".join(themes(r["title"], r["source_says"]))
        if not r["tag_rating"]: r["tag_rating"], r["tag_rating_reason"] = rag(r)
        key = (r["url"], r["title"].strip().lower())
        if r["id"] in seen or key in seen: continue
        seen.add(r["id"]); seen.add(key); items.append({c: r[c] for c in COLS})
    if errors:
        print("Validation failed, nothing written:"); [print(" -", e) for e in errors]; sys.exit(1)

    items.sort(key=lambda r: (r["published"], r["title"]), reverse=True)
    quarters = {}
    for r in items:
        k, label = reporting_quarter(r["published"]); r["reporting_period"] = label
        quarters.setdefault(k, {"label": label, "rows": []})["rows"].append(r)

    meta = doc.get("meta", {})
    meta.update({"updated": TODAY, "item_count": len(items), "rating_criteria": RAG_CRITERIA})
    json.dump({"meta": meta, "items": items}, open(os.path.join(DATA, "items.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    write_csv(os.path.join(DATA, "items.csv"), COLS, items)
    for k, v in quarters.items(): write_csv(os.path.join(DATA, f"period-{k}.csv"), COLS, v["rows"])
    json.dump([{"key": k, "label": v["label"], "file": f"data/period-{k}.csv", "items": len(v["rows"])}
               for k, v in sorted(quarters.items(), reverse=True)], open(os.path.join(DATA, "periods.json"), "w"), indent=1)

    models = json.load(open(os.path.join(DATA, "models.json"), encoding="utf-8"))["models"]
    mcols = list(dict.fromkeys(k for m in models for k in m))
    write_csv(os.path.join(DATA, "models.csv"), mcols, models)

    regs = json.load(open(os.path.join(DATA, "regulation.json"), encoding="utf-8"))["frameworks"]
    write_csv(os.path.join(DATA, "regulation.csv"),
              ["name","sub","what","legal","risk","applies","focus","owner","teeth","ai","status","statusDate","statusUrl"], regs)

    bench = json.load(open(os.path.join(DATA, "benchmarks.json"), encoding="utf-8"))
    bench["updated"] = max([r["date"] for t in bench["tests"] for r in t["rows"]] or [bench.get("updated", "")])
    json.dump(bench, open(os.path.join(DATA, "benchmarks.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    rows = [{"benchmark": t["name"], "category": t["category"], "model": r["model"], "result": r["display"], "value": r["value"],
             "date": r["date"], "measured_by": r["measured_by"], "self_reported": "Yes" if r["self_reported"] else "No", "url": r["url"]}
            for t in bench["tests"] for r in t["rows"]]
    write_csv(os.path.join(DATA, "benchmarks.csv"),
              ["benchmark","category","model","result","value","date","measured_by","self_reported","url"], rows)

    print(f"{len(items)} items;", {v['label']: len(v['rows']) for k, v in sorted(quarters.items())},
          f"| {len(models)} models | {len(regs)} frameworks | {len(rows)} benchmark results")

if __name__ == "__main__":
    main()
