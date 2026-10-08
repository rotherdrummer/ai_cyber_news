"""Build data/benchmarks.json from exported evaluation results plus the Sovereignty Map benchmark sheet (24 Sep 2026)."""
import json, glob, os, sys
OUT=sys.argv[1]
ev={}
for f in glob.glob("db/evidence/*.json"):
    d=json.load(open(f)); d=d.get("data",d)
    if isinstance(d.get("value"),(int,float)): ev.setdefault(d["test"],[]).append(d)
def rows(test, fix=None):
    out=[]
    for e in ev.get(test,[]):
        evalr=e.get("evaluator","")
        if fix: evalr=fix(e) or evalr
        out.append({"model":e["model"],"value":e["value"],"display":e.get("result",""),"date":e["date"],"url":e.get("url",""),
                    "measured_by":evalr,"self_reported":"self-reported" in evalr.lower() or "reported at launch" in evalr.lower(),"weights":"Open" if e.get("weights")=="open" else "Closed"})
    return sorted(out,key=lambda r:-r["value"])
def eb_fix(e):
    return "OpenAI (reported at launch, safeguards off)" if e["model"]=="GPT-6 Astra" else None
SOV="Frontier AI Sovereignty Map, 24 Sep 2026"
tests=[
 {"name":"ExploitBench","category":"Offensive cyber","run_by":"Carnegie Mellon University (Seunghyun Lee and Prof. David Brumley)",
  "what":"How far an AI agent gets in building working exploits for real, already-patched bugs in Chrome's JavaScript engine, scored across 16 capability steps from reaching the bug to full control.",
  "scored":"% of 16 capability flags","max":100,"rows":rows("ExploitBench",eb_fix)},
 {"name":"SEC-Bench Pro","category":"Offensive cyber","run_by":"Reported by OpenAI","what":"Security engineering tasks including vulnerability finding and exploitation.",
  "scored":"% score","max":100,"rows":rows("SEC-Bench Pro")},
 {"name":"ExploitGym","category":"Offensive cyber","run_by":"Reported by OpenAI","what":"Exploit development tasks in a test environment.","scored":"% success","max":100,"rows":rows("ExploitGym")},
 {"name":"AISI simulated network attack range","category":"Offensive cyber","run_by":"UK AI Security Institute",
  "what":"Whether a model can carry out a 32-step simulated attack on a corporate network from start to finish without help. The range has no active defenders.",
  "scored":"attempts completing all 32 steps, out of 10","max":10,"rows":rows("AISI simulated network attack range")},
 {"name":"AISI unsanctioned supply-chain attacks","category":"Agent behaviour","run_by":"UK AI Security Institute",
  "what":"How often a model, given a task, carries out a software supply-chain attack it was not authorised to perform. Simulated, with the model's cyber safeguards switched off.",
  "scored":"% of simulated runs","max":100,"rows":rows("AISI unsanctioned supply-chain attacks")},
 {"name":"GDPval-AA","category":"General professional work","run_by":"Artificial Analysis (dataset by OpenAI)",
  "what":"Whether a model can produce the documents, spreadsheets and slides real professionals produce, judged blind against experts averaging 14 years in the role. Elo score anchored at 1600; higher is better.",
  "scored":"Elo (1600 = anchor)","max":None,"scale":[1400,1900],
  "rows":[{"model":m,"value":v,"display":str(v),"date":"2026-09-24","url":"https://artificialanalysis.ai/","measured_by":"Artificial Analysis","self_reported":False,"weights":"Closed","note":SOV}
          for m,v in [("Claude Opus 5.5",1846),("Claude Fable 5.1",1735),("Claude Opus 5",1708),("Grok 4.7",1695),("Muse Spark 1.3",1674),("GPT-5.6 Sol",1588),("GPT-6 Astra",1542),("GPT-6 Sol",1487),("Gemini 3.8 Flash",1412)]]},
 {"name":"HealthBench Professional","category":"Clinical","run_by":"OpenAI (published April 2026); leaderboard maintained by Arcophos",
  "what":"Physician-graded performance on 525 real clinician tasks: consults, documentation and research. Physician-written answers score 0.437 against the same rubrics.",
  "scored":"0 to 1 rubric agreement","max":1,"baseline":0.437,"baseline_label":"physicians",
  "rows":[{"model":m,"value":v,"display":f"{v:.3f}","date":"2026-09-24","url":"","measured_by":"Arcophos leaderboard","self_reported":False,"weights":"Closed","note":SOV}
          for m,v in [("Claude Fable 5",0.660),("GPT-6 Astra",0.634),("Claude Fable 5.1",0.621),("GPT-5.6 Sol",0.605),("Claude Opus 5",0.598)]]},
]
caveats=[
 {"title":"Configuration is half the score","text":"Reasoning effort, tool access and agent scaffolds change results more than model choice does. A score without its configuration is not comparable."},
 {"title":"Lab model is not the shipped model","text":"Cyber scores are usually measured on unrestricted internal builds. Products on sale are deliberately weaker, so lab figures overstate what a customer gets and understate what an attacker with open weights gets."},
 {"title":"Self-reported results","text":"Results a developer reports about its own model are marked. They are not independently checked and may not match the benchmark owner's scoring."},
 {"title":"None of them measure your risk","text":"No benchmark covers data residency, supply chain, model provenance or clinical safety in service. Benchmarks narrow a shortlist; they are not assurance."},
]
json.dump({"updated":max(r["date"] for t in tests for r in t["rows"]),"tests":tests,"caveats":caveats},open(os.path.join(OUT,"data","benchmarks.json"),"w"),ensure_ascii=False,indent=1)
import csv
with open(os.path.join(OUT,"data","benchmarks.csv"),"w",newline="",encoding="utf-8-sig") as fh:
    w=csv.writer(fh); w.writerow(["benchmark","category","model","result","value","date","measured_by","self_reported","url"])
    for t in tests:
        for r in t["rows"]: w.writerow([t["name"],t["category"],r["model"],r["display"],r["value"],r["date"],r["measured_by"],"Yes" if r["self_reported"] else "No",r["url"]])
print({t["name"]:len(t["rows"]) for t in tests})
