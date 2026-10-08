"""Build reference data (frontier models by jurisdiction, regulatory landscape) from the exported store."""
import json, glob, os, csv, sys
DB = os.path.join(os.path.dirname(__file__), "db"); OUT = sys.argv[1]
def load(p):
    d = json.load(open(p)); return d.get("data", d)
def clean_url(u): return u if isinstance(u,str) and u.startswith("https://") and "claude.ai" not in u else ""
models=[]
for f in sorted(glob.glob(os.path.join(DB,"models","*.json"))):
    m=load(f); mid=os.path.basename(f)[:-5]
    models.append({"id":mid,"name":m.get("name",""),"developer":m.get("lab",""),"jurisdiction":m.get("jurisdiction","Other"),
      "weights":"Open" if m.get("weights")=="open" else "Closed","released":m.get("released",""),"access":m.get("access",""),
      "tier":m.get("tier",""),"cyber_evidence":m.get("cyber",""),"evidence_url":clean_url(m.get("evidenceUrl","")),"updated":m.get("updated","")})
regs=[]
for f in sorted(glob.glob(os.path.join(DB,"regulation","*.json"))):
    r=load(f); r["id"]=os.path.basename(f)[:-5]; r["statusUrl"]=clean_url(r.get("statusUrl","")); regs.append(r)
regs.sort(key=lambda r:r.get("order",0))
notes=[
 {"title":"Region hosting is not sovereignty","text":"US law (including the CLOUD Act) can compel a US-parent company to produce data wherever its servers are. A UK or EU region gives data residency, not jurisdictional control."},
 {"title":"What actually removes that reach","text":"Keeping inference inside your own boundary: open weights on your own hardware, or a domestic sovereign model. Zero-retention terms and cloud data boundaries reduce exposure but remain a US stack."},
 {"title":"Where the open-weight frontier sits","text":"Most leading open-weight models now come from Chinese developers. Self-hosting gives control of the model, not of its supply chain."},
]
os.makedirs(os.path.join(OUT,"data"),exist_ok=True)
json.dump({"updated":max([m["updated"] for m in models if m["updated"]] or [""]),"notes":notes,"models":models},open(os.path.join(OUT,"data","models.json"),"w"),ensure_ascii=False,indent=1)
json.dump({"updated":max([r.get("statusDate","") for r in regs] or [""]),"frameworks":regs},open(os.path.join(OUT,"data","regulation.json"),"w"),ensure_ascii=False,indent=1)
with open(os.path.join(OUT,"data","models.csv"),"w",newline="",encoding="utf-8-sig") as fh:
    w=csv.DictWriter(fh,fieldnames=list(models[0].keys())); w.writeheader(); [w.writerow(m) for m in models]
cols=["name","sub","what","legal","risk","applies","focus","owner","teeth","ai","status","statusDate","statusUrl"]
with open(os.path.join(OUT,"data","regulation.csv"),"w",newline="",encoding="utf-8-sig") as fh:
    w=csv.DictWriter(fh,fieldnames=cols,extrasaction="ignore"); w.writeheader(); [w.writerow(r) for r in regs]
print(len(models),"models;",len(regs),"frameworks")
for r in regs: print(r["name"],"|",r.get("status","")[:90],"|",len(r.get("changes",[])),"changes")
