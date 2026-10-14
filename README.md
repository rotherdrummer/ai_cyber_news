# AI Cyber News public dataset

A public-source dataset of AI and cyber security intelligence, and a static dashboard over it. Public sources only. Not an official product of any organisation.

## Files

| File | What it is |
| --- | --- |
| `index.html` | The dashboard. Reads `data/items.json`. |
| `data/items.json` | Every item, with a `meta` block describing the fields. |
| `data/items.csv` | The same items as CSV (UTF-8 with BOM, opens in Excel). |
| `data/period-YYYY-MM.csv` | Items in one reporting quarter (Jun–Aug, Sep–Nov, Dec–Feb, Mar–May), named by its first month. Listed in `data/periods.json`. |
| `data/models.json`, `data/models.csv` | Frontier AI models by jurisdiction, weights, access, place in the developer's range (`position`, levels defined under `positions`), the developer's CEO (`developers`) and published cyber evidence. |
| `data/agents.json`, `data/agents.csv` | AI agents and assistants: who makes them, which models they run on, what they can act on, access, and published security evidence. `explainer` holds the model-versus-agent notes shown on the page. |
| `data/benchmarks.json`, `data/benchmarks.csv` | Published benchmark and evaluation results, with who measured them and whether they are self-reported. |
| `data/regulation.json`, `data/regulation.csv` | Regulatory landscape for AI, cyber and digital health assurance, with status and change log. |
| `data/sources.json` | The sources monitored, why each is used, and a log of changes to them. |

## Fields

The item CSVs (`items.csv`, `period-*.csv`) start with `row_number` and `rows_in_file`, so anyone reading the file can check they have read every row.


Columns describing the source: `id`, `published`, `reporting_period`, `collected`, `item_type`, `title`, `publisher`, `url`, `source_relation`, `source_category`, `source_says`, `key_findings`, `evidence_links`, `health_named`.

`source_relation` is **Original source** (published by the organisation that did the work or holds the evidence) or **Third-party report** (reported by someone else; used only where no original was found). `source_category` is one of UK government, AI developer, Independent evaluator, Legal and policy analysis, News and model trackers.

Machine-assigned categorisation (not findings): `tag_risk_area`, `tag_themes`, `tag_rating` (Red, Amber, Green), `tag_rating_reason`, `related_ids`. Rating criteria are in `data/items.json` under `meta.rating_criteria`.

Risk areas: AI-enabled cyber threats, Autonomous AI risk, Secure AI adoption, Cross-cutting.
