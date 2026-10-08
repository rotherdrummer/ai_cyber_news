# Watchfloor public dataset

A public-source dataset of AI and cyber security intelligence, and a static dashboard over it. Public sources only. Not an official product of any organisation.

## Files

| File | What it is |
| --- | --- |
| `index.html` | The dashboard. Reads `data/items.json`. |
| `data/items.json` | Every item, with a `meta` block describing the fields. |
| `data/items.csv` | The same items as CSV (UTF-8 with BOM, opens in Excel). |
| `data/YYYY-Qn.csv` | Items published in that quarter. |

## Fields

Columns describing the source: `id`, `published`, `collected`, `item_type`, `title`, `publisher`, `url`, `source_type` (Primary or Secondary), `source_says`, `key_findings`, `evidence_links`, `health_named`.

Machine-assigned categorisation (not findings): `tag_risk_area`, `tag_themes`, `tag_significant`, `related_ids`.

Risk areas: AI-enabled cyber threats, Autonomous AI risk, Secure AI adoption, Cross-cutting.
