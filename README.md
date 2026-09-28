# PFDA Assignment — UNSW NB15 Network Traffic Analysis

**CT127-3-2-PFDA | R | Group project**

Analyzing 175K network flow records to distinguish normal vs attack traffic using the UNSW NB15 dataset.

## My part: Member 4 — Duration & Protocol Analysis

**Objective 1 — Duration vs attacks:**
- Distribution of connection duration for normal vs attack traffic
- Is there a significant difference in average duration?

**Objective 2 — Protocols vs attacks:**
- Which protocols are most common in attack traffic?
- Attack rate by protocol type

**Data cleaning done:** missing values, outliers (kept), duplicates removed, data types, inconsistent protocol entries (empty/"-" → "unknown"), negative/zero duration checks

**3 charts:** duration histogram (normal=green/attack=red), duration boxplot, protocol distribution stacked bar (proportional by attack status)

## Files
- `PFDA_Analysis.R` — full group script (Ibrahim = Member 4)
- `data/UNSW_NB15.csv` — dataset (175K records, 49 features)
- `data/UNSW_NB15_features.csv` — feature descriptions
- `docs/assignment-brief.pdf` — brief
