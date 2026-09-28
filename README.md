# PFDA Assignment — UNSW NB15 Network Traffic Analysis

**Module:** CT127-3-2-PFDA — Programming For Data Analysis
**University:** Asia Pacific University (APU)
**Hand Out:** 1 November 2025 | **Hand In:** 6 December 2025 | **Weightage:** 50%
**Language:** R (RStudio)
**Group:** Group Work (4 members)

---

## Project Overview

This is a group assignment for PFDA. The task is to analyze the **UNSW NB15 network traffic dataset** — a comprehensive collection of network flow records labeled as normal or various attack types. The goal is to perform data import, preparation, exploratory data analysis, and hypothesis testing using R programming.

## Assignment Brief Summary

- **Coursework Title:** Cyber intrusion detection and classification
- **Type:** Group Assignment (4 members)
- **Deliverables:** RScript (source code) + 6500-word report
- **Requirements:**
  - R program must compile and execute without errors
  - Cleaning and pre-processing must be done in R using scripting (no Excel/OpenRefine)
  - No duplication allowed in the dataset
  - Good programming practices: comments, variable naming, indentation
  - Each objective starts on a separate page with student name
  - Extra features in separate page with explanation

## Dataset: UNSW NB15

The UNSW NB15 dataset is a network intrusion detection dataset created by the Australian Centre for Cyber Security (ACSC). It contains **175,341 network flow records** with **49 features**.

### Key Features

| Category | Features |
|----------|----------|
| **Identities** | srcip, sport, dstip, dsport |
| **Protocol** | proto, service, state |
| **Traffic** | dur, sbytes, dbytes, spkts, dpkts, rate |
| **Timing** | sttl, dttl, sload, dload, sloss, dloss |
| **TCP** | swin, dwin, stcpb, dtcpb, tcprtt, synack, ackdat |
| **Jitter** | sjit, djit |
| **HTTP** | trans_depth, res_bdy_len, ct_flw_http_mthd |
| **FTP** | is_ftp_login, ct_ftp_cmd |
| **Connections** | ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm |
| **Label** | attack_cat (Fuzzers, Analysis, Backdoors, DoS Exploits, Generic, Reconnaissance, Shellcode, Worms), label (0=Normal, 1=Attack) |

### Attack Categories

- Fuzzers — Malformed packets to crash services
- Analysis — Reconnaissance and probing
- Backdoors — Remote access tools
- DoS Exploits — Denial of service attacks
- Generic — Generic attacks
- Reconnaissance — Network scanning
- Shellcode — Code injection attempts
- Worms — Self-propagating malware

## R Code Included

**PFDA_Analysis.R** — Complete R script covering:

1. **Data Import and Description** — Load CSV, display structure, summary statistics
2. **Data Preparation** — Missing values, duplicate removal, type conversion, categorical validation, negative value checks
3. **Exploratory Data Analysis** — Attack category distribution, protocol distribution, service distribution, label distribution
4. **Hypothesis Testing** — T-tests, ANOVA, chi-square tests for normal vs attack differences
5. **Visualization** — Bar plots, pie charts, boxplots, scatter plots (saved to plots/ folder)
6. **Feature Analysis** — Correlation matrix, top correlations with label
7. **Data Validation** — Final checks, cleaned dataset export

## File Structure

```
PFDA Assignment/
├── PFDA_Analysis.R              # R script for analysis (MAIN DELIVERABLE)
├── 5. UNSW_NB15.csv             # Main dataset (175K records)
├── 5. UNSW_NB15 - Copy.csv      # Dataset backup
├── 6. NUSW-NB15_features.csv    # Feature descriptions
├── 1. Assignment question.pdf   # Full assignment brief
├── Assignment Report Template(1).docx  # Report structure template
├── CustomerSQL.sql              # SQL scripts
└── README.md                    # This file
```

## Group Work Note

This is a **group project** for CT127-3-2-PFDA with 4 members. Each member is responsible for their own analysis section in the report. The workload matrix in the final report specifies each member's assigned columns and contributions.

---

*Repository created for academic portfolio purposes.*
