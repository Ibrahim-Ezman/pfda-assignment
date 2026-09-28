# PFDA Assignment — UNSW NB15 Network Traffic Analysis

**Module:** CT127-3-2-PFDA — Programming For Data Analysis
**University:** Asia Pacific University (APU)
**Hand Out:** 1 November 2025 | **Hand In:** 6 December 2025 | **Weightage:** 50%
**Language:** R (RStudio)
**Group:** Group Work (5 members — Group 16)

---

## Project Overview

Group assignment for PFDA: analyze the **UNSW NB15 network traffic dataset** — 175,341 network flow records with 49 features, labeled as normal or various attack types. Deliverables: RScript + 6500-word report.

## Assignment Brief

- R program must compile and execute without errors
- Cleaning and pre-processing in R (no Excel/OpenRefine)
- No duplication allowed
- Good programming practices: comments, variable naming, indentation
- Each objective starts on a separate page with student name
- Extra features in separate page with explanation

## Dataset: UNSW NB15

**175,341 records**, 49 features. Attack categories: Fuzzers, Analysis, Backdoors, DoS Exploits, Generic, Reconnaissance, Shellcode, Worms.

### Key Features

| Category | Features |
|----------|----------|
| Identities | srcip, sport, dstip, dsport |
| Protocol | proto, service, state |
| Traffic | dur, sbytes, dbytes, spkts, dpkts, rate |
| Timing | sttl, dttl, sload, dload, sloss, dloss |
| TCP | swin, dwin, stcpb, dtcpb, tcprtt, synack, ackdat |
| Jitter | sjit, djit |
| HTTP | trans_depth, res_bdy_len, ct_flw_http_mthd |
| FTP | is_ftp_login, ct_ftp_cmd |
| Connections | ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm |
| Label | attack_cat, label (0=Normal, 1=Attack) |

## 🎯 MY CONTRIBUTION: Member 4 — Ibrahim Bin Mohd Ezman (TP081387)

I implemented **Objective 1** and **Objective 2** in the R script:

### Objective 1: Duration and Cyber Attacks
- Analysis 1-1: Distribution of duration for normal vs attack traffic
- Analysis 1-2: Difference in average duration between normal and attack connections

### Objective 2: Network Protocols and Attack Occurrence
- Analysis 2-1: Which protocols are most commonly used in attack traffic vs normal traffic
- Analysis 2-2: Attack rate for different protocol types

## R Script Structure (1060 lines)

| Member | Student | Objectives |
|--------|---------|------------|
| Member 1 | Yu Sakuma (TP074909) | Objective 1: SLOAD & DLOAD |
| Member 2 | I Nyoman Baynanda Sutama (TP084160) | Objective 2: SBYTES & DBYTES + ML Classification |
| Member 3 | Taichi Sasaki (TP074942) | Objective 3: ct_srv_dst & attack_cat |
| **Member 4** | **Ibrahim Bin Mohd Ezman (TP081387)** | **Objective 4: Duration & Attacks + Objective 5: Protocols** |
| Member 5 | Akhmad Ali Rafi (TP077577) | Objective 5: SPKTS & DPKTS |

*Note: Member 4 and 5 sections overlap in the original file — Ibrahim contributed Objective 4 (Duration) and Objective 2 (Protocols).*

## File Structure

```
PFDA Assignment/
├── PFDA_Analysis.R              # R script (1060 lines, Group 16)
├── 5. UNSW_NB15.csv             # Main dataset (175K records)
├── 6. NUSW-NB15_features.csv    # Feature descriptions
├── 1. Assignment question.pdf   # Full assignment brief
└── README.md                    # This file
```

## Group Work Note

This is a **group project** for CT127-3-2-PFDA (5 members, Group 16). Each member owns specific objectives in the R script and report sections.

---

*Repository created for academic portfolio purposes.*
