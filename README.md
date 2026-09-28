# PFDA Assignment — UNSW NB15 Network Traffic Analysis

**Module:** CT127-3-2-PFDA — Programming For Data Analysis
**University:** Asia Pacific University (APU)
**Hand Out:** 1 November 2025 | **Hand In:** 6 December 2025 | **Weightage:** 50%
**Language:** Python / R (as per assignment requirements)
**Group:** Group Work (5 members)

---

## Project Overview

This is a group assignment for PFDA. The task is to analyze the **UNSW NB15 network traffic dataset** — a comprehensive collection of network flow records labeled as normal or various attack types. The goal is to perform data import, preparation, exploratory data analysis, and hypothesis testing.

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

## Assignment Structure (Group Work)

The report template follows this structure:

1. **Introduction (group work)** — Data import and description, assumptions
2. **Student sections** — Objectives, Data Preparation, EDA, Hypothesis Testing, Conclusion (each student has their own section)
3. **Overall Conclusion (group work)** — Group hypothesis, overall conclusion, limitations
4. **Workload Matrix** — Member responsibilities

### What Each Student Does
- Max 3 objectives per student
- Data preparation (missing values, outliers, duplicates, data types, inconsistencies)
- EDA with summary statistics and 1–2 charts per objective
- Formulate and test 1 hypothesis per objective
- Conclusion per section

## Analysis Approach

### Data Preparation
- Check and handle missing values
- Detect and handle outliers
- Remove duplicates
- Check data types
- Handle inconsistent categorical entries
- Check for negative/zero values
- Normalize/scale where needed
- Final validation

### Exploratory Data Analysis
- Summary statistics per objective
- Visualizations: distribution plots, correlation heatmaps, attack category breakdowns
- Feature importance analysis

### Hypothesis Testing
- Formulate null/alternative hypotheses per objective
- Statistical tests (t-test, chi-square, ANOVA as appropriate)
- Interpret results with APA referencing

## File Structure

```
PFDA Assignment/
├── 1. Assignment question.pdf     # Full assignment brief
├── 2. APU Assignment Cover.doc    # Cover page template
├── Assignment Report Template(1).docx  # Report structure template
├── 5. UNSW_NB15.csv              # Main dataset (175K records)
├── 6. NUSW-NB15_features.csv     # Feature descriptions
└── CustomerSQL.sql               # SQL scripts
```

## Group Work Note

This is a **group project** for CT127-3-2-PFDA with 5 members. Each member is responsible for their own analysis section in the report. The workload matrix in the final report specifies each member's assigned columns and contributions.

---

*Repository created for academic portfolio purposes.*
