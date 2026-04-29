# Data Science for Cyber Security — Full Assessment Specification
**Module Code:** UFCE8B-30-3 | **Module Title:** Data Science for Cyber Security
**Module Leader:** Ahsan Ikram | **Module Tutors:** Ahsan Ikram, Andrew McCarthy
**Year:** 2025-26

---

## General Assessment Brief

| Field | Details |
|---|---|
| Assessment Title | Data Science Portfolio |
| Assessment Type | Portfolio |
| Assessment Weighting | 100% of total module mark |
| Size / Length | 3000-words or equivalent |
| Submission Deadline | Before **14:00 on 07/05/2026** |
| Late Submission | Eligible for 48-hour late submission window |
| Marks & Feedback Due | 20 working days after the submission window date |
| Marks & Feedback Via | Blackboard |

### Module Learning Outcomes

1. To demonstrate understanding of programming for the purposes of data science in cyber security.
2. To demonstrate practical skills of gathering, processing and analysing data to solve cyber security challenges.
3. To reflect upon techniques and methods used and evaluate their performance.

### Use of AI

Generative AI tools may be used in an **assistive role only** for:
- Drafting and structuring content (**excluding** software or coding content).
- Supporting a particular process such as translating content.
- Providing ideas or inspiration to help overcome a creative block.

GenAI may suggest topics/content, but you must always locate and critically engage with actual literature/research/evidence yourself. If you use GenAI, you **must** acknowledge its use.

### Submission Format

Submit a **zipped (compressed) file** via Blackboard containing:
1. A completed coversheet.
2. A sub-folder for each portfolio task (each folder must contain all relevant data and materials needed to run/validate the completed tasks).
3. A video file (or URL) demonstrating the working and execution of the completed tasks.

### Portfolio Overview

| Task | Description | Week Released |
|---|---|---|
| 01 | **Data Quality Pipeline Task:** Create a data quality pipeline including data acquisition, data validation, data cleaning, and at least two analyses and visualisations. Optional transformations for advanced phases. | Week 4 |
| 02 | **Machine Learning Task:** Comparatively analyse and select a machine learning model to solve a cyber security case study (e.g. phishing, bullying, intrusion). | Week 8 |
| 03 | **Threat/Anomaly Analysis Task:** Create an experimental proof of concept for applying data analytics to malware analysis. | Week 12 |
| 04 | **Security Monitoring Dashboard:** Select and apply data science metrics to a cyber security case study and prepare a monitoring dashboard for real-time analysis. | Week 16 |

### Marking Criteria (Overall)

| Grade Band | Mark | Descriptor |
|---|---|---|
| Outstanding | 86–100 | All tasks completed to a high standard; results verified and validated; structured, executable codebase; performance metrics considered throughout. |
| Excellent | 70–85 | All tasks mostly completed; results mostly verified; codebase structured and executable; performance metrics partially considered. |
| Very Good | 60–69 | Most tasks completed; results occasionally verified; codebase partially structured and executable. |
| Good | 50–59 | At least half of tasks completed; results rarely verified; codebase rarely structured. |
| Adequate | 40–49 | Less than half of tasks completed; results not verified; codebase not structured. |
| Inadequate | 0–40 | Tasks barely attempted; results unclear; codebase not working. |

**Component Weightings:**
- Accuracy & Completeness: **80%** (20% per portfolio task)
- Video Demonstration: **15%**
- Presentation, Citations & References: **5%**

### Passing the Module

You need to show evidence of attempting and completing **at least half** of the portfolio tasks to a good standard to pass.

---

## Task 1 — Data Quality Pipeline

**Weighting:** 20% | **Date Issued:** 24/10/2025

### Scenario

You are a cyber security analyst building a data analysis pipeline to train and test a packet classifier. You have acquired a labelled network traffic dataset with **47 network features** per packet (source IP, source port, protocol, etc.). The data has two class label columns: one labelling malicious packets by attack type (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms) and one labelling data as benign/malicious.

Before training a machine learning model, you will run descriptive and exploratory analysis focused on cleaning the data — identifying and fixing missing, incomplete, and inaccurate values.

**Dataset:** `task1.csv` (Available on Blackboard)
**Tool:** Python + Jupyter Notebook (required)
**Deliverable:** A single Jupyter Notebook.

### Sub-tasks & Marks

| # | Task | Marks |
|---|---|---|
| 1 | Load the dataset; find and print the total number of rows and columns. | 2 |
| 2 | Run exploratory analysis; print a summary of missing values across all columns. Fix missing values using an interpolation method. | 3 |
| 3 | Investigate the source and destination IP columns for incomplete or inaccurate IPs. Create a bar chart showing the number of errors, missing, and correct values. | 6 |
| 4 | `Stime` and `Ltime` show two timestamps per row (described in `features.csv`). Investigate whether these columns have missing or inaccurate values; provide a fix and print evidence on screen. | 4 |
| 5 | Find the percentage of malicious vs. benign packets in the sample. (Hint: malicious packets are labelled by attack type in one of the columns.) | 2 |
| 6 | Visualise the number of packets per attack type in an appropriate chart to evaluate the distribution/share of each attack type. | 3 |
| **Total** | | **20** |

---

## Task 2 — Machine Learning (Misinformation Analysis)

**Weighting:** 25% | **Date Issued:** 24/11/2025

### Scenario

You are a cyber security data analyst consulting law enforcement to establish a timeline of events and track the spread of misinformation, in order to create an attacker profile following an incident. One dataset is a dump of social media posts around the time of the incident. Some content appears to be targeted misinformation campaigns.

**Dataset:** `fake_news.csv` (Available on Blackboard)
**Note:** Use `on_bad_lines='skip'` in `read_csv`.
**Tool:** Python + Jupyter Notebook (required)
**Deliverable:** A single Jupyter Notebook.

### Dataset Description (20 Columns)

| # | Column | # | Column |
|---|---|---|---|
| 1 | id | 11 | domain_rank |
| 2 | intext content | 12 | thread_title |
| 3 | language | 13 | spam_score |
| 4 | language of the article | 14 | main_img_url |
| 5 | crawled | 15 | replies_count |
| 6 | crawled from where | 16 | participants_count |
| 7 | site_url | 17 | likes |
| 8 | site source | 18 | comments |
| 9 | country | 19 | shares |
| 10 | country name | 20 | type |

### Sub-tasks & Marks

| # | Task | Marks |
|---|---|---|
| 1 | Prepare a correlation matrix for all numerical columns. Identify the top three strongest correlated column pairs. Print a summary. | 3 |
| 2 | Apply linear regression to the correlated columns identified in (1). Present regression lines with clearly labelled visualisations. | 6 |
| 3 | Extract all data labelled `conspiracy`, `hate`, and `satire` (from the `type` column). Train an appropriate Naïve Bayes classifier (80–20 train-test split). Test accuracy with five samples from each type. | 6 |
| 4 | Using the `author`, `shares`, `type`, and `title` columns for `hate`, `satire`, and `junksci` data items, create a **node-link graph** where: `author` and `title` are nodes; titles are connected to authors; node shape/icon represents `type`; node size/colour represents `shares` on a calculated scale (e.g. 0–100, 100–500, 500–1000). | 6 |
| 5 | Using the `text` column for `bias` and `conspiracy` rows: prepare data by removing stopwords, applying tokenisation and lemmatisation; then prepare word clouds for both categories. | 4 |
| **Total** | | **25** |

---

## Task 3 — Threat/Anomaly Analysis (Malware Analysis)

**Weighting:** 20% | **Date Issued:** 16/02/2026

### Scenario

You are a cyber security analyst consulting for a private company that has been subject to various phishing attacks. You have quarantined sample files from prospective phishing emails and links, and you will investigate them using Python and data science techniques related to malware analysis.

**Sample Files:** `File1.task3`, `File2.task3`, `File3.task3`, `dataset_task3.csv`, `readme.txt` (Available on Blackboard)
**File Format:** All files are in Windows Portable Executable (PE) format.
**Tool:** Python + Jupyter Notebook (required)
**Deliverable:** A single Jupyter Notebook.

### Sub-tasks & Marks

| # | Task | Marks |
|---|---|---|
| 1 | Print all Section headers for each file. | 2 |
| 2 | Print all imported libraries for each file. | 2 |
| 3 | Print a summary of all string features of length four or more characters (e.g. total count, average length, frequency, etc.). | 4 |
| 4 | Create a list of the following suspicious imports: `GetProcAddress`, `CreateRemoteThread`, `TerminateProcess`, `VirtualAlloc`, `WriteProcessMemory`. Write a script to check if these calls exist in a sample file. If a file has **more than 50% matches**, classify it as malicious. | 4 |
| 5 | Using the training data in `dataset_task3.csv`: train and test a **Decision Tree** and a **Neural Network** model; compare the accuracy of the two models. (The `readme.txt` file contains brief descriptions of the features.) | 8 |
| **Total** | | **20** |

---

## Task 4 — Security Monitoring Dashboard

**Weighting:** 20% | **Date Issued:** 16/02/2026

### Scenario

You are a cyber security analyst consulting for a **financial organisation**. Their recent risk assessment indicates a higher than usual threat of a malware attack, and they have decided to be proactive and improve their defences.

One focus area is the development of a **real-time visualisation dashboard**. The first prototype aims to monitor:

1. **Network Traffic** (throughput, protocol, source, etc.)
2. **Endpoints** (current issues, OS version, firewall status, etc.)
3. **Data Backups** (backup coverage, backup encryption, backup validation, etc.)
4. **Staff Readiness and Awareness** (pending training, job role risk profile, current risk profile, etc.)

**Sample Files:** None provided — generate dummy data.
**Tool:** Python (required)
**Deliverable:** A document (data collection plan) + a Python dashboard prototype.

### Deliverable 1 — Data Collection Plan (Document)

Provide a structured table of suggestions for what data should be collected. The table must include:

| Column | Description |
|---|---|
| Category | e.g. Network, Endpoint, Staff Readiness |
| Subcategory | e.g. Protocol, Staff PC, Current Profile |
| Metric / Format | e.g. Text, 3-scale (low-medium-high) |
| Frequency | e.g. Real-time, 10 min, 3 months |
| Collection Mode | e.g. Automated, Manual |
| Collection Mechanism | e.g. Network tap, SNMP trap, HR records |
| Recorded At | e.g. Gateway router, Host machines, HR system |
| Storage | e.g. CSV file, Excel file |

**Example rows:**

| Category | Subcategory | Metric / Format | Frequency | Collection Mode | Collection Mechanism | Recorded At | Storage |
|---|---|---|---|---|---|---|---|
| Network | Protocol | Text | Real-time | Automated | Network tap | Gateway router | CSV file |
| Endpoint | Staff PC | Text | 10 min | Automated | SNMP trap | Host machines | CSV file |
| Staff readiness | Current Profile | 3-scale (low-medium-high) | 3 months | Manual | HR records | HR system | Excel file |

### Deliverable 2 — Python Dashboard Prototype

- You do **not** need real data — generate **5–10 rows of dummy data**.
- The dashboard must use **at least two input files** (CSV, text, Excel, or database table).
- Focus on **usability and user experience**: layout selection, chart selection, placement of important information, fonts, colours, separators, etc.

### Sub-tasks & Marks

| # | Task | Marks |
|---|---|---|
| 1 | Three identified data metrics each, for: network traffic monitoring, endpoints monitoring, data backups monitoring, and staff readiness monitoring. | 4 |
| 2 | Prototype dashboard using at least two input files and **six charts**. | 8 |
| 3 | At least one **geo-spatial visualisation** (counted within the six charts in part 2). | 2 |
| 4 | At least one **interactive visualisation** (counted within the six charts in part 2). Choose an appropriate interaction e.g. data filter, layout change, auto-refresh, etc. | 2 |
| 5 | Effective **layout and design** of the dashboard. | 4 |
| **Total** | | **20** |

---

## Assessment Cover Sheet

**Module:** UFCE4B-30-3 Data Science for Cyber Security
**Assessment:** Data Science Portfolio Submission

| Field | Value |
|---|---|
| Student Number | *(fill in)* |
| Student Name | *(fill in)* |

### Submission Checklist

Submit the following:
1. This completed cover sheet.
2. A zipped folder containing four sub-folders titled `Task 1`, `Task 2`, `Task 3`, and `Task 4`. Each sub-folder must contain all files related to that task.

### File Manifest

| Task | Files Submitted | Special Instructions |
|---|---|---|
| Task-1 Folder | *(list files)* | *(e.g. run instructions)* |
| Task-2 Folder | *(list files)* | *(e.g. run instructions)* |
| Task-3 Folder | *(list files)* | *(e.g. run instructions)* |
| Task-4 Folder | *(list files)* | *(e.g. run instructions)* |
| Video Demo | *(file or URL)* | |
