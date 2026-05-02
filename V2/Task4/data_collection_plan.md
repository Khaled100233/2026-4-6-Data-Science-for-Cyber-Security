# Data Collection Plan — Financial Organisation Security Monitoring Dashboard

## Introduction

Effective cyber security in a financial organisation depends fundamentally on the systematic, continuous collection of high-quality operational data. Financial institutions are high-value targets for malware campaigns — including ransomware, banking trojans, and advanced persistent threats (APTs) — because of the sensitive customer data, transaction systems, and regulatory obligations they manage. A real-time security monitoring dashboard is only as reliable as the data feeding it: incomplete, delayed, or inaccurate data can mask threats until irreversible damage has occurred.

This data collection plan defines the specific metrics to be gathered across four critical monitoring domains: Network Traffic, Endpoints, Data Backups, and Staff Readiness. For each domain it specifies what data is collected, how frequently, by what mechanism, and where it is stored. The goal is to ensure that the monitoring dashboard has a consistent, trustworthy, and timely data supply that enables rapid detection of anomalies, compliance validation, and informed incident response — all aligned with financial-sector regulatory frameworks such as PCI-DSS, ISO 27001, and the FCA's operational resilience guidelines.

---

## Data Collection Table

| Category | Subcategory | Metric / Format | Frequency | Collection Mode | Collection Mechanism | Recorded At | Storage |
|---|---|---|---|---|---|---|---|
| Network Traffic | Throughput | `throughput_mbps` — float (Mbps) | Every 30 s | Automated | Network tap / NetFlow agent | Firewall / Core switch | Time-series DB (InfluxDB) |
| Network Traffic | Protocol | `protocol` — string (TCP/UDP/ICMP/DNS/HTTP/HTTPS) | Per packet | Automated | Deep Packet Inspection (DPI) probe | Perimeter gateway | SIEM (Splunk / ELK) |
| Network Traffic | Source / Destination | `src_ip`, `dst_ip` — IPv4/IPv6 string | Per connection | Automated | NetFlow v9 / IPFIX collector | Border router | SIEM log index |
| Network Traffic | Packet Size | `packet_size_bytes` — integer | Per packet (sampled 1:100) | Automated | Packet capture agent (libpcap) | Intrusion Detection System | SIEM / raw PCAP archive |
| Network Traffic | Port Numbers | `src_port`, `dst_port` — integer (0–65535) | Per connection | Automated | NetFlow / firewall log | Firewall | SIEM log index |
| Network Traffic | Connection Duration | `connection_duration_s` — float (seconds) | Per session | Automated | Session-tracking firewall | Stateful firewall | SIEM log index |
| Network Traffic | Anomaly Flag | `anomaly_flag` — binary (0/1) | Per connection (real-time) | Automated | ML anomaly detection engine (IDS/NDR) | SIEM / NDR platform | SIEM alert store |
| Network Traffic | Geographic Origin | `src_country`, `src_lat`, `src_lon` — string / float | Per connection | Automated | GeoIP enrichment service (MaxMind) | SIEM enrichment layer | SIEM log index |
| Endpoints | OS Version | `os_version` — string (e.g., "Windows 11 22H2") | Every 4 h | Automated | EDR agent (CrowdStrike / Defender for Endpoint) | Endpoint | Asset management DB |
| Endpoints | Firewall Status | `firewall_status` — enum (Active/Inactive) | Every 15 min | Automated | EDR agent host-telemetry | Endpoint | SIEM / CMDB |
| Endpoints | Antivirus Status | `antivirus_status` — enum (Updated/Outdated/Missing) | Every 15 min | Automated | AV management console (Defender / Sophos) | Endpoint | SIEM / CMDB |
| Endpoints | Patch Level | `patch_level_pct` — float (%) | Daily | Automated | Patch management platform (WSUS / Intune) | Endpoint | Patch management DB |
| Endpoints | Active Processes | `active_processes` — integer | Every 5 min | Automated | EDR agent process telemetry | Endpoint | EDR telemetry store |
| Endpoints | Login Attempts (24 h) | `login_attempts_24h` — integer | Aggregated hourly | Automated | Windows Event Log / Syslog (Event ID 4625) | Domain Controller | SIEM log index |
| Endpoints | Disk Encryption | `disk_encryption` — enum (Enabled/Disabled) | Daily | Automated | BitLocker / FileVault management API | Endpoint | CMDB |
| Endpoints | Active Issues | `active_issues` — integer (open alerts) | Every 15 min | Automated | EDR console API | EDR platform | SIEM / ticketing system |
| Data Backups | Backup Coverage | `coverage_pct` — float (%) | Daily (post-job) | Automated | Backup software API (Veeam / Commvault) | Backup server | Backup management DB |
| Data Backups | Last Backup Timestamp | `backup_date` — ISO 8601 datetime | Per backup job | Automated | Backup scheduler log | Backup server | Backup management DB |
| Data Backups | Encryption Status | `encryption_status` — enum (Encrypted/Unencrypted) | Per backup job | Automated | Backup software configuration report | Backup server | Backup management DB |
| Data Backups | Validation Result | `validation_result` — enum (Pass/Fail) | Daily (post-job) | Automated | Automated restore-test script | Backup server | Backup management DB |
| Data Backups | Backup Type | `backup_type` — enum (Full/Incremental/Differential) | Per backup job | Automated | Backup scheduler log | Backup server | Backup management DB |
| Data Backups | Location | `location` — enum (On-site/Off-site/Cloud) | Per backup job | Automated | Backup software API | Backup server | Backup management DB |
| Data Backups | RTO Compliance | `rto_compliant` — enum (Yes/No) | Daily | Automated | Recovery-time test script vs SLA threshold | Backup server | GRC / ITSM platform |
| Data Backups | Backup Size | `size_gb` — float (GB) | Per backup job | Automated | Backup software API | Backup server | Backup management DB |
| Staff Readiness | Pending Trainings | `pending_trainings` — integer | Daily | Automated | LMS API (Moodle / KnowBe4) | LMS platform | HR / GRC database |
| Staff Readiness | Training Completion % | `training_completion_pct` — float (%) | Daily | Automated | LMS API | LMS platform | HR / GRC database |
| Staff Readiness | Job Role Risk Profile | `risk_profile` — enum (Low/Medium/High) | Quarterly (reviewed) | Manual + Automated | HR system + risk classification model | HR / Risk team | GRC platform |
| Staff Readiness | Days Since Last Training | `days_since_training` — integer | Daily | Automated | LMS API (last completion date delta) | LMS platform | HR / GRC database |
| Staff Readiness | Last Phishing Simulation Result | `last_phishing_result` — enum (Pass/Fail) | Per campaign (monthly) | Automated | Phishing simulation platform (GoPhish / KnowBe4) | Phishing sim server | GRC / HR database |
| Staff Readiness | Phishing Click Rate | `phishing_click_rate_pct` — float (%) | Per campaign (monthly) | Automated | Phishing simulation platform | Phishing sim server | GRC / HR database |
| Staff Readiness | Department | `department` — string | On change | Automated | HR information system (HRIS) sync | HRIS | HR / GRC database |

---

## Category Justifications

### Network Traffic
Network traffic data is the primary early-warning signal for malware activity in a financial organisation. Malware infections frequently manifest as unusual outbound connections (C2 beacon traffic), lateral movement across internal subnets, or large data exfiltration bursts — all of which alter throughput, protocol distribution, and connection patterns. By collecting granular metrics such as `src_ip`, `dst_ip`, `protocol`, `packet_size_bytes`, and `connection_duration_s` at near-real-time frequency, analysts can correlate events across the kill chain. The `anomaly_flag` field, produced by a machine-learning-based Network Detection and Response (NDR) system, allows the dashboard to surface statistically abnormal sessions immediately. Geographic enrichment (`src_country`, `src_lat`, `src_lon`) enables rapid identification of connections originating from high-risk jurisdictions — a common indicator of nation-state or organised-crime activity targeting financial institutions.

### Endpoints
Endpoints (workstations, servers, and laptops) are the most common initial entry point for malware through phishing attachments, drive-by downloads, and vulnerable software. Collecting `os_version` and `patch_level_pct` identifies machines running unpatched software with known CVEs — the primary vector for ransomware deployment. `firewall_status` and `antivirus_status` detect misconfigurations that remove protective layers. `login_attempts_24h` surfaces brute-force and credential-stuffing attacks, while `disk_encryption` confirms that data-at-rest controls are active — critical for regulatory compliance (PCI-DSS requirement 3). The `active_issues` count aggregates open EDR alerts per host, giving analysts an at-a-glance risk score for each endpoint. Collecting these metrics every 15 minutes via an EDR agent ensures that any sudden degradation in security posture is caught within a single monitoring cycle.

### Data Backups
In the context of ransomware — the dominant malware threat to financial organisations — the integrity and availability of backups is a last line of defence. Without verified, encrypted, offsite backups, a ransomware attack can result in permanent data loss or a coercive ransom payment. `coverage_pct` and `backup_date` confirm that all critical systems are backed up on schedule. `encryption_status` ensures that backup media cannot be read if physically stolen. `validation_result` (automated restore testing) is particularly important: a backup that has never been verified may be corrupt or incomplete, rendering it useless during an incident. `rto_compliant` tracks whether recovery time objectives — mandated by financial regulators and internal business continuity plans — are actually achievable. The `location` field confirms the 3-2-1 backup rule (three copies, two media, one offsite) is being followed.

### Staff Readiness
Human error remains the most common root cause of successful malware incidents, particularly through phishing and social engineering. Financial organisations are explicitly targeted with spear-phishing campaigns because employees have access to payment systems, SWIFT terminals, and customer data. `pending_trainings` and `training_completion_pct` identify staff who have not completed mandatory security awareness training — a regulatory requirement under DORA and ISO 27001. `days_since_training` flags employees whose awareness may have degraded over time. `last_phishing_result` and `phishing_click_rate_pct` provide empirical, behavioural evidence of susceptibility rather than relying solely on training attendance. `risk_profile` combines job role (e.g., Finance Director, System Administrator) with behavioural data to produce a prioritised risk score, enabling security teams to focus remediation effort on the highest-risk individuals before an incident occurs.
