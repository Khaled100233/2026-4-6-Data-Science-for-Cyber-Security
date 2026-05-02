"""
generate_data.py
================
Generates realistic dummy CSV data files for the Financial Organisation
Cyber Security Dashboard (Task 4 — V2).

Produces four CSV files in the same directory as this script:
  - network_traffic.csv
  - endpoints.csv
  - backups.csv
  - staff_readiness.csv

Run this script once before launching dashboard.py to populate the data files.
Usage:
    cd V2/Task4 && python generate_data.py
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# ── Reproducibility ──────────────────────────────────────────────────────────
random.seed(42)
np.random.seed(42)

# ── Output directory (same folder as this script) ────────────────────────────
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

def random_ip(private: bool = False) -> str:
    if private:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


CITY_COORDS = {
    "London":      ("GB",  51.5074,  -0.1278),
    "New York":    ("US",  40.7128, -74.0060),
    "Beijing":     ("CN",  39.9042, 116.4074),
    "Moscow":      ("RU",  55.7558,  37.6173),
    "Lagos":       ("NG",   6.5244,   3.3792),
    "São Paulo":   ("BR", -23.5505, -46.6333),
    "Sydney":      ("AU", -33.8688, 151.2093),
    "Dubai":       ("AE",  25.2048,  55.2708),
    "Berlin":      ("DE",  52.5200,  13.4050),
    "Tokyo":       ("JP",  35.6762, 139.6503),
    "Paris":       ("FR",  48.8566,   2.3522),
    "Toronto":     ("CA",  43.6532, -79.3832),
    "Mumbai":      ("IN",  19.0760,  72.8777),
    "Seoul":       ("KR",  37.5665, 126.9780),
    "Mexico City": ("MX",  19.4326, -99.1332),
    "Johannesburg":("ZA", -26.2041,  28.0473),
    "Istanbul":    ("TR",  41.0082,  28.9784),
    "Rome":        ("IT",  41.9028,  12.4964),
    "Madrid":      ("ES",  40.4168,  -3.7038),
    "Riyadh":      ("SA",  24.6877,  46.7219),
}
CITIES = list(CITY_COORDS.keys())


# ─────────────────────────────────────────────────────────────────────────────
# 1. Network Traffic
# ─────────────────────────────────────────────────────────────────────────────

def generate_network_traffic(n: int = 50) -> pd.DataFrame:
    protocols = ["TCP", "UDP", "HTTPS", "HTTP", "DNS", "ICMP"]
    base_time = datetime(2026, 5, 1, 8, 0, 0)
    rows = []
    for i in range(n):
        city = CITIES[i % len(CITIES)]
        country, lat, lon = CITY_COORDS[city]
        anomaly = 1 if random.random() < 0.25 else 0
        rows.append({
            "timestamp":             (base_time + timedelta(minutes=i * 3)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":                random_ip(private=False),
            "dst_ip":                random_ip(private=True),
            "protocol":              random.choice(protocols),
            "throughput_mbps":       round(random.uniform(0.5, 95.0) * (3.0 if anomaly else 1.0), 2),
            "packet_size_bytes":     random.randint(64, 1500),
            "src_port":              random.randint(1024, 65535),
            "dst_port":              random.choice([80, 443, 22, 3389, 53, 8080, 445]),
            "connection_duration_s": round(random.uniform(0.1, 300.0), 2),
            "anomaly_flag":          anomaly,
            "src_country":           country,
            "src_lat":               lat,
            "src_lon":               lon,
            "dst_country":           "GB",
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Endpoints
# ─────────────────────────────────────────────────────────────────────────────

def generate_endpoints(n: int = 20) -> pd.DataFrame:
    os_versions = [
        "Windows 11 22H2", "Windows 10 21H2", "Windows Server 2019",
        "Ubuntu 22.04 LTS", "macOS 14 Sonoma", "Windows Server 2022",
    ]
    av_statuses = ["Updated", "Updated", "Updated", "Outdated", "Missing"]
    cities = ["London", "Manchester", "Birmingham", "Edinburgh",
              "Bristol", "Leeds", "Liverpool", "Cardiff", "Sheffield", "Glasgow"]
    rows = []
    for i in range(n):
        fw_active = random.random() > 0.15
        patch_pct = round(random.uniform(55, 100), 1)
        rows.append({
            "endpoint_id":        f"EP-{1000 + i}",
            "hostname":           f"FINPC-{10 + i:02d}",
            "os_version":         random.choice(os_versions),
            "firewall_status":    "Active" if fw_active else "Inactive",
            "antivirus_status":   random.choice(av_statuses),
            "patch_level":        patch_pct,
            "login_attempts_24h": random.randint(0, 25),
            "disk_encryption":    random.choice(["Enabled", "Enabled", "Enabled", "Disabled"]),
            "active_issues":      random.randint(0, 6),
            "location_city":      cities[i % len(cities)],
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Data Backups
# ─────────────────────────────────────────────────────────────────────────────

def generate_backups(n: int = 20) -> pd.DataFrame:
    systems = [
        "Core Banking System", "Customer Database", "Email Server",
        "Payment Gateway", "HR System", "Compliance Archive",
        "Trading Platform", "Audit Log Server", "CRM System", "File Server",
    ]
    base_date = datetime(2026, 5, 1, 2, 0, 0)
    rows = []
    for i in range(n):
        coverage = round(random.uniform(50, 100), 1)
        rto_ok   = "Yes" if coverage >= 75 and random.random() > 0.2 else "No"
        rows.append({
            "backup_id":         f"BK-{2000 + i}",
            "system_name":       systems[i % len(systems)],
            "backup_date":       (base_date - timedelta(hours=i * 6)).strftime("%Y-%m-%d %H:%M:%S"),
            "coverage_pct":      coverage,
            "encryption_status": random.choice(["Encrypted", "Encrypted", "Encrypted", "Unencrypted"]),
            "validation_result": "Pass" if random.random() > 0.2 else "Fail",
            "backup_type":       random.choice(["Full", "Incremental", "Differential"]),
            "location":          random.choice(["On-site", "Off-site", "Off-site"]),
            "rto_compliant":     rto_ok,
            "size_gb":           round(random.uniform(5, 500), 1),
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Staff Readiness
# ─────────────────────────────────────────────────────────────────────────────

def generate_staff_readiness(n: int = 30) -> pd.DataFrame:
    departments = ["Finance", "IT", "Operations", "HR", "Compliance",
                   "Risk", "Trading", "Legal", "Customer Services", "Executive"]
    roles = ["Analyst", "Manager", "Director", "Developer",
             "Administrator", "Officer", "Trader", "Advisor"]
    risk_profiles = ["Low", "Low", "Medium", "Medium", "High"]
    rows = []
    for i in range(n):
        completion = round(random.uniform(20, 100), 1)
        risk = random.choice(risk_profiles)
        phish_pass = (
            "Pass" if (risk == "Low"    and random.random() > 0.1) or
                      (risk == "Medium" and random.random() > 0.35) or
                      (risk == "High"   and random.random() > 0.55)
            else "Fail"
        )
        rows.append({
            "employee_id":             f"EMP-{3000 + i}",
            "department":              departments[i % len(departments)],
            "job_role":                random.choice(roles),
            "risk_profile":            risk,
            "pending_trainings":       random.randint(0, 5),
            "training_completion_pct": completion,
            "days_since_training":     random.randint(1, 180),
            "last_phishing_result":    phish_pass,
            "phishing_click_rate_pct": round(random.uniform(0, 60), 1),
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Main — generate and save all files
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    datasets = {
        "network_traffic.csv": generate_network_traffic(50),
        "endpoints.csv":       generate_endpoints(20),
        "backups.csv":         generate_backups(20),
        "staff_readiness.csv": generate_staff_readiness(30),
    }
    for filename, df in datasets.items():
        path = os.path.join(OUTPUT_DIR, filename)
        df.to_csv(path, index=False)
        print(f"[generate_data] Saved {len(df)} rows → {path}")
    print("\n[generate_data] All data files generated successfully.")


if __name__ == "__main__":
    main()
