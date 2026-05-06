"""
dashboard.py
============
Financial Organisation — Cyber Security Monitoring Dashboard
Task 4 | Data Science for Cyber Security

Built using Streamlit with a sidebar navigation model and 4 full-screen
domain pages.

Usage:
    cd Task4 && streamlit run dashboard.py
    Then open: http://localhost:8501

Key References:
    Streamlit Inc. (2019) — Streamlit — The fastest way to build data apps. https://streamlit.io
    Vielberth et al. (2020) — SIEM survey. IEEE Access, 8, 143812–143836.
        https://doi.org/10.1109/ACCESS.2020.3012196
    Plotly Technologies Inc. (2015) — Collaborative data science. https://plot.ly
    McKinney, W. (2010) — Data Structures for Statistical Computing in Python.
        Proceedings of the 9th Python in Science Conference (SciPy), 51–56.
    ISO/IEC 27001:2022 — Information Security Management. https://www.iso.org/standard/82875.html
    PCI-DSS v4.0 — Payment Card Industry Data Security Standard.
        https://www.pcisecuritystandards.org/document_library/
"""

# ── Standard library ──────────────────────────────────────────────────────────
import os
import time
import threading
from datetime import datetime

# ── Third-party ───────────────────────────────────────────────────────────────
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ── Auto-refresh (30-second cycle) ────────────────────────────────────────────
try:
    from streamlit_autorefresh import st_autorefresh
    _AUTOREFRESH_AVAILABLE = True
except ImportError:
    _AUTOREFRESH_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Page configuration — must be the first Streamlit call
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberSec Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
# Data directory — check script-local folder first (self-contained), then Task4/
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = _SCRIPT_DIR   # Task4 ships its own CSVs via generate_data.py
if not os.path.isfile(os.path.join(DATA_DIR, "network_traffic.csv")):
    # Fallback: original Task4/ folder two levels up (legacy path)
    for candidate in [
        os.path.join(_SCRIPT_DIR, "..", "..", "Task4"),
        "Task4", "../Task4", "../../Task4",
    ]:
        full = os.path.abspath(candidate)
        if os.path.isfile(os.path.join(full, "network_traffic.csv")):
            DATA_DIR = full
            break

NETWORK_CSV  = os.path.join(DATA_DIR, "network_traffic.csv")
ENDPOINT_CSV = os.path.join(DATA_DIR, "endpoints.csv")
BACKUP_CSV   = os.path.join(DATA_DIR, "backups.csv")
STAFF_CSV    = os.path.join(DATA_DIR, "staff_readiness.csv")

# Colour palette
C_GREEN  = "#2ecc71"
C_AMBER  = "#f39c12"
C_RED    = "#e74c3c"
C_BLUE   = "#3498db"
C_DARK   = "#0e1117"

RISK_COLOURS = {"Low": C_GREEN, "Medium": C_AMBER, "High": C_RED}

# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=30)
def load_all_data():
    """
    Load all four CSV datasets from the Task4 directory.

    Returns:
        tuple: (network_df, endpoints_df, backups_df, staff_df)
    """
    network   = pd.read_csv(NETWORK_CSV,  parse_dates=["timestamp"])
    endpoints = pd.read_csv(ENDPOINT_CSV)
    backups   = pd.read_csv(BACKUP_CSV,   parse_dates=["backup_date"])
    staff     = pd.read_csv(STAFF_CSV)
    return network, endpoints, backups, staff


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar navigation
# ─────────────────────────────────────────────────────────────────────────────

def render_sidebar():
    """Render the dark sidebar with navigation radio buttons."""
    with st.sidebar:
        st.markdown(
            "<h2 style='color:#3498db;'>🛡️ CyberSec Monitor</h2>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color:#95a5a6; font-size:0.85em;'>Financial Organisation<br>"
            "Real-time security overview</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        page = st.radio(
            "Navigate to",
            options=["🌐 Network", "💻 Endpoints", "💾 Backups", "👥 Staff"],
            key="nav_page",
        )
        st.divider()
        st.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

        if _AUTOREFRESH_AVAILABLE:
            st.caption("Auto-refresh: every 30 s")
        else:
            if st.button("↺ Refresh now"):
                st.cache_data.clear()
                st.rerun()

    return page


# ─────────────────────────────────────────────────────────────────────────────
# Page: Network Traffic
# ─────────────────────────────────────────────────────────────────────────────

def page_network(df: pd.DataFrame):
    """
    Render the Network Traffic monitoring page.

    Charts:
        - st.metric KPIs
        - Area chart of throughput over time
        - Choropleth map of anomalies by country
        - Protocol filter via selectbox
    """
    st.title("🌐 Network Traffic Monitor")

    # ── KPI metrics ──────────────────────────────────────────────────────────
    total_packets = len(df)
    anomalies     = int(df["anomaly_flag"].sum()) if "anomaly_flag" in df.columns else 0
    avg_throughput = round(df["throughput_mbps"].mean(), 2) if "throughput_mbps" in df.columns else 0
    anomaly_rate   = round(anomalies / max(total_packets, 1) * 100, 2)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets", f"{total_packets:,}")
    c2.metric("Anomalies Detected", f"{anomalies:,}", delta=f"{anomaly_rate}%")
    c3.metric("Avg Throughput (Mbps)", avg_throughput)
    c4.metric("Unique Source Countries",
              df["src_country"].nunique() if "src_country" in df.columns else "N/A")

    st.divider()

    # ── Protocol filter ───────────────────────────────────────────────────────
    if "protocol" in df.columns:
        protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
        selected_proto = st.selectbox("Filter by Protocol", protocols, key="proto_filter")
        filtered = df if selected_proto == "All" else df[df["protocol"] == selected_proto]
    else:
        filtered = df

    # ── Area chart: throughput over time ──────────────────────────────────────
    if "timestamp" in filtered.columns and "throughput_mbps" in filtered.columns:
        ts_df = (
            filtered.set_index("timestamp")["throughput_mbps"]
            .resample("15min")
            .mean()
            .reset_index()
        )
        fig_area = px.area(
            ts_df, x="timestamp", y="throughput_mbps",
            title="Network Throughput Over Time (15-min average)",
            labels={"timestamp": "Time", "throughput_mbps": "Throughput (Mbps)"},
            template="plotly_dark",
            color_discrete_sequence=[C_BLUE],
        )
        fig_area.update_layout(height=350, showlegend=False)
        st.plotly_chart(fig_area, use_container_width=True)

    # ── Choropleth: anomaly count by source country ───────────────────────────
    if "src_country" in df.columns and "anomaly_flag" in df.columns:
        # Convert ISO alpha-2 → alpha-3 codes required by Plotly's 'ISO-3' locationmode
        ALPHA2_TO_ALPHA3 = {
            "AE": "ARE", "AU": "AUS", "BR": "BRA", "CN": "CHN",
            "DE": "DEU", "FR": "FRA", "GB": "GBR", "IN": "IND",
            "JP": "JPN", "NG": "NGA", "RU": "RUS", "US": "USA",
            "ZA": "ZAF", "CA": "CAN", "MX": "MEX", "KR": "KOR",
            "SA": "SAU", "TR": "TUR", "IT": "ITA", "ES": "ESP",
        }
        country_anom = (
            df.groupby("src_country")["anomaly_flag"]
            .sum()
            .reset_index()
            .rename(columns={"src_country": "Country", "anomaly_flag": "Anomalies"})
        )
        country_anom["ISO3"] = country_anom["Country"].map(ALPHA2_TO_ALPHA3)
        country_anom = country_anom.dropna(subset=["ISO3"])

        if not country_anom.empty:
            max_anom = int(country_anom["Anomalies"].max())
            fig_map = px.choropleth(
                country_anom,
                locations="ISO3",
                locationmode="ISO-3",
                color="Anomalies",
                hover_name="Country",
                title="Anomaly Count by Source Country",
                color_continuous_scale=[[0, "#2ecc71"], [0.5, "#f39c12"], [1.0, "#e74c3c"]],
                range_color=[0, max(max_anom, 1)],
                template="plotly_dark",
            )
            fig_map.update_geos(showframe=False, showcoastlines=True,
                                landcolor="#1a1a2e", oceancolor="#0d0d1a", showocean=True)
            fig_map.update_layout(height=420, geo=dict(bgcolor=C_DARK))
            st.plotly_chart(fig_map, use_container_width=True)

    # ── Download button ───────────────────────────────────────────────────────
    st.download_button(
        "⬇ Download Network Data (CSV)",
        data=filtered.to_csv(index=False),
        file_name="network_traffic_export.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Page: Endpoints
# ─────────────────────────────────────────────────────────────────────────────

def page_endpoints(df: pd.DataFrame):
    """
    Render the Endpoint Security page.

    Charts:
        - Radar / spider chart per endpoint security dimensions
        - Heatmap of patch_level and login_attempts_24h per hostname
    """
    st.title("💻 Endpoint Security")

    # ── KPI strip ────────────────────────────────────────────────────────────
    total_eps = len(df)
    active_fw = int((df["firewall_status"] == "Active").sum()) if "firewall_status" in df.columns else 0
    avg_patch = round(df["patch_level"].mean(), 1) if "patch_level" in df.columns else 0
    high_logins = int((df["login_attempts_24h"] > 20).sum()) if "login_attempts_24h" in df.columns else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Endpoints", total_eps)
    c2.metric("Active Firewalls", f"{active_fw}/{total_eps}")
    c3.metric("Avg Patch Level (%)", avg_patch)
    c4.metric("High Login Attempts (>20)", high_logins)

    st.divider()

    # ── Radar chart: security dimensions per endpoint ─────────────────────────
    radar_cols = ["patch_level", "login_attempts_24h", "active_issues"]
    available_radar = [c for c in radar_cols if c in df.columns]

    if available_radar and "hostname" in df.columns:
        sample = df.head(8).copy()
        # Normalise to 0–100 for display
        norm = sample[available_radar].copy()
        for col in available_radar:
            col_max = norm[col].max()
            if col_max > 0:
                norm[col] = (norm[col] / col_max * 100).round(1)

        fig_radar = go.Figure()
        colours_cycle = px.colors.qualitative.Plotly
        for i, (_, row) in enumerate(sample.iterrows()):
            values = [float(norm.loc[row.name, col]) for col in available_radar]
            values.append(values[0])  # close the polygon
            categories = available_radar + [available_radar[0]]
            fig_radar.add_trace(
                go.Scatterpolar(
                    r=values,
                    theta=categories,
                    fill="toself",
                    name=str(row["hostname"]),
                    line_color=colours_cycle[i % len(colours_cycle)],
                    opacity=0.7,
                )
            )
        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 100]),
                bgcolor="#1a1a2e",
            ),
            title="Endpoint Security Dimensions (top 8 hosts, normalised 0–100)",
            template="plotly_dark",
            height=480,
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # ── Heatmap: patch level + login attempts per hostname ────────────────────
    heat_cols = [c for c in ["patch_level", "login_attempts_24h"] if c in df.columns]
    if heat_cols and "hostname" in df.columns:
        heat_df = df[["hostname"] + heat_cols].head(20).set_index("hostname")
        fig_heat = px.imshow(
            heat_df,
            title="Endpoint Heatmap: Patch Level & Login Attempts (top 20 hosts)",
            color_continuous_scale="RdYlGn",
            text_auto=True,
            template="plotly_dark",
        )
        fig_heat.update_layout(height=500, xaxis_title="Metric", yaxis_title="Hostname")
        st.plotly_chart(fig_heat, use_container_width=True)

    # ── Download button ───────────────────────────────────────────────────────
    st.download_button(
        "⬇ Download Endpoint Data (CSV)",
        data=df.to_csv(index=False),
        file_name="endpoints_export.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Page: Backups
# ─────────────────────────────────────────────────────────────────────────────

def page_backups(df: pd.DataFrame):
    """
    Render the Data Backup status page.

    Charts:
        - Treemap of backup size coloured by encryption_status
        - Gantt-style timeline of backup_date per system
    """
    st.title("💾 Data Backup Status")

    # ── KPI strip ────────────────────────────────────────────────────────────
    total_bk   = len(df)
    encrypted  = int((df["encryption_status"] == "Encrypted").sum()) if "encryption_status" in df.columns else 0
    rto_ok     = int((df["rto_compliant"] == "Yes").sum()) if "rto_compliant" in df.columns else 0
    total_gb   = round(df["size_gb"].sum(), 1) if "size_gb" in df.columns else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Backup Jobs", total_bk)
    c2.metric("Encrypted", f"{encrypted}/{total_bk}")
    c3.metric("RTO Compliant", f"{rto_ok}/{total_bk}")
    c4.metric("Total Data (GB)", f"{total_gb:,.1f}")

    st.divider()

    # ── Treemap: backup size coloured by encryption status ────────────────────
    if all(c in df.columns for c in ["system_name", "size_gb", "encryption_status"]):
        fig_tree = px.treemap(
            df,
            path=["encryption_status", "system_name"],
            values="size_gb",
            color="encryption_status",
            color_discrete_map={
                "Encrypted": C_GREEN,
                "Unencrypted": C_RED,
            },
            title="Backup Storage Treemap — Size (GB) by Encryption Status",
            template="plotly_dark",
        )
        fig_tree.update_traces(
            textinfo="label+value",
            texttemplate="<b>%{label}</b><br>%{value:.1f} GB",
        )
        fig_tree.update_layout(height=440)
        st.plotly_chart(fig_tree, use_container_width=True)

    # ── Gantt-style: backup timeline per system ────────────────────────────────
    if all(c in df.columns for c in ["system_name", "backup_date", "backup_type"]):
        gantt_df = df.copy()
        gantt_df["backup_date"] = pd.to_datetime(gantt_df["backup_date"], errors="coerce")
        gantt_df = gantt_df.dropna(subset=["backup_date"])
        # Add a 1-hour duration for Gantt bars
        gantt_df["end_date"] = gantt_df["backup_date"] + pd.Timedelta(hours=1)
        gantt_df = gantt_df.sort_values("backup_date")

        fig_gantt = px.timeline(
            gantt_df,
            x_start="backup_date",
            x_end="end_date",
            y="system_name",
            color="backup_type",
            title="Backup Timeline per System (Gantt)",
            labels={"system_name": "System", "backup_type": "Backup Type"},
            template="plotly_dark",
        )
        fig_gantt.update_yaxes(autorange="reversed")
        fig_gantt.update_layout(height=450, legend_title="Backup Type")
        st.plotly_chart(fig_gantt, use_container_width=True)

    # ── Download button ───────────────────────────────────────────────────────
    st.download_button(
        "⬇ Download Backup Data (CSV)",
        data=df.to_csv(index=False),
        file_name="backups_export.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Page: Staff Readiness
# ─────────────────────────────────────────────────────────────────────────────

def page_staff(df: pd.DataFrame):
    """
    Render the Staff Readiness & Awareness page.

    Charts:
        - Sunburst: department → risk_profile → job_role (equal weight per employee)
        - Bubble chart: days_since_training vs training_completion_pct
          (size = pending_trainings, colour = risk_profile)
        - Interactive single-value slider to filter by max days_since_training
    """
    st.title("👥 Staff Readiness & Awareness")

    # ── KPI strip (4 columns) ─────────────────────────────────────────────────
    total_staff = len(df)
    high_risk   = int((df["risk_profile"] == "High").sum()) if "risk_profile" in df.columns else 0
    avg_comp    = round(df["training_completion_pct"].mean(), 1) if "training_completion_pct" in df.columns else 0
    # Phishing fail rate: percentage of staff who failed the last simulation
    if "last_phishing_result" in df.columns and len(df) > 0:
        phishing_fail_rate = round(
            (df["last_phishing_result"] == "Fail").sum() / len(df) * 100, 1
        )
    else:
        phishing_fail_rate = 0.0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Staff", total_staff)
    # Show a red delta arrow when any high-risk employees are present
    c2.metric(
        "High Risk Count",
        high_risk,
        delta=f"+{high_risk}" if high_risk > 0 else None,
        delta_color="inverse",   # 'inverse' makes positive delta red
    )
    c3.metric("Avg Training Completion (%)", avg_comp)
    c4.metric("Phishing Fail Rate (%)", phishing_fail_rate)

    st.divider()

    # ── Slider: filter by maximum days since last training ────────────────────
    if "days_since_training" in df.columns:
        max_slider = st.slider(
            "Filter: Max days since last training",
            min_value=1,
            max_value=180,
            value=180,
            step=1,
            key="days_slider",
        )
        # Keep only staff whose training is within the selected window
        filtered_df = df[df["days_since_training"] <= max_slider]
        st.caption(f"Showing {len(filtered_df)} of {len(df)} staff members")
    else:
        filtered_df = df

    # ── Chart 1: Sunburst — department → risk_profile → job_role ─────────────
    sunburst_cols = [c for c in ["department", "risk_profile", "job_role"]
                     if c in filtered_df.columns]
    if len(sunburst_cols) >= 2:
        # Add a synthetic 'count' column so every employee has equal weight
        sun_df = filtered_df.copy()
        sun_df["count"] = 1
        fig_sun = px.sunburst(
            sun_df,
            path=sunburst_cols,
            values="count",
            color="risk_profile" if "risk_profile" in sunburst_cols else sunburst_cols[0],
            color_discrete_map={"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e74c3c"},
            title="Staff Risk Hierarchy: Department → Risk Profile → Job Role",
            template="plotly_dark",
            height=500,
        )
        st.plotly_chart(fig_sun, use_container_width=True)

    # ── Chart 2: Bubble chart — days_since_training vs training_completion_pct ─
    bubble_needed = ["days_since_training", "training_completion_pct",
                     "pending_trainings", "risk_profile"]
    if all(c in filtered_df.columns for c in bubble_needed):
        # Clip pending_trainings so zero values still render as visible points
        bubble_df = filtered_df.copy()
        bubble_df["pending_trainings"] = bubble_df["pending_trainings"].clip(lower=1)

        # Build hover_data list from whichever optional columns are present
        hover_cols = [c for c in ["employee_id", "department", "job_role",
                                   "last_phishing_result"]
                      if c in bubble_df.columns]

        fig_bubble = px.scatter(
            bubble_df,
            x="days_since_training",
            y="training_completion_pct",
            size="pending_trainings",
            color="risk_profile",
            color_discrete_map={"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e74c3c"},
            hover_data=hover_cols if hover_cols else None,
            size_max=40,
            title="Training Compliance vs Risk Profile",
            labels={
                "days_since_training": "Days Since Last Training",
                "training_completion_pct": "Training Completion (%)",
            },
            template="plotly_dark",
            height=450,
        )
        # Add a vertical dashed red warning line at 90 days
        fig_bubble.add_vline(
            x=90,
            line_dash="dash",
            line_color="red",
            annotation_text="90-day warning",
            annotation_position="top right",
        )
        fig_bubble.update_layout(legend_title="Risk Profile")
        st.plotly_chart(fig_bubble, use_container_width=True)

    # ── Download button ───────────────────────────────────────────────────────
    st.download_button(
        "⬇ Download Staff Data (CSV)",
        data=filtered_df.to_csv(index=False),
        file_name="staff_readiness_export.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main application entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Main entry point — wires together sidebar, auto-refresh, and pages."""

    # Auto-refresh every 30 seconds
    if _AUTOREFRESH_AVAILABLE:
        st_autorefresh(interval=30_000, key="auto_refresh_counter")

    # Render sidebar and get selected page
    page = render_sidebar()

    # Load data
    try:
        network, endpoints, backups, staff = load_all_data()
    except FileNotFoundError as exc:
        st.error(
            f"❌ Data files not found: {exc}\n\n"
            "Please ensure the `Task4/` CSV files exist in the workspace root."
        )
        st.stop()

    # Route to the selected page
    if "Network" in page:
        page_network(network)
    elif "Endpoints" in page:
        page_endpoints(endpoints)
    elif "Backups" in page:
        page_backups(backups)
    elif "Staff" in page:
        page_staff(staff)


if __name__ == "__main__":
    main()
