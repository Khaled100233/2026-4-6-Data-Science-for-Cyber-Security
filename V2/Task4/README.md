# CyberSec Dashboard — Streamlit

A Streamlit-based real-time cyber security monitoring dashboard for a financial organisation.

## Architecture

| Feature | Detail |
|---------|--------|
| Framework | Streamlit |
| Navigation | Sidebar radio buttons (4 pages) |
| Auto-refresh | streamlit-autorefresh (30 s) |
| Theme | Dark (configured via `.streamlit/config.toml`) |
| Charts | Plotly (area, choropleth, radar, heatmap, treemap, timeline, sunburst, bubble) |

## Pages

| Page | Key Charts |
|------|-----------|
| 🌐 Network | Area throughput · Choropleth anomaly map · Protocol filter |
| 💻 Endpoints | Radar per host · Patch/login heatmap |
| 💾 Backups | Treemap by encryption · Gantt timeline |
| 👥 Staff | Sunburst hierarchy · Bubble readiness chart · Day-range slider |

## Data Files

The dashboard reads from the `Task4/` folder:

- `network_traffic.csv`
- `endpoints.csv`
- `backups.csv`
- `staff_readiness.csv`

## Setup

```bash
# Install dependencies
pip install -r requirements.txt
```

## Run

```bash
cd Task4 && streamlit run dashboard.py
```

Then open **http://localhost:8501** in your browser.

## Features

- **Download Report** button on every page exports current page data as CSV.
- **Protocol filter** (Network page) — interactive selectbox.
- **Days-since-training slider** (Staff page) — filters bubble and sunburst charts.
- **Auto-refresh** every 30 seconds via `streamlit-autorefresh`.
- **Dark theme** applied globally via `.streamlit/config.toml`.
