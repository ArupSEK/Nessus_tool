#!/usr/bin/env python3
"""
Browser dashboard for Nessus authentication results.

Run:
    streamlit run nessus_auth_dashboard_web.py
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from nessus_auth_rapid7_gui import (
    APP_NAME,
    APP_VERSION,
    AuthClassifier,
    AuthStatus,
    DashboardData,
    Exporter,
    NessusClient,
    STATUS_COLORS,
    STATUS_ORDER,
)


st.set_page_config(
    page_title=f"{APP_NAME} Web",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)


def status_color(status: AuthStatus | str) -> str:
    if isinstance(status, str):
        try:
            status = AuthStatus(status)
        except ValueError:
            return "#64748B"
    return STATUS_COLORS.get(status, "#64748B")


def rows_to_dataframe(rows: List[Dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    df = rows_to_dataframe(rows)
    if df.empty:
        return b"No data\n"
    return df.to_csv(index=False).encode("utf-8-sig")


def excel_bytes(data: DashboardData) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        path = Path(tmp.name)
    try:
        Exporter.export_excel(data, path)
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def classify_uploaded_csv(uploaded_file) -> DashboardData:
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp.write(uploaded_file.getvalue())
        path = Path(tmp.name)
    try:
        classifier = AuthClassifier()
        raw_rows, findings, csv_hosts = classifier.parse_csv(path)
        return classifier.classify(
            scan_name=Path(uploaded_file.name).stem,
            scan_id="offline",
            history_id="",
            authoritative_hosts=csv_hosts,
            findings=findings,
            raw_rows_count=len(raw_rows),
            source_file=uploaded_file.name,
        )
    finally:
        path.unlink(missing_ok=True)


def classify_api_scan(base_url: str, access_key: str, secret_key: str, verify_tls: bool,
                      scan_id: str, scan_name: str, history_id: str) -> DashboardData:
    classifier = AuthClassifier()
    client = NessusClient(base_url, access_key, secret_key, verify_tls=verify_tls)

    authoritative_hosts: List[str] = []
    try:
        details = client.get_scan_details(scan_id, history_id or None)
        authoritative_hosts = classifier.hosts_from_scan_details(details)
    except Exception:
        authoritative_hosts = []

    with tempfile.TemporaryDirectory(prefix="nessus_auth_web_") as tmpdir:
        csv_path = Path(tmpdir) / f"nessus_scan_{scan_id}_preview.csv"
        client.export_scan_csv(scan_id, csv_path, history_id or None)
        raw_rows, findings, csv_hosts = classifier.parse_csv(csv_path)
        if not authoritative_hosts:
            authoritative_hosts = csv_hosts
        return classifier.classify(
            scan_name=scan_name,
            scan_id=scan_id,
            history_id=history_id,
            authoritative_hosts=authoritative_hosts,
            findings=findings,
            raw_rows_count=len(raw_rows),
            source_file="Temporary Nessus API CSV export",
        )


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: #0f172a;
            color: #e2e8f0;
        }
        [data-testid="stSidebar"] {
            background: #111827;
        }
        .metric-card {
            border-radius: 8px;
            padding: 14px 16px;
            min-height: 96px;
            color: #ffffff;
            box-shadow: 0 10px 28px rgba(0, 0, 0, 0.18);
        }
        .metric-label {
            font-size: 0.82rem;
            font-weight: 700;
            opacity: 0.92;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 1.9rem;
            line-height: 2.1rem;
            font-weight: 800;
            margin-top: 10px;
        }
        .status-pill {
            border-radius: 999px;
            color: #ffffff;
            display: inline-block;
            font-size: 0.78rem;
            font-weight: 700;
            padding: 4px 10px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: Any, color: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card" style="background: {color};">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics(data: DashboardData) -> None:
    metric_defs = [
        ("Total IPs", "#0891B2"),
        ("Auth Passed", status_color(AuthStatus.PASS)),
        ("Auth Failed", status_color(AuthStatus.FAIL)),
        ("Partial Auth", status_color(AuthStatus.PARTIAL)),
        ("No Credentials", status_color(AuthStatus.NOCREDS)),
        ("Unknown", status_color(AuthStatus.UNKNOWN)),
        ("Credential Coverage %", "#14B8A6"),
        ("Auth Success %", "#84CC16"),
    ]

    cols = st.columns(4)
    for idx, (key, color) in enumerate(metric_defs):
        with cols[idx % 4]:
            value = data.metrics.get(key, 0)
            if "%" in key:
                value = f"{value}%"
            metric_card(key, value, color)


def render_charts(data: DashboardData) -> None:
    chart_rows = [
        {"Status": "PASS", "Hosts": data.metrics.get("Auth Passed", 0)},
        {"Status": "FAIL", "Hosts": data.metrics.get("Auth Failed", 0)},
        {"Status": "PARTIAL", "Hosts": data.metrics.get("Partial Auth", 0)},
        {"Status": "NOCREDS", "Hosts": data.metrics.get("No Credentials", 0)},
        {"Status": "UNKNOWN", "Hosts": data.metrics.get("Unknown", 0)},
    ]
    status_df = pd.DataFrame(chart_rows)

    left, right = st.columns(2)
    with left:
        st.subheader("Authentication Status")
        st.bar_chart(status_df.set_index("Status"), color="#38bdf8")

    with right:
        st.subheader("Top Authentication Issues")
        issue_counts: Dict[str, int] = {}
        for host in data.host_records:
            if host.status == AuthStatus.PASS:
                continue
            reason = (host.reasons[0] if host.reasons else "Unknown")[:55]
            issue_counts[reason] = issue_counts.get(reason, 0) + 1
        issue_df = pd.DataFrame(
            sorted(issue_counts.items(), key=lambda item: item[1], reverse=True)[:10],
            columns=["Issue", "Hosts"],
        )
        if issue_df.empty:
            st.info("No non-pass authentication issues found.")
        else:
            st.bar_chart(issue_df.set_index("Issue"), color="#f97316")


def render_tables(data: DashboardData) -> None:
    status_options = ["ALL"] + [status.value for status in STATUS_ORDER]
    selected_status = st.selectbox("Status filter", status_options, index=0)
    search = st.text_input("Search host, reason, account, or plugin ID", "")

    host_df = rows_to_dataframe(Exporter.host_rows(data))
    if not host_df.empty:
        if selected_status != "ALL":
            host_df = host_df[host_df["Status"] == selected_status]
        if search:
            search_l = search.lower()
            host_df = host_df[
                host_df.apply(lambda row: search_l in " ".join(map(str, row.values)).lower(), axis=1)
            ]

    host_tab, protocol_tab, finding_tab = st.tabs(["Host Status", "Protocol Breakdown", "Auth Findings"])
    with host_tab:
        st.dataframe(host_df, use_container_width=True, hide_index=True)
    with protocol_tab:
        st.dataframe(rows_to_dataframe(Exporter.protocol_rows(data)), use_container_width=True, hide_index=True)
    with finding_tab:
        st.dataframe(rows_to_dataframe(Exporter.finding_rows(data)), use_container_width=True, hide_index=True)


def render_downloads(data: DashboardData) -> None:
    host_rows = Exporter.host_rows(data)
    protocol_rows = Exporter.protocol_rows(data)
    finding_rows = Exporter.finding_rows(data)

    cols = st.columns(4)
    cols[0].download_button("Download hosts CSV", csv_bytes(host_rows), "host_status.csv", "text/csv")
    cols[1].download_button("Download protocols CSV", csv_bytes(protocol_rows), "protocol_status.csv", "text/csv")
    cols[2].download_button("Download findings CSV", csv_bytes(finding_rows), "auth_findings.csv", "text/csv")
    try:
        cols[3].download_button(
            "Download Excel",
            excel_bytes(data),
            f"nessus_auth_dashboard_{data.scan_id or 'offline'}.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as exc:
        cols[3].warning(f"Excel unavailable: {exc}")


def render_summary(data: DashboardData) -> None:
    st.subheader("Summary")
    st.write(f"Scan: `{data.scan_name}`")
    st.write(f"Scan ID: `{data.scan_id}` | History ID: `{data.history_id or 'latest/default'}`")
    st.write(f"Generated: `{data.generated_at}` | Source: `{data.source_file}`")
    if data.notes:
        for note in data.notes:
            st.info(note)


def api_sidebar() -> None:
    st.sidebar.subheader("Nessus API")
    base_url = st.sidebar.text_input("Base URL", "https://127.0.0.1:8834")
    access_key = st.sidebar.text_input("Access Key", type="password")
    secret_key = st.sidebar.text_input("Secret Key", type="password")
    verify_tls = st.sidebar.checkbox("Verify TLS", value=False)

    if st.sidebar.button("Load scans"):
        try:
            client = NessusClient(base_url, access_key, secret_key, verify_tls=verify_tls)
            st.session_state["scans"] = client.list_scans()
            st.sidebar.success(f"Loaded {len(st.session_state['scans'])} scans")
        except Exception as exc:
            st.sidebar.error(f"Failed to load scans: {exc}")

    scans = st.session_state.get("scans", [])
    if scans:
        labels = [f"{scan.get('id')} - {scan.get('name', '')}" for scan in scans]
        selected = st.sidebar.selectbox("Scan", labels)
        history_id = st.sidebar.text_input("History ID", "")
        if st.sidebar.button("Build API dashboard"):
            scan = scans[labels.index(selected)]
            scan_id = str(scan.get("id", ""))
            scan_name = str(scan.get("name", scan_id))
            try:
                with st.spinner("Exporting Nessus CSV and building dashboard..."):
                    st.session_state["dashboard_data"] = classify_api_scan(
                        base_url, access_key, secret_key, verify_tls, scan_id, scan_name, history_id.strip()
                    )
            except Exception as exc:
                st.sidebar.error(f"Dashboard failed: {exc}")


def main() -> None:
    inject_css()
    st.title(f"{APP_NAME} Web")
    st.caption(f"Version {APP_VERSION} browser dashboard")

    api_sidebar()

    uploaded = st.file_uploader("Upload a Nessus CSV export", type=["csv"])
    if uploaded is not None:
        try:
            with st.spinner("Parsing CSV and classifying authentication status..."):
                st.session_state["dashboard_data"] = classify_uploaded_csv(uploaded)
        except Exception as exc:
            st.error(f"Could not parse CSV: {exc}")

    data = st.session_state.get("dashboard_data")
    if not data:
        st.info("Upload a Nessus CSV or load a scan from the sidebar to view the dashboard.")
        return

    render_metrics(data)
    st.divider()
    render_charts(data)
    st.divider()
    render_summary(data)
    render_downloads(data)
    st.divider()
    render_tables(data)


if __name__ == "__main__":
    main()
