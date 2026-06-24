# Nessus_tool

Repository for Nessus tooling.

## Desktop GUI

```powershell
python nessus_auth_rapid7_gui.py
```

## Browser Dashboard

Install the web dependencies:

```powershell
python -m pip install -r requirements-web.txt
```

Run the Streamlit dashboard:

```powershell
streamlit run nessus_auth_dashboard_web.py
```

Then open:

```text
http://localhost:8501
```

The browser dashboard can load a Nessus CSV export directly, or connect to the
Nessus API from the sidebar.
