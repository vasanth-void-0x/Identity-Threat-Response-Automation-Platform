"""app/views/mitre_view.py - MITRE ATT&CK technique overview page."""

from __future__ import annotations

import streamlit as st

from app.components.charts import mitre_heatmap_chart
from app.theme import page_header
from app.utils.data_mode import filter_incidents
from database import repository
from mitre.mapper import load_techniques, technique_frequency


def render() -> None:
    page_header("MITRE ATT&CK Coverage", "Technique frequency, tactical coverage and related incident evidence.")

    all_alerts = repository.get_alerts(limit=5000)
    incidents = filter_incidents(repository.get_incidents(limit=1000), all_alerts, st.session_state.get("data_mode", "Live Splunk"))
    freq = technique_frequency([i.get("mitre_techniques", []) for i in incidents])
    techniques = load_techniques()

    coverage_tab, catalog_tab = st.tabs(["Coverage heatmap", "Technique catalog"])
    with coverage_tab:
        st.plotly_chart(mitre_heatmap_chart(freq), use_container_width=True, config={"displayModeBar": False})
    with catalog_tab:
        for tid, meta in techniques.items():
            count = freq.get(tid, 0)
            with st.expander(f"{tid} · {meta['name']} · {count} incident(s)"):
                st.write(f"**Tactic** · {meta['tactic']}")
                st.write(meta["description"])
                st.write(f"**Detection source** · {meta['detection_source']}")
                for step in meta.get("investigation_steps", []):
                    st.write(f"- {step}")
                related = [i for i in incidents if tid in i.get("mitre_techniques", [])]
                for inc in related[:10]:
                    st.write(f"`{inc['incident_id']}` · {inc['title']} · {inc['severity']}")
