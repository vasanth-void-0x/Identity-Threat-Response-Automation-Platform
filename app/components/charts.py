"""app/components/charts.py - Plotly chart builders for the dashboard."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from app.utils.formatting import SEVERITY_COLORS
from mitre.mapper import load_techniques
from threat_intelligence.geoip import resolve_geoip


PLOT_BG = "rgba(5,5,7,0)"
GRID = "rgba(255,255,255,.07)"
FONT = "#b9b9c4"


def _compact(fig: go.Figure, *, height: int, title: str) -> go.Figure:
    fig.update_layout(
        title=dict(text=title, x=.025, xanchor="left", font=dict(size=14, color="#e9e9ef")),
        height=height,
        margin=dict(l=28, r=18, t=42, b=26),
        paper_bgcolor=PLOT_BG,
        plot_bgcolor=PLOT_BG,
        font=dict(family="Inter, sans-serif", size=10, color=FONT),
        legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", y=1.02, x=1, xanchor="right"),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def _empty(*, height: int, title: str, message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, x=.5, y=.5, xref="paper", yref="paper", showarrow=False,
                       font=dict(size=13, color="#737380"))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _compact(fig, height=height, title=title)


def severity_distribution_chart(incidents: list[dict]):
    if not incidents:
        return _empty(height=164, title="INCIDENT SEVERITY", message="No incidents in this data source")
    df = pd.DataFrame(incidents)
    counts = df["severity"].value_counts().reindex(["low", "medium", "high", "critical"]).fillna(0)
    fig = px.bar(
        x=counts.index, y=counts.values,
        labels={"x": "Severity", "y": "Incident Count"},
        color=counts.index,
        color_discrete_map=SEVERITY_COLORS,
        title=None,
    )
    fig.update_layout(showlegend=False)
    return _compact(fig, height=164, title="INCIDENT SEVERITY")


def severity_donut_chart(incidents: list[dict]):
    """Compact incident severity donut. Slice total always equals len(incidents)."""
    if not incidents:
        return _empty(height=176, title="INCIDENT SEVERITY", message="No incidents in this data source")
    df = pd.DataFrame(incidents)
    order = ["critical", "high", "medium", "low"]
    counts = df["severity"].value_counts().reindex(order).fillna(0).astype(int)
    counts = counts[counts > 0]
    fig = go.Figure(go.Pie(
        labels=[label.capitalize() for label in counts.index],
        values=counts.values,
        hole=.62,
        marker=dict(colors=[SEVERITY_COLORS.get(s, "#888") for s in counts.index],
                    line=dict(color="rgba(5,5,7,1)", width=2)),
        textinfo="value",
        textfont=dict(size=11, color="#fff"),
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        sort=False,
    ))
    total = int(counts.sum())
    fig.add_annotation(text=f"<b>{total}</b><br><span style='font-size:9px'>TOTAL</span>",
                        x=.5, y=.5, showarrow=False, font=dict(size=15, color="#f7f7fb"))
    fig = _compact(fig, height=176, title="INCIDENT SEVERITY")
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", y=-.08, x=.5, xanchor="center", font=dict(size=9),
                    bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=8, r=8, t=34, b=6),
    )
    return fig


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return f"rgba(139,92,246,{alpha})"
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


def mini_sparkline_chart(values: list[float], *, color: str = "#8b5cf6"):
    """Ultra-compact trend line for a bottom metric card. No axes/labels/title."""
    fig = go.Figure()
    if not values or all(v == 0 for v in values):
        fig.add_trace(go.Scatter(y=[0, 0], mode="lines", line=dict(color="rgba(255,255,255,.08)", width=1.5)))
    else:
        fig.add_trace(go.Scatter(
            y=values, mode="lines", line=dict(color=color, width=1.6, shape="spline"),
            fill="tozeroy", fillcolor=_hex_to_rgba(color, .14),
        ))
    fig.update_xaxes(visible=False, showgrid=False)
    fig.update_yaxes(visible=False, showgrid=False)
    fig.update_layout(
        height=26, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
    )
    return fig


def alert_timeline_chart(alerts: list[dict]):
    if not alerts:
        return _empty(height=164, title="ALERT VOLUME", message="No alerts in this data source")
    df = pd.DataFrame(alerts)
    df["created_at"] = pd.to_datetime(
    df["created_at"],
    format="mixed",
    utc=True,
    errors="coerce",
)
    
    df = df.dropna(subset=["created_at"])
    df["hour_bucket"] = df["created_at"].dt.floor("h")
    grouped = df.groupby(["hour_bucket", "severity"]).size().reset_index(name="count")
    fig = px.line(
        grouped, x="hour_bucket", y="count", color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title=None,
        markers=True,
    )
    fig.update_xaxes(tickformat="%b %d, %H:%M", title="Time")
    fig.update_yaxes(title="Alert Count", rangemode="tozero")
    return _compact(fig, height=164, title="ALERT VOLUME")


def mitre_technique_chart(technique_frequency: dict[str, int]):
    if not technique_frequency:
        return go.Figure()
    df = pd.DataFrame(
        [{"technique": k, "count": v} for k, v in sorted(technique_frequency.items(), key=lambda x: -x[1])]
    )
    fig = px.bar(df, x="technique", y="count", title=None, color_discrete_sequence=["#8b5cf6"])
    return _compact(fig, height=330, title="MITRE ATT&CK TECHNIQUE FREQUENCY")


def risk_score_gauge(score: int, severity: str):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": f"Risk Score ({severity.upper()})"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": SEVERITY_COLORS.get(severity, "#888")},
            "steps": [
                {"range": [0, 29], "color": "#101a17"},
                {"range": [30, 59], "color": "#1b1910"},
                {"range": [60, 79], "color": "#1d1510"},
                {"range": [80, 100], "color": "#1d1014"},
            ],
        },
    ))
    fig.update_layout(height=250, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor=PLOT_BG, font_color=FONT)
    return fig


def world_attack_map_chart(alerts: list[dict], *, expanded: bool = False, height: int | None = None):
    """
    Plots a world map of alert source IPs using GeoIP. Respects the
    configured provider (mock/live - see threat_intelligence.geoip.
    resolve_geoip) and labels each location with its actual data source
    (mock/cache/live) so simulated coordinates are never presented as real
    attacker locations. Bubble size = alert count at that location, color =
    highest severity seen from that location.

    `height` lets embedded callers (e.g. the Overview's larger centre-column
    card) request a taller render than the default; `expanded` (full map)
    always wins with its own fixed height.
    """
    default_height = 620 if expanded else (height or 352)
    ips = [a["source_ip"] for a in alerts if a.get("source_ip")]
    if not ips:
        fig = go.Figure()
        return _empty(height=default_height, title="GEOIP ATTACK MAP", message="No source IP evidence in this data source")

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    location_data: dict[tuple, dict] = {}
    sources_seen: set[str] = set()

    for a in alerts:
        ip = a.get("source_ip")
        if not ip:
            continue
        geo = resolve_geoip(ip)
        if geo.get("lat") is None or geo.get("lon") is None:
            continue
        sources_seen.add(geo.get("source", "mock"))
        key = (geo["city"], geo["country"])
        entry = location_data.setdefault(key, {
            "city": geo["city"], "country": geo["country"],
            "lat": geo["lat"], "lon": geo["lon"],
            "count": 0, "severity": "low", "ips": set(), "users": set(), "hosts": set(),
            "source": geo.get("source", "mock"),
        })
        entry["count"] += 1
        entry["ips"].add(ip)
        if a.get("user"):
            entry["users"].add(str(a["user"]))
        if a.get("hostname") or a.get("host"):
            entry["hosts"].add(str(a.get("hostname") or a.get("host")))
        if severity_rank.get(a.get("severity", "low"), 0) > severity_rank.get(entry["severity"], 0):
            entry["severity"] = a.get("severity", "low")

    if not location_data:
        fig = go.Figure()
        return _empty(height=default_height, title="GEOIP ATTACK MAP", message="No geolocatable source IP evidence")

    df = pd.DataFrame(location_data.values())
    df["ip_count"] = df["ips"].apply(len)
    df["ip_list"] = df["ips"].apply(lambda values: ", ".join(sorted(values)[:6]) or "—")
    df["user_list"] = df["users"].apply(lambda values: ", ".join(sorted(values)[:6]) or "—")
    df["host_list"] = df["hosts"].apply(lambda values: ", ".join(sorted(values)[:6]) or "—")
    source_label = {"mock": "simulated", "live": "live GeoIP", "cache": "cached live GeoIP"}
    df["source_label"] = df["source"].map(source_label).fillna("simulated")
    df["label"] = (
        df["city"] + ", " + df["country"] + " — " + df["count"].astype(str)
        + " alert(s) (" + df["source_label"] + ")"
    )

    # Overall badge: if ANY location used live/cached data, call it live; otherwise fully simulated.
    map_data_source = "live" if ("live" in sources_seen or "cache" in sources_seen) else "mock"

    # A soft outer marker ring gives every source a radar-like presence.
    fig = go.Figure()
    fig.add_trace(go.Scattergeo(
        lat=df["lat"], lon=df["lon"], mode="markers",
        marker=dict(size=(10 + df["count"].clip(upper=12) * 1.05), color="#8b5cf6", opacity=.15,
                    line=dict(width=1, color="rgba(167,139,250,.35)")),
        hoverinfo="skip", showlegend=False,
    ))
    marker_fig = px.scatter_geo(
        df, lat="lat", lon="lon", size="count", color="severity",
        color_discrete_map=SEVERITY_COLORS,
        custom_data=["city", "country", "count", "severity", "ip_list", "user_list", "host_list", "source_label"],
        size_max=16,
        projection="equirectangular",
        title=None,
    )
    for trace in marker_fig.data:
        trace.hovertemplate = (
            "<b>%{customdata[0]}, %{customdata[1]}</b><br>"
            "Alerts: %{customdata[2]} · Severity: %{customdata[3]}<br>"
            "Source IPs: %{customdata[4]}<br>Users: %{customdata[5]}<br>"
            "Devices / hosts: %{customdata[6]}<br>GeoIP provider: %{customdata[7]}"
            "<extra>ITRAP evidence</extra>"
        )
        fig.add_trace(trace)
    # A monitored-environment hub makes the global relationship readable.
    # Lines are telemetry connections, not an assertion of packet direction.
    hub_lat, hub_lon = 13.0827, 80.2707
    line_colors = {"low": "#34d399", "medium": "#fbbf24", "high": "#fb923c", "critical": "#fb4b5f"}
    for location in location_data.values():
        fig.add_trace(go.Scattergeo(
            lat=[location["lat"], hub_lat], lon=[location["lon"], hub_lon],
            mode="lines", line=dict(width=1.15, color=line_colors.get(location["severity"], "#8b5cf6")),
            opacity=.18, hoverinfo="skip", showlegend=False,
        ))
    fig.add_trace(go.Scattergeo(
        lat=[hub_lat], lon=[hub_lon], mode="markers+text",
        marker=dict(size=8, color="#22d3ee", symbol="diamond", line=dict(width=1.4, color="#cffafe")),
        text=["ITRAP"], textposition="top center", textfont=dict(size=8, color="#67e8f9"),
        hovertemplate="ITRAP monitored environment<extra></extra>", showlegend=False,
    ))
    fig.update_geos(
        projection_type="equirectangular", showframe=False,
        showcountries=True, countrycolor="#654591", showcoastlines=True, coastlinecolor="#7651a7",
        showland=True, landcolor="#181020", showocean=True, oceancolor="#030305",
        showlakes=True, lakecolor="#07050b", bgcolor="rgba(0,0,0,0)",
        lataxis=dict(showgrid=True, gridcolor="rgba(139,92,246,.085)", gridwidth=.5),
        lonaxis=dict(showgrid=True, gridcolor="rgba(139,92,246,.085)", gridwidth=.5),
    )
    title = "GEOIP ATTACK MAP · " + ("SIMULATED LOCATIONS" if map_data_source == "mock" else "LIVE PUBLIC-IP GEOLOCATION")
    fig = _compact(fig, height=default_height, title=title)
    fig.update_layout(
        margin=dict(l=8, r=8, t=42, b=8),
        geo=dict(domain=dict(x=[0, 1], y=[0, 1]), projection_scale=1.17),
        legend=dict(bgcolor="rgba(5,5,8,.76)", bordercolor="rgba(139,92,246,.24)", borderwidth=1),
    )
    return fig


def mitre_heatmap_chart(technique_frequency_map: dict[str, int]):
    """
    MITRE ATT&CK Navigator-style heatmap: tactics as columns, techniques
    grouped under their primary tactic, cell color = incident frequency.
    """
    techniques = load_techniques()

    tactic_groups: dict[str, list[str]] = {}
    for tid, meta in techniques.items():
        primary_tactic = meta["tactic"].split(",")[0].strip()
        tactic_groups.setdefault(primary_tactic, []).append(tid)

    tactics = sorted(tactic_groups.keys())
    max_rows = max(len(v) for v in tactic_groups.values()) if tactic_groups else 0

    z, id_labels, hover_text = [], [], []
    for row in range(max_rows):
        z_row, id_row, hover_row = [], [], []
        for tactic in tactics:
            ids_in_tactic = sorted(tactic_groups[tactic])
            if row < len(ids_in_tactic):
                tid = ids_in_tactic[row]
                count = technique_frequency_map.get(tid, 0)
                name = techniques[tid]["name"]
                z_row.append(count)
                id_row.append(tid)
                hover_row.append(f"{tid} — {name}<br>{count} incident(s)")
            else:
                z_row.append(None)
                id_row.append("")
                hover_row.append("")
        z.append(z_row)
        id_labels.append(id_row)
        hover_text.append(hover_row)

    fig = go.Figure(data=go.Heatmap(
        z=z, x=tactics, text=id_labels, texttemplate="%{text}",
        customdata=hover_text, hovertemplate="%{customdata}<extra></extra>",
        colorscale=[[0, "#1a1d29"], [0.01, "#2d3436"], [0.35, "#f1c40f"],
                    [0.65, "#e67e22"], [1, "#c0392b"]],
        showscale=True, colorbar=dict(title="Incidents"),
        xgap=3, ygap=3,
    ))
    fig.update_layout(
        title="MITRE ATT&CK Coverage Heatmap",
        yaxis=dict(showticklabels=False, autorange="reversed"),
        xaxis=dict(side="top"),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig
