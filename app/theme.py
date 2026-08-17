"""ITRAP's near-black glass design system."""

from __future__ import annotations

import streamlit as st

from app.utils.session import navigate_to


THEME_CSS = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;600&family=Space+Grotesk:wght@600;700&family=Sora:wght@500;600;700&display=swap');
:root{
  --ink:#050507;--surface:rgba(10,10,14,.74);--surface-2:rgba(14,14,20,.86);
  --line:rgba(255,255,255,.105);--violet:#8b5cf6;--violet-dark:#4c1d95;
  --text:#f7f7fb;--muted:#9595a4;--cyan:#22d3ee;--green:#34d399;
  --amber:#fbbf24;--red:#fb4b5f;
}
@keyframes edgePulse{0%,100%{border-color:rgba(139,92,246,.16);box-shadow:inset 0 1px rgba(255,255,255,.025),0 0 0 rgba(76,29,149,0),0 14px 36px rgba(0,0,0,.24)}50%{border-color:rgba(139,92,246,.46);box-shadow:inset 0 1px rgba(255,255,255,.04),0 0 20px rgba(76,29,149,.22),0 16px 42px rgba(0,0,0,.32)}}
@keyframes mapScan{0%{transform:translateY(-120%);opacity:0}15%{opacity:.28}75%{opacity:.16}100%{transform:translateY(900%);opacity:0}}
@keyframes mapBreathe{0%,100%{box-shadow:inset 0 0 0 1px rgba(139,92,246,.12),inset 0 0 38px rgba(76,29,149,.08),0 0 18px rgba(76,29,149,.16),0 18px 44px rgba(0,0,0,.38)}50%{box-shadow:inset 0 0 0 1px rgba(167,139,250,.32),inset 0 0 54px rgba(76,29,149,.15),0 0 36px rgba(91,33,182,.32),0 22px 54px rgba(0,0,0,.48)}}
@keyframes ambientDrift{0%,100%{transform:translate3d(-4%,-3%,0) scale(1)}50%{transform:translate3d(4%,3%,0) scale(1.08)}}
@keyframes activeGlow{0%,100%{box-shadow:inset 0 -3px #7c3aed,0 0 10px rgba(76,29,149,.18)}50%{box-shadow:inset 0 -3px #a78bfa,0 0 26px rgba(109,40,217,.42)}}
@keyframes navSignal{0%,100%{filter:brightness(1);box-shadow:inset 0 -3px #7c3aed,0 0 12px rgba(76,29,149,.26)}50%{filter:brightness(1.15);box-shadow:inset 0 -3px #c4b5fd,0 0 30px rgba(109,40,217,.55)}}
@keyframes onlinePulse{0%,100%{box-shadow:inset 0 0 12px rgba(52,211,153,.08),0 0 12px rgba(52,211,153,.18)}50%{box-shadow:inset 0 0 18px rgba(52,211,153,.16),0 0 25px rgba(52,211,153,.38)}}
@keyframes sheen{0%{transform:translateX(-160%) skewX(-22deg)}100%{transform:translateX(280%) skewX(-22deg)}}
html,body,[class*="css"]{font-family:'Inter',sans-serif}
.stApp{color:var(--text);background:
  radial-gradient(circle at 50% -18%,rgba(76,29,149,.24),transparent 40%),
  radial-gradient(circle at 102% 55%,rgba(76,29,149,.14),transparent 34%),
  radial-gradient(circle at -2% 82%,rgba(109,40,217,.11),transparent 30%),
  linear-gradient(180deg,#050507 0%,#07070a 60%,#050507 100%)}
.stApp::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.16;
  background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);
  background-size:48px 48px;mask-image:linear-gradient(to bottom,black,transparent 80%)}
[data-testid="stSidebar"],button[data-testid="stSidebarCollapseButton"]{display:none!important}
.block-container{max-width:1720px;padding:.34rem 1rem .4rem}
.stMainBlockContainer>div>[data-testid="stVerticalBlock"]{gap:.24rem}
.st-key-overview_main_row [data-testid="stVerticalBlock"]{gap:.22rem}
header[data-testid="stHeader"]{background:transparent;height:0}
#MainMenu,footer,.stDeployButton,header [data-testid="stToolbar"]{display:none!important}
h1,h2,h3{font-family:'Sora',sans-serif!important;color:#fff!important;letter-spacing:-.025em}
code,.mono,[data-testid="stMetricValue"]{font-family:'JetBrains Mono',monospace!important}
hr{border-color:var(--line)!important;margin:.7rem 0!important}
.itrap-header{margin:0;padding:0;position:relative}.itrap-header::after{content:"";position:absolute;left:50px;bottom:-7px;width:126px;height:1px;background:linear-gradient(90deg,#8b5cf6,rgba(34,211,238,.5),transparent);box-shadow:0 0 10px #6d28d9}
.itrap-brand{display:flex;align-items:center;gap:.65rem}.itrap-mark{width:43px;height:43px;filter:drop-shadow(0 0 11px rgba(139,92,246,.28))}
.itrap-name{font:700 1.42rem 'Space Grotesk';letter-spacing:.08em;color:#fff;line-height:1}
.itrap-full{font-size:.64rem;color:#a7a7b5;letter-spacing:.035em;margin-top:.2rem}
.itrap-status{display:flex;align-items:center;justify-content:flex-end;gap:.38rem;flex-wrap:nowrap;padding-top:.22rem}
.status-pill{border:1px solid var(--line);border-radius:9px;background:rgba(8,8,11,.72);padding:.37rem .55rem;color:#b8b8c3;font-size:.66rem;white-space:nowrap;backdrop-filter:blur(18px)}
.status-pill.live{color:#5bffc0;background:rgba(4,30,22,.78);border-color:rgba(52,211,153,.62);animation:onlinePulse 2.8s ease-in-out infinite}.status-pill.warn{color:#ffd36d;border-color:rgba(251,191,36,.23)}
.page-heading{margin:-.08rem 0 .18rem}.page-heading h1{font-size:1.25rem!important;margin:0}.page-heading p{margin:.03rem 0 0;color:var(--muted);font-size:.64rem}
div[data-testid="stMetric"]{position:relative;background:linear-gradient(145deg,rgba(13,13,18,.88),rgba(7,7,10,.72));border:1px solid rgba(139,92,246,.16);border-radius:12px;padding:.47rem .62rem;min-height:66px;box-shadow:inset 0 1px rgba(255,255,255,.025),0 12px 30px rgba(0,0,0,.2);backdrop-filter:blur(18px);animation:edgePulse 5.6s ease-in-out infinite}
div[data-testid="stMetric"]:nth-child(2n){animation-delay:-1.4s}div[data-testid="stMetric"]:nth-child(3n){animation-delay:-2.8s}
div[data-testid="stMetric"]:hover{border-color:rgba(139,92,246,.32);box-shadow:0 0 0 1px rgba(76,29,149,.12),0 14px 38px rgba(0,0,0,.3)}
div[data-testid="stMetric"] label{color:var(--muted)!important;font-size:.58rem!important;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
div[data-testid="stMetricValue"]{font-size:1.12rem!important;color:#fff}
[data-testid="stPlotlyChart"],[data-testid="stDataFrame"],div[data-testid="stExpander"],div[data-testid="stJson"]{position:relative;background:var(--surface);border:1px solid rgba(139,92,246,.19);border-radius:14px;overflow:hidden;box-shadow:inset 0 1px rgba(255,255,255,.025),0 0 16px rgba(76,29,149,.12),0 16px 40px rgba(0,0,0,.28);backdrop-filter:blur(20px);transition:border-color .25s ease,box-shadow .25s ease,transform .25s ease}
[data-testid="stPlotlyChart"]:hover,[data-testid="stDataFrame"]:hover,div[data-testid="stExpander"]:hover{border-color:rgba(139,92,246,.55);box-shadow:inset 0 1px rgba(255,255,255,.035),0 0 26px rgba(76,29,149,.26),0 18px 46px rgba(0,0,0,.34)}
/* Animated scan passes over the large first (GeoIP) chart. */
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:first-child [data-testid="stPlotlyChart"]{animation:mapBreathe 5.4s ease-in-out infinite}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:first-child [data-testid="stPlotlyChart"]::after{content:"";position:absolute;z-index:4;pointer-events:none;left:0;right:0;top:0;height:42px;background:linear-gradient(180deg,transparent,rgba(139,92,246,.18),rgba(34,211,238,.09),transparent);filter:blur(3px);animation:mapScan 6.2s linear infinite}
.map-fullscreen-shell~[data-testid="stHorizontalBlock"]+[data-testid="stPlotlyChart"],.st-key-fullscreen_map_Demo_Data,.st-key-fullscreen_map_Live_Splunk,.st-key-fullscreen_map_Combined{animation:mapBreathe 5.4s ease-in-out infinite}
body:has(.map-fullscreen-shell) .st-key-primary_navigation{visibility:hidden!important}
body:has(.map-fullscreen-shell) .block-container{padding-bottom:.7rem}
div.stButton>button,div.stDownloadButton>button,button[data-testid^="stBaseButton"],button[data-testid="stPopoverButton"]{position:relative;overflow:hidden;border-radius:10px;border:1px solid rgba(139,92,246,.3)!important;background:rgba(10,10,14,.84)!important;color:#eeeaf8!important;font-weight:600;min-height:2.35rem;box-shadow:inset 0 1px rgba(255,255,255,.035),0 0 12px rgba(76,29,149,.1);transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease}
div.stButton>button::before,div.stDownloadButton>button::before{content:"";position:absolute;inset:-20% auto -20% -35%;width:24%;background:linear-gradient(90deg,transparent,rgba(196,181,253,.38),transparent);transform:skewX(-22deg)}
div.stButton>button:hover,div.stDownloadButton>button:hover,button[data-testid^="stBaseButton"]:hover,button[data-testid="stPopoverButton"]:hover{border-color:#8b5cf6!important;color:#fff!important;transform:translateY(-2px);box-shadow:0 0 24px rgba(76,29,149,.34)}
div.stButton>button:active,div.stDownloadButton>button:active{transform:translateY(0) scale(.975);box-shadow:0 0 34px rgba(109,40,217,.48)}
div.stButton>button:hover::before,div.stDownloadButton>button:hover::before{animation:sheen .8s ease-out}
div[data-baseweb="select"]>div,div[data-baseweb="input"]>div,textarea{background:rgba(9,9,13,.9)!important;border-color:var(--line)!important;border-radius:10px!important}
[data-baseweb="tab-list"]{gap:.28rem;background:rgba(8,8,11,.8);padding:.3rem;border:1px solid var(--line);border-radius:12px}
[data-baseweb="tab"]{border-radius:8px;padding:.45rem .68rem;font-size:.78rem}[aria-selected="true"][data-baseweb="tab"]{background:rgba(76,29,149,.28);color:#fff}
[data-testid="stAlert"]{border-radius:12px;border:1px solid var(--line);background:rgba(12,12,17,.9)}
div[role="radiogroup"]{gap:.28rem}
div[role="radiogroup"] label{background:rgba(8,8,11,.94);border:1px solid var(--line);border-radius:11px;padding:.46rem .68rem}
div[role="radiogroup"] label{transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease}div[role="radiogroup"] label:hover{transform:translateY(-2px);border-color:rgba(139,92,246,.5);box-shadow:0 0 20px rgba(76,29,149,.24)}
div[role="radiogroup"] label:has(input:checked){border-color:rgba(139,92,246,.72);background:rgba(18,14,27,.96);animation:activeGlow 2.8s ease-in-out infinite}
div[role="radiogroup"] label>div:first-child{display:none}
label[data-testid="stRadioOption"] div:not([data-testid]):not(:has([data-testid="stMarkdownContainer"])){display:none!important}
.st-key-header_mode [data-testid="stButtonGroup"]{padding:3px;border:1px solid rgba(139,92,246,.28);border-radius:11px;background:rgba(5,5,9,.78);box-shadow:inset 0 0 18px rgba(76,29,149,.09)}
.st-key-header_mode button{min-height:34px!important;padding:.2rem .46rem!important;font-size:.62rem!important;border-radius:8px!important;white-space:nowrap!important}
.st-key-header_mode button[aria-pressed="true"]{border-color:rgba(167,139,250,.75)!important;background:rgba(76,29,149,.38)!important;box-shadow:0 0 18px rgba(109,40,217,.34)!important;color:#fff!important}
.st-key-header_help button,.st-key-header_settings button{min-height:34px!important;min-width:36px!important;padding:.2rem!important;font-size:.82rem!important}
.alien-help{font-size:.76rem;color:#c9c7d4}.alien-help b{color:#c4b5fd}.alien-help code{color:#67e8f9}.alien-help hr{margin:.45rem 0!important}
/* Top navigation bar (replaces the old right-side dock) - never covers the map. */
.st-key-primary_navigation{position:sticky;top:.5rem;z-index:30;background:linear-gradient(155deg,rgba(13,9,20,.94),rgba(4,4,7,.96));border:1px solid rgba(139,92,246,.36);border-radius:13px;padding:.28rem;backdrop-filter:blur(26px);box-shadow:inset 0 1px rgba(196,181,253,.09),0 0 22px rgba(76,29,149,.2),0 14px 34px rgba(0,0,0,.42);margin-bottom:.4rem}
.st-key-primary_navigation div[role="radiogroup"]{display:flex!important;flex-direction:row!important;flex-wrap:nowrap!important;gap:.26rem!important;width:100%;justify-content:stretch!important}
.st-key-primary_navigation label{flex:1 1 0;justify-content:center!important;align-items:center;min-height:34px;margin:0!important;padding:.4rem .3rem!important;font-size:.63rem!important;line-height:1.05!important;white-space:nowrap!important;text-align:center}
.st-key-primary_navigation label:has(input:checked){animation:navSignal 2.5s ease-in-out infinite;color:#fff;text-shadow:0 0 12px rgba(196,181,253,.65)}
.st-key-primary_navigation label:hover{transform:translateY(-2px)!important}
/* HUD side panels (System Status / Live Event Monitor / Threat Level / Incident Summary). */
.hud-card{position:relative;background:linear-gradient(150deg,rgba(13,13,18,.86),rgba(7,7,10,.7));border:1px solid rgba(139,92,246,.18);border-radius:11px;padding:.32rem .5rem .34rem;margin-bottom:.22rem;box-shadow:inset 0 1px rgba(255,255,255,.02),0 10px 26px rgba(0,0,0,.22);backdrop-filter:blur(16px);animation:edgePulse 6.4s ease-in-out infinite}
.hud-title{font:700 .6rem 'Sora',sans-serif;letter-spacing:.09em;color:#c9c2e8;margin-bottom:.22rem;text-transform:uppercase}
.hud-row{display:flex;justify-content:space-between;align-items:center;padding:.08rem 0;font-size:.66rem;border-bottom:1px dashed rgba(255,255,255,.05)}
.hud-row:last-child{border-bottom:none}
.hud-label{color:var(--muted)}
.hud-value{color:#eceaf5;font-family:'JetBrains Mono',monospace;font-weight:600;font-size:.66rem}
.hud-value.hud-on{color:#5bffc0}.hud-value.hud-warn{color:#ffd36d}.hud-value.hud-off{color:#ff8fa0}
.hud-empty{color:#767686;font-size:.68rem;padding:.5rem 0;text-align:center}
.hud-latest{margin:.32rem 0;padding:.36rem .4rem;border-left:2px solid #8b5cf6;background:rgba(139,92,246,.07);border-radius:0 8px 8px 0}
.hud-latest-title{font-size:.68rem;color:#f0edfb;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hud-latest-meta{font-size:.6rem;color:var(--muted);margin-top:.1rem}
.threat-badge{display:inline-block;font:800 .82rem 'Space Grotesk';letter-spacing:.06em;padding:.16rem .55rem;border-radius:7px;margin:.1rem 0 .38rem}
.threat-on{color:#5bffc0;background:rgba(6,32,24,.7);border:1px solid rgba(52,211,153,.4)}
.threat-warn{color:#ffd36d;background:rgba(38,26,4,.7);border:1px solid rgba(251,191,36,.4)}
.threat-off{color:#ff8fa0;background:rgba(40,6,12,.7);border:1px solid rgba(251,75,95,.45);animation:onlinePulse 2.4s ease-in-out infinite}
.risk-bar{display:flex;gap:3px;margin:.22rem 0 .42rem}
.risk-seg{flex:1;height:6px;border-radius:3px;background:rgba(255,255,255,.06)}
.risk-seg-0.active{background:#34d399;box-shadow:0 0 8px rgba(52,211,153,.5)}
.risk-seg-1.active{background:#fbbf24;box-shadow:0 0 8px rgba(251,191,36,.5)}
.risk-seg-2.active{background:#fb923c;box-shadow:0 0 8px rgba(251,146,60,.5)}
.risk-seg-3.active{background:#fb4b5f;box-shadow:0 0 8px rgba(251,75,95,.5)}
/* Quick Actions strip. */
.quick-actions-label{font:700 .58rem 'Sora',sans-serif;letter-spacing:.1em;color:#9d94c4;margin:.05rem 0 .5rem;text-transform:uppercase;position:relative;z-index:1}
.st-key-qa_contain button{border-color:rgba(251,191,36,.5)!important;color:#ffd980!important}
.st-key-qa_contain button:hover{border-color:#fb923c!important;box-shadow:0 0 22px rgba(251,146,60,.34)!important}
/* Vertical Quick Actions panel (left column, below Live Event Monitor). */
.st-key-quick_actions_panel{margin-top:.15rem}
.st-key-quick_actions_panel [data-testid="stVerticalBlock"]{gap:.22rem}
.st-key-quick_actions_panel div.stButton>button{min-height:1.78rem!important;padding:.22rem .5rem!important;font-size:.66rem!important;justify-content:flex-start!important}
/* Top KPI strip - six unified cards (value + embedded sparkline) directly
   under the nav bar. The column itself is the card; the native stMetric and
   stPlotlyChart elements inside go transparent/borderless so they read as
   one piece instead of two stacked cards. */
.st-key-kpi_strip{margin-bottom:.2rem}
.st-key-kpi_strip [data-testid="stColumn"]{position:relative;background:linear-gradient(150deg,rgba(13,13,18,.86),rgba(7,7,10,.7));border:1px solid rgba(139,92,246,.18);border-radius:11px;padding:.32rem .5rem .2rem;box-shadow:inset 0 1px rgba(255,255,255,.02),0 10px 22px rgba(0,0,0,.2);backdrop-filter:blur(16px);animation:edgePulse 6.2s ease-in-out infinite}
.st-key-kpi_strip [data-testid="stColumn"]:nth-child(2n){animation-delay:-1.5s}
.st-key-kpi_strip [data-testid="stColumn"]:nth-child(3n){animation-delay:-3.1s}
.st-key-kpi_strip [data-testid="stColumn"]:hover{border-color:rgba(139,92,246,.4);box-shadow:0 0 0 1px rgba(76,29,149,.14),0 14px 30px rgba(0,0,0,.28)}
.st-key-kpi_strip [data-testid="stMetric"]{background:transparent!important;border:none!important;box-shadow:none!important;padding:0!important;min-height:auto!important;animation:none!important;backdrop-filter:none!important}
.st-key-kpi_strip [data-testid="stMetricLabel"] p{font-size:.56rem!important}
.st-key-kpi_strip [data-testid="stMetricValue"]{font-size:.98rem!important}
.st-key-kpi_strip [data-testid="stPlotlyChart"]{background:transparent!important;border:none!important;box-shadow:none!important;backdrop-filter:none!important;margin-top:-8px}
/* Overview footer row (GeoIP caption / last-sync caption / Full map /
   Alert volume / Recent incidents) - kept as compact as the KPI strip so it
   never pushes the page past one viewport. */
.st-key-overview_footer_row{margin-top:0}
.st-key-overview_footer_row div.stButton>button,.st-key-overview_footer_row button[data-testid="stPopoverButton"]{min-height:1.7rem!important;padding:.18rem .4rem!important;font-size:.62rem!important}
.st-key-overview_footer_row [data-testid="stCaptionContainer"]{margin:0!important}
.st-key-overview_footer_row [data-testid="stCaptionContainer"] p{font-size:.62rem!important;margin:0!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media(max-width:1300px){.block-container{padding:.4rem .7rem .9rem}}
@media(max-width:1050px){.block-container{padding:.45rem .6rem .8rem}.itrap-full{display:none}.itrap-mark{width:38px;height:38px}.st-key-primary_navigation div[role="radiogroup"]{flex-wrap:wrap!important}.st-key-primary_navigation label{flex:1 1 22%;padding:.34rem .2rem!important;font-size:.56rem!important}.itrap-status .status-pill:nth-child(n+2){display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
"""


def inject_theme() -> None:
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def app_header(*, logo_svg: str, data_mode: str, data_modes: tuple[str, ...], splunk_status: dict, simulation: bool) -> str:
    splunk_class = "live" if splunk_status["online"] else "warn"
    splunk_label = "SPLUNK ONLINE" if splunk_status["online"] else "SPLUNK OFFLINE"
    splunk_title = splunk_status.get("detail", "")
    response_label = "SIMULATION SAFE" if simulation else "REAL ACTIONS"
    brand_col, mode_col, status_col, help_col, settings_col = st.columns([3.5, 3.25, 1.75, .34, .34], gap="small", vertical_alignment="center")
    with brand_col:
        st.markdown(
            f'<div class="itrap-header"><div class="itrap-brand">{logo_svg}'
            '<div><div class="itrap-name">ITRAP</div>'
            '<div class="itrap-full">Identity Threat Response Automation Platform</div></div></div></div>',
            unsafe_allow_html=True,
        )
    with mode_col:
        selected = st.segmented_control(
            "Data source", data_modes, default=data_mode,
            label_visibility="collapsed", key="header_mode",
        ) or data_mode
    with status_col:
        st.markdown(
            f'<div class="itrap-status"><span class="status-pill {splunk_class}" title="{splunk_title}">● {splunk_label}</span>'
            f'<span class="status-pill warn">◐ {response_label}</span></div>',
            unsafe_allow_html=True,
        )
    with help_col:
        with st.popover("?", use_container_width=True, help="Help"):
            st.markdown(
                '<div class="alien-help"><b>DATA MODES</b><br>'
                '<code>Demo Data</code> — safe built-in attack scenarios, default on startup.<br>'
                '<code>Live Splunk</code> — only events actually ingested from Splunk.<br>'
                '<code>Combined</code> — demo and Splunk evidence together. Switching never happens silently.<hr>'
                '<b>SPLUNK CONNECTION &amp; SYNC</b><br>Open Settings → Splunk → Test Connection, then Sync Events. '
                '<code>SPLUNK ONLINE</code> only appears after a real successful test or sync — a configured token alone is not '
                'treated as proof of connectivity. If offline, Live Splunk stays selectable and simply shows an empty state.<hr>'
                '<b>INVESTIGATION WORKFLOW</b><br>Alerts → Incidents → Threat Intel / MITRE ATT&CK → Response. '
                'AI analysis is advisory only and never triggers a response action.<hr>'
                '<b>SIMULATION SAFETY</b><br>Response actions run in simulation by default — nothing real changes. '
                'Real actions require an explicit request plus a second analyst approval.<hr>'
                '<b>FULL MAP</b><br>Use ⛶ Full map to zoom, pan and inspect source-evidence hover details full-screen; '
                '← Overview returns instantly.<hr>'
                '<b>REPORTS</b><br>Generate a PDF or HTML incident report from the Reports page or the Export Report '
                'quick action — includes timeline, MITRE mapping, AI notes and analyst decisions.</div>',
                unsafe_allow_html=True,
            )
    with settings_col:
        if st.button("⚙", help="Open Settings", use_container_width=True, key="header_settings"):
            navigate_to("Settings")
            st.rerun()
    return selected


def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(
        f'<div class="page-heading"><h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )
