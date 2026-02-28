from scapy.all import sniff, TCP, IP
import numpy as np
import streamlit as st
import joblib
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['figure.facecolor'] = '#0e1117'
matplotlib.rcParams['axes.facecolor'] = '#1a1f2e'
matplotlib.rcParams['axes.edgecolor'] = '#2d3748'
matplotlib.rcParams['text.color'] = '#e2e8f0'
matplotlib.rcParams['axes.labelcolor'] = '#94a3b8'
matplotlib.rcParams['xtick.color'] = '#94a3b8'
matplotlib.rcParams['ytick.color'] = '#94a3b8'
matplotlib.rcParams['grid.color'] = '#2d3748'
import shap
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter
import time

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Base ── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
  }

  .stApp { background: #070b14; }

  /* ── Hide default Streamlit chrome ── */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1400px; }

  /* ── Sidebar ── */
  section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1e2d40;
  }
  section[data-testid="stSidebar"] .stSlider > div > div {
    background: #1e2d40;
  }

  /* ── Top banner ── */
  .top-banner {
    background: linear-gradient(135deg, #0d1b2a 0%, #112240 50%, #0d1b2a 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .banner-title {
    font-size: 1.8rem;
    font-weight: 700;
    background: linear-gradient(90deg, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.02em;
  }
  .banner-sub {
    font-size: 0.85rem;
    color: #475569;
    margin-top: 0.2rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .status-pill {
    background: #0a2a1a;
    border: 1px solid #14532d;
    border-radius: 999px;
    padding: 0.35rem 1rem;
    font-size: 0.78rem;
    color: #4ade80;
    font-family: 'JetBrains Mono', monospace;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .pulse-dot {
    width: 8px; height: 8px;
    background: #4ade80;
    border-radius: 50%;
    animation: pulse 1.5s infinite;
    display: inline-block;
  }
  @keyframes pulse {
    0%,100% { opacity:1; transform:scale(1); }
    50%      { opacity:.4; transform:scale(1.3); }
  }

  /* ── Metric cards ── */
  .metric-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin:1rem 0; }
  .metric-card {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    transition: border-color .2s;
  }
  .metric-card:hover { border-color: #38bdf8; }
  .metric-label { font-size:0.72rem; color:#475569; text-transform:uppercase; letter-spacing:.08em; font-weight:600; }
  .metric-value { font-size:1.6rem; font-weight:700; color:#e2e8f0; margin:.25rem 0 0; font-family:'JetBrains Mono',monospace; }
  .metric-badge { font-size:0.72rem; margin-top:.3rem; padding:.2rem .6rem; border-radius:999px; display:inline-block; font-weight:600; }
  .badge-danger  { background:#2d1515; color:#f87171; border:1px solid #7f1d1d; }
  .badge-safe    { background:#0a2a1a; color:#4ade80; border:1px solid #14532d; }
  .badge-warn    { background:#2d2007; color:#fbbf24; border:1px solid #78350f; }
  .badge-info    { background:#0c1a2e; color:#38bdf8; border:1px solid #1e40af; }

  /* ── Verdict banner ── */
  .verdict-malicious {
    background: linear-gradient(135deg, #2d0a0a, #3d1515);
    border: 1px solid #ef4444;
    border-radius: 10px;
    padding: 1.2rem 1.5rem;
    display: flex; align-items:center; gap:1rem;
  }
  .verdict-benign {
    background: linear-gradient(135deg, #0a2a1a, #0d3b25);
    border: 1px solid #22c55e;
    border-radius: 10px;
    padding: 1.2rem 1.5rem;
    display: flex; align-items:center; gap:1rem;
  }
  .verdict-icon { font-size:2rem; }
  .verdict-title { font-size:1.3rem; font-weight:700; }
  .verdict-title.mal { color:#f87171; }
  .verdict-title.ok  { color:#4ade80; }
  .verdict-reason { font-size:0.82rem; color:#94a3b8; margin-top:.2rem; font-family:'JetBrains Mono',monospace; }

  /* ── Section headers ── */
  .section-head {
    font-size:.7rem; text-transform:uppercase; letter-spacing:.15em;
    color:#38bdf8; font-weight:700; margin:1.5rem 0 .75rem;
    display:flex; align-items:center; gap:.5rem;
  }
  .section-head::after {
    content:''; flex:1; height:1px; background:linear-gradient(90deg,#1e3a5f,transparent);
  }

  /* ── Tabs ── */
  .stTabs [data-baseweb="tab-list"] {
    background: #0d1117;
    border-radius: 8px;
    border: 1px solid #1e2d40;
    padding: 0.3rem;
    gap: 0.2rem;
  }
  .stTabs [data-baseweb="tab"] {
    border-radius: 6px;
    color: #475569 !important;
    font-size: 0.82rem;
    font-weight: 500;
    padding: .4rem 1rem;
  }
  .stTabs [aria-selected="true"] {
    background: #1e2d40 !important;
    color: #38bdf8 !important;
  }

  /* ── Buttons ── */
  .stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #0ea5e9, #6366f1) !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    padding: .6rem 1.5rem !important;
    transition: opacity .2s !important;
    color: white !important;
  }
  .stButton > button[kind="primary"]:hover { opacity: .85 !important; }

  /* ── Progress ── */
  .stProgress > div > div { background: linear-gradient(90deg, #0ea5e9, #6366f1); }

  /* ── Dataframe ── */
  .stDataFrame { border: 1px solid #1e2d40; border-radius: 8px; overflow:hidden; }

  /* ── Info / Error boxes ── */
  .stAlert { border-radius: 8px; }

  /* ── Sidebar labels ── */
  .sidebar-section {
    font-size:.68rem; text-transform:uppercase; letter-spacing:.12em;
    color:#38bdf8; font-weight:700; margin:1.2rem 0 .5rem;
  }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# PLOTLY DARK THEME HELPER
# ─────────────────────────────────────────────
DARK_LAYOUT = dict(
    paper_bgcolor='#0d1117',
    plot_bgcolor='#0d1117',
    font=dict(color='#94a3b8', family='Inter'),
    xaxis=dict(gridcolor='#1e2d40', linecolor='#2d3748', zeroline=False),
    yaxis=dict(gridcolor='#1e2d40', linecolor='#2d3748', zeroline=False),
    margin=dict(l=40, r=20, t=50, b=40),
    legend=dict(bgcolor='#0d1117', bordercolor='#1e2d40', borderwidth=1)
)

# ─────────────────────────────────────────────
# MODEL LOADING
# ─────────────────────────────────────────────
@st.cache_resource
def load_models():
    try:
        xgb_model = joblib.load('production/xgb_production_v1.pkl')
        iso_model = joblib.load('production/iso_production_v1.pkl')
        try:
            background_data = joblib.load('production/background_data.pkl')
        except:
            background_data = None
        return xgb_model, iso_model, background_data
    except FileNotFoundError:
        st.error("Model files not found. Please check paths.")
        return None, None, None

# ─────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────
def extract_flow_features(packets):
    tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and pkt.haslayer(IP)]
    if not tcp_packets:
        return None

    first_pkt = tcp_packets[0]
    src_ip   = first_pkt[IP].src
    src_port = first_pkt[TCP].sport
    start_time = tcp_packets[0].time
    end_time   = tcp_packets[-1].time
    flow_duration = max(end_time - start_time, 1e-6)

    fwd_lengths, bwd_lengths = [], []
    fwd_timestamps, bwd_timestamps = [], []
    packet_sizes, packet_times, packet_directions = [], [], []
    syn_count = ack_count = fin_count = rst_count = psh_count = urg_count = 0

    for pkt in tcp_packets:
        size = len(pkt)
        packet_sizes.append(size)
        packet_times.append(pkt.time - start_time)
        flags = pkt[TCP].flags
        if flags & 0x02: syn_count += 1
        if flags & 0x10: ack_count += 1
        if flags & 0x01: fin_count += 1
        if flags & 0x04: rst_count += 1
        if flags & 0x08: psh_count += 1
        if flags & 0x20: urg_count += 1
        if pkt[IP].src == src_ip and pkt[TCP].sport == src_port:
            fwd_lengths.append(size); fwd_timestamps.append(pkt.time)
            packet_directions.append('Forward')
        else:
            bwd_lengths.append(size); bwd_timestamps.append(pkt.time)
            packet_directions.append('Backward')

    total_bytes   = sum(len(p) for p in tcp_packets)
    total_packets = len(tcp_packets)
    flow_bytes_ps = total_bytes / flow_duration
    flow_pkts_ps  = total_packets / flow_duration

    all_ts  = sorted(p.time for p in tcp_packets)
    iat     = np.diff(all_ts) if len(all_ts) > 1 else np.array([0])
    fwd_iat = np.diff(sorted(fwd_timestamps)) if len(fwd_timestamps) > 1 else np.array([0])
    bwd_iat = np.diff(sorted(bwd_timestamps)) if len(bwd_timestamps) > 1 else np.array([0])

    sm = lambda x: np.mean(x)  if len(x) else 0
    ss = lambda x: np.std(x)   if len(x) else 0
    sx = lambda x: np.max(x)   if len(x) else 0
    sn = lambda x: np.min(x)   if len(x) else 0
    su = lambda x: np.sum(x)   if len(x) else 0
    sv = lambda x: np.var(x)   if len(x) else 0

    features = [
        flow_duration, total_bytes, total_packets,
        len(fwd_lengths), len(bwd_lengths),
        su(fwd_lengths), su(bwd_lengths),
        sm(fwd_lengths), ss(fwd_lengths),
        sm(bwd_lengths), ss(bwd_lengths),
        flow_bytes_ps, flow_pkts_ps,
        sm(iat), ss(iat), sx(iat), sn(iat),
        sm(fwd_iat), ss(fwd_iat), sx(fwd_iat), sn(fwd_iat),
        sm(bwd_iat), ss(bwd_iat), sx(bwd_iat), sn(bwd_iat),
        fin_count, syn_count, rst_count, psh_count, ack_count, urg_count,
        sm(fwd_lengths + bwd_lengths), sv(fwd_lengths + bwd_lengths)
    ]
    assert len(features) == 33

    return np.array(features, dtype=float).reshape(1, -1), {
        'packet_sizes': packet_sizes, 'packet_times': packet_times,
        'packet_directions': packet_directions,
        'fwd_lengths': fwd_lengths, 'bwd_lengths': bwd_lengths,
        'iat': iat, 'total_packets': total_packets, 'flow_duration': flow_duration
    }

# ─────────────────────────────────────────────
# SHAP
# ─────────────────────────────────────────────
def create_shap_explanation(model, X, feature_names, background_data=None):
    try:
        explainer = shap.TreeExplainer(model, background_data) if background_data is not None else shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        return shap_values[0], explainer.expected_value
    except Exception as e:
        st.warning(f"SHAP unavailable: {e}")
        return None, None

def plot_feature_importance(shap_values, feature_names, expected_value, prediction_prob):
    if shap_values is None:
        return None
    fig, ax = plt.subplots(figsize=(10, 7))
    top_idx = np.argsort(np.abs(shap_values))[-15:]
    vals  = shap_values[top_idx]
    names = [feature_names[i] for i in top_idx]
    colors = ['#ef4444' if v > 0 else '#38bdf8' for v in vals]
    y_pos = np.arange(len(names))
    bars = ax.barh(y_pos, vals, color=colors, height=0.6)
    ax.set_yticks(y_pos); ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel('SHAP Value  (← Benign   |   Malicious →)', fontsize=9)
    ax.set_title(f'Feature Impact Analysis  ·  Prediction Score: {prediction_prob:.3f}', fontsize=10, pad=12)
    ax.axvline(x=0, color='#4b5563', linewidth=1)
    ax.grid(axis='x', alpha=0.3)
    for bar, val in zip(bars, vals):
        ax.text(val + (0.002 if val >= 0 else -0.002),
                bar.get_y() + bar.get_height()/2,
                f'{val:.3f}', va='center',
                ha='left' if val >= 0 else 'right',
                fontsize=7.5, color='#94a3b8')
    plt.tight_layout()
    return fig

# ─────────────────────────────────────────────
# PLOTLY CHARTS
# ─────────────────────────────────────────────
def plot_packet_timeseries(packet_data):
    df = pd.DataFrame({
        'Time (s)': packet_data['packet_times'],
        'Packet Size': packet_data['packet_sizes'],
        'Direction': packet_data['packet_directions']
    })
    fig = px.scatter(df, x='Time (s)', y='Packet Size', color='Direction',
                     color_discrete_map={'Forward': '#38bdf8', 'Backward': '#f472b6'},
                     title='Packet Size Over Time')
    fig.update_traces(marker=dict(size=7, opacity=0.8))
    fig.update_layout(**DARK_LAYOUT)
    return fig

def plot_packet_size_distribution(packet_data):
    fwd = np.array(packet_data['fwd_lengths']) if packet_data['fwd_lengths'] else np.array([])
    bwd = np.array(packet_data['bwd_lengths']) if packet_data['bwd_lengths'] else np.array([])
    all_sizes = np.concatenate([fwd, bwd]) if (len(fwd) and len(bwd)) else (fwd if len(fwd) else bwd)

    fig = go.Figure()

    if len(fwd):
        fig.add_trace(go.Histogram(x=fwd, name=f'Forward ({len(fwd)} pkts)',
                                   marker_color='#38bdf8', opacity=0.75, nbinsx=30))
        # Mean line - forward
        fig.add_vline(x=float(np.mean(fwd)), line_dash='dash', line_color='#38bdf8', line_width=1.5,
                      annotation_text=f'Fwd μ={np.mean(fwd):.0f}B',
                      annotation_font_color='#38bdf8', annotation_font_size=11,
                      annotation_position='top right')

    if len(bwd):
        fig.add_trace(go.Histogram(x=bwd, name=f'Backward ({len(bwd)} pkts)',
                                   marker_color='#f472b6', opacity=0.75, nbinsx=30))
        # Mean line - backward
        fig.add_vline(x=float(np.mean(bwd)), line_dash='dash', line_color='#f472b6', line_width=1.5,
                      annotation_text=f'Bwd μ={np.mean(bwd):.0f}B',
                      annotation_font_color='#f472b6', annotation_font_size=11,
                      annotation_position='top left')

    # MTU reference line
    fig.add_vline(x=1500, line_dash='dot', line_color='#fbbf24', line_width=1,
                  annotation_text='MTU (1500B)', annotation_font_color='#fbbf24',
                  annotation_font_size=10, annotation_position='bottom right')

    # Build stats annotation text
    stats_lines = []
    if len(fwd):
        stats_lines.append(f"<b style='color:#38bdf8'>Forward</b>")
        stats_lines.append(f"  Mean: {np.mean(fwd):.0f}B  |  Std: {np.std(fwd):.0f}B")
        stats_lines.append(f"  Min: {np.min(fwd):.0f}B  |  Max: {np.max(fwd):.0f}B")
        stats_lines.append(f"  Total: {np.sum(fwd)/1024:.1f} KB")
    if len(bwd):
        stats_lines.append(f"<b style='color:#f472b6'>Backward</b>")
        stats_lines.append(f"  Mean: {np.mean(bwd):.0f}B  |  Std: {np.std(bwd):.0f}B")
        stats_lines.append(f"  Min: {np.min(bwd):.0f}B  |  Max: {np.max(bwd):.0f}B")
        stats_lines.append(f"  Total: {np.sum(bwd)/1024:.1f} KB")

    # Asymmetry insight
    if len(fwd) and len(bwd):
        ratio = np.mean(fwd) / max(np.mean(bwd), 1)
        if ratio > 3:
            insight = "⚠️ Large fwd/bwd asymmetry — possible data exfiltration"
            insight_color = '#ef4444'
        elif ratio < 0.33:
            insight = "⚠️ Large bwd dominance — possible download flood"
            insight_color = '#fbbf24'
        else:
            insight = "✅ Balanced bidirectional traffic"
            insight_color = '#4ade80'
        fig.add_annotation(
            x=0.98, y=0.97, xref='paper', yref='paper',
            text=insight, showarrow=False,
            font=dict(color=insight_color, size=11),
            bgcolor='#0d1117', bordercolor=insight_color, borderwidth=1,
            borderpad=6, xanchor='right', yanchor='top'
        )

    fig.update_layout(
        barmode='overlay',
        title=dict(text='Packet Size Distribution', font=dict(size=14, color='#e2e8f0')),
        xaxis_title='Packet Size (bytes)',
        yaxis_title='Count',
        **DARK_LAYOUT
    )
    return fig, stats_lines


def plot_iat_distribution(packet_data):
    iat = packet_data['iat']
    if not len(iat):
        return None, []

    iat_ms = iat * 1000
    p25, p50, p75, p95 = np.percentile(iat_ms, [25, 50, 75, 95])

    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=iat_ms, nbinsx=40,
        name='IAT',
        marker=dict(color='#818cf8', opacity=0.85),
    ))

    # Percentile lines — each label placed at a different y height to avoid overlap
    percentile_defs = [
        (p25, 'P25',        '#4ade80', 0.97),
        (p50, 'P50 median', '#fbbf24', 0.82),
        (p75, 'P75',        '#f97316', 0.67),
        (p95, 'P95',        '#ef4444', 0.52),
    ]
    for val, label, color, ypos in percentile_defs:
        fig.add_vline(x=val, line_dash='dash', line_color=color, line_width=1.5)
        fig.add_annotation(
            x=val, y=ypos, xref='x', yref='paper',
            text=f'<b>{label}</b> {val:.1f}ms',
            showarrow=False,
            font=dict(color=color, size=10, family='JetBrains Mono'),
            bgcolor='rgba(13,17,23,0.85)', bordercolor=color, borderwidth=1,
            borderpad=4, xanchor='left', yanchor='middle', xshift=7
        )

    # Burst detection insight
    burst_threshold = p95
    burst_pkts = np.sum(iat_ms < 10)  # packets arriving < 10ms apart
    total = len(iat_ms)
    burst_pct = burst_pkts / total * 100

    if burst_pct > 60:
        insight = f"⚠️ HIGH BURST ({burst_pct:.0f}% pkts < 10ms apart) — possible flood/DoS"
        insight_color = '#ef4444'
    elif burst_pct > 30:
        insight = f"⚡ Moderate bursting ({burst_pct:.0f}% pkts < 10ms)"
        insight_color = '#fbbf24'
    else:
        insight = f"✅ Steady flow ({burst_pct:.0f}% burst packets)"
        insight_color = '#4ade80'

    fig.add_annotation(
        x=0.98, y=0.97, xref='paper', yref='paper',
        text=insight, showarrow=False,
        font=dict(color=insight_color, size=11),
        bgcolor='#0d1117', bordercolor=insight_color, borderwidth=1,
        borderpad=6, xanchor='right', yanchor='top'
    )

    fig.update_layout(
        title=dict(text='Inter-Arrival Time Distribution', font=dict(size=14, color='#e2e8f0')),
        xaxis_title='IAT (ms)',
        yaxis_title='Count',
        showlegend=False,
        **DARK_LAYOUT
    )

    stats_lines = [
        f"Mean: {np.mean(iat_ms):.2f}ms  |  Std: {np.std(iat_ms):.2f}ms",
        f"Min: {np.min(iat_ms):.2f}ms  |  Max: {np.max(iat_ms):.2f}ms",
        f"Median (P50): {p50:.2f}ms  |  P95: {p95:.2f}ms",
        f"Burst packets (< 10ms): {burst_pkts}/{total} ({burst_pct:.1f}%)"
    ]
    return fig, stats_lines


def plot_flags(X):
    flag_data = {
        'FIN': X[0][25], 'SYN': X[0][26], 'RST': X[0][27],
        'PSH': X[0][28], 'ACK': X[0][29], 'URG': X[0][30]
    }
    total_flags = sum(flag_data.values())

    # Color coding: red = suspicious, yellow = notable, blue = normal
    color_map = {
        'FIN': '#fbbf24',  # connection teardown — notable
        'SYN': '#ef4444',  # connection initiation — suspicious if high
        'RST': '#ef4444',  # reset — suspicious
        'PSH': '#38bdf8',  # data push — normal
        'ACK': '#4ade80',  # acknowledgement — normal
        'URG': '#f97316',  # urgent — suspicious
    }
    colors = [color_map[k] for k in flag_data]
    pcts   = [v / max(total_flags, 1) * 100 for v in flag_data.values()]

    fig = go.Figure(go.Bar(
        x=list(flag_data.keys()),
        y=list(flag_data.values()),
        marker_color=colors,
        text=[f'{v:.0f}<br>({p:.1f}%)' for v, p in zip(flag_data.values(), pcts)],
        textposition='outside',
        textfont=dict(size=11, color='#94a3b8'),
        width=0.5
    ))

    # Threat annotations for suspicious patterns
    annotations = []
    if flag_data['SYN'] > 20:
        annotations.append("⚠️ High SYN count — possible SYN flood / port scan")
    if flag_data['RST'] > 10:
        annotations.append("⚠️ High RST count — possible connection rejection / scan")
    if flag_data['URG'] > 5:
        annotations.append("⚠️ URG flags present — unusual in normal traffic")
    if flag_data['ACK'] > 0 and flag_data['SYN'] == 0:
        annotations.append("ℹ️ ACK-only flow — mid-session or asymmetric capture")
    if not annotations:
        annotations.append("✅ Flag distribution looks normal")

    subtitle = '  |  '.join(annotations)
    fig.update_layout(
        title=dict(
            text=f'TCP Flag Distribution<br><sup style="color:#64748b">{subtitle}</sup>',
            font=dict(size=14, color='#e2e8f0')
        ),
        xaxis_title='TCP Flag',
        yaxis_title='Count',
        **DARK_LAYOUT
    )
    return fig, flag_data, total_flags

# ─────────────────────────────────────────────
# FEATURE NAMES
# ─────────────────────────────────────────────
FEATURE_NAMES = [
    "Duration","Total Bytes","Total Packets","Fwd Packets","Bwd Packets",
    "Fwd Bytes","Bwd Bytes","Fwd Len Mean","Fwd Len Std","Bwd Len Mean",
    "Bwd Len Std","Bytes/s","Packets/s","IAT Mean","IAT Std","IAT Max","IAT Min",
    "Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "FIN","SYN","RST","PSH","ACK","URG","Avg Size","Size Var"
]
FEATURE_NAMES_DISPLAY = [
    "Flow Duration (s)","Total Bytes","Total Packets","Fwd Packets","Bwd Packets",
    "Fwd Bytes","Bwd Bytes","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s",
    "IAT Mean (s)","IAT Std (s)","IAT Max (s)","IAT Min (s)",
    "Fwd IAT Mean (s)","Fwd IAT Std (s)","Fwd IAT Max (s)","Fwd IAT Min (s)",
    "Bwd IAT Mean (s)","Bwd IAT Std (s)","Bwd IAT Max (s)","Bwd IAT Min (s)",
    "FIN Count","SYN Count","RST Count","PSH Count","ACK Count","URG Count",
    "Average Packet Size","Packet Size Variance"
]
FEATURE_UNITS = [
    's','bytes','count','count','count','bytes','bytes','bytes','bytes',
    'bytes','bytes','bytes/s','packets/s','s','s','s','s','s','s','s','s',
    's','s','s','s','count','count','count','count','count','count','bytes','bytes²'
]

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0 .5rem;">
      <span style="font-size:2.5rem;">🛡️</span>
      <div style="font-size:1.1rem;font-weight:700;color:#e2e8f0;margin-top:.3rem;">NetGuard IDS</div>
      <div style="font-size:.72rem;color:#475569;font-family:'JetBrains Mono',monospace;">v2.0 · XGBoost + IsolationForest</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">⚙️ Capture Settings</div>', unsafe_allow_html=True)
    capture_time = st.slider("Duration (seconds)", 5, 30, 10)
    threshold    = st.slider("Detection Threshold", 0.1, 0.9, 0.5, 0.05)

    st.markdown('<div class="sidebar-section">📊 Visualizations</div>', unsafe_allow_html=True)
    show_shap          = st.checkbox("Feature Impact (SHAP)", value=True)
    show_timeseries    = st.checkbox("Packet Time Series",    value=True)
    show_distributions = st.checkbox("Size Distributions",    value=True)

    st.markdown('<div class="sidebar-section">ℹ️ About</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-size:.78rem;color:#475569;line-height:1.6;">
    Hybrid detection combining supervised XGBoost classification with unsupervised Isolation Forest anomaly detection over 33 network flow features.
    </div>
    """, unsafe_allow_html=True)

# ─────────────────────────────────────────────
# MAIN CONTENT
# ─────────────────────────────────────────────

# Top banner
st.markdown(f"""
<div class="top-banner">
  <div>
    <div class="banner-title">Network Intrusion Detection System</div>
    <div class="banner-sub">Real-time traffic analysis · Hybrid ML detection · Explainable AI</div>
  </div>
  <div class="status-pill">
    <span class="pulse-dot"></span>
    SYSTEM READY
  </div>
</div>
""", unsafe_allow_html=True)

# Load models
xgb_model, iso_model, background_data = load_models()
THRESHOLD = threshold

# ── Capture button ──────────────────────────
col_btn, col_info = st.columns([1, 3])
with col_btn:
    start = st.button("📡  Start Live Capture", type="primary", use_container_width=True)
with col_info:
    st.markdown(f"""
    <div style="background:#0d1117;border:1px solid #1e2d40;border-radius:8px;padding:.7rem 1rem;font-size:.8rem;color:#475569;font-family:'JetBrains Mono',monospace;margin-top:.2rem;">
      Threshold: <span style="color:#fbbf24;">{threshold:.2f}</span> &nbsp;·&nbsp;
      Duration: <span style="color:#38bdf8;">{capture_time}s</span> &nbsp;·&nbsp;
      Mode: <span style="color:#818cf8;">Hybrid (XGB + IsoForest)</span>
    </div>
    """, unsafe_allow_html=True)

# ── Capture & Analysis ──────────────────────
if start:
    if not xgb_model:
        st.error("Models not loaded. Please check model files.")
    else:
        progress_bar = st.progress(0)
        status_text  = st.empty()
        status_text.info(f"🔍 Capturing traffic for **{capture_time}s** — admin/root privileges may be required.")

        try:
            packets = sniff(timeout=capture_time)
            for i in range(100):
                time.sleep(0.01)
                progress_bar.progress(i + 1)
            status_text.success(f"✅ Captured **{len(packets)}** packets")

            result = extract_flow_features(packets)
            if result is None:
                st.warning("⚠️ No TCP packets found in the capture window.")
            else:
                X, packet_data = result
                xgb_prob  = xgb_model.predict_proba(X)[0][1]
                iso_score = iso_model.decision_function(X)[0]

                if xgb_prob >= THRESHOLD:
                    final_prediction = 1
                    reason = f"High supervised confidence ({xgb_prob:.3f} ≥ {THRESHOLD:.2f})"
                elif iso_score < 0:
                    final_prediction = 1
                    reason = f"Behavioral anomaly (Isolation score: {iso_score:.4f})"
                else:
                    final_prediction = 0
                    reason = f"Normal traffic pattern (score: {xgb_prob:.3f} < {THRESHOLD:.2f})"

                # ── Verdict ──
                st.markdown('<div class="section-head">🔐 Detection Result</div>', unsafe_allow_html=True)
                if final_prediction == 1:
                    st.markdown(f"""
                    <div class="verdict-malicious">
                      <div class="verdict-icon">🚨</div>
                      <div>
                        <div class="verdict-title mal">MALICIOUS TRAFFIC DETECTED</div>
                        <div class="verdict-reason">{reason}</div>
                      </div>
                    </div>""", unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="verdict-benign">
                      <div class="verdict-icon">✅</div>
                      <div>
                        <div class="verdict-title ok">TRAFFIC APPEARS BENIGN</div>
                        <div class="verdict-reason">{reason}</div>
                      </div>
                    </div>""", unsafe_allow_html=True)

                # ── Metrics ──
                st.markdown('<div class="section-head">📊 Flow Metrics</div>', unsafe_allow_html=True)
                def badge(label, cls):
                    return f'<div class="metric-badge {cls}">{label}</div>'

                cols = st.columns(4)
                with cols[0]:
                    st.markdown(f"""<div class="metric-card">
                      <div class="metric-label">XGB Probability</div>
                      <div class="metric-value">{xgb_prob:.3f}</div>
                      {badge("Malicious" if xgb_prob >= THRESHOLD else "Benign",
                             "badge-danger" if xgb_prob >= THRESHOLD else "badge-safe")}
                    </div>""", unsafe_allow_html=True)
                with cols[1]:
                    st.markdown(f"""<div class="metric-card">
                      <div class="metric-label">Isolation Score</div>
                      <div class="metric-value">{iso_score:.4f}</div>
                      {badge("Anomaly" if iso_score < 0 else "Normal",
                             "badge-warn" if iso_score < 0 else "badge-safe")}
                    </div>""", unsafe_allow_html=True)
                with cols[2]:
                    st.markdown(f"""<div class="metric-card">
                      <div class="metric-label">Flow Duration</div>
                      <div class="metric-value">{X[0][0]:.3f}s</div>
                      {badge(f"{packet_data['fwd_lengths'].__len__()} fwd / {packet_data['bwd_lengths'].__len__()} bwd pkts", "badge-info")}
                    </div>""", unsafe_allow_html=True)
                with cols[3]:
                    pps = int(X[0][2]) / max(X[0][0], 1e-6)
                    st.markdown(f"""<div class="metric-card">
                      <div class="metric-label">Packet Rate</div>
                      <div class="metric-value">{pps:.0f}/s</div>
                      {badge(f"{int(X[0][2])} total packets", "badge-info")}
                    </div>""", unsafe_allow_html=True)

                # ── Tabs ──
                st.markdown('<div class="section-head">📈 Deep Analysis</div>', unsafe_allow_html=True)
                tab1, tab2, tab3, tab4 = st.tabs([
                    "🔍 Feature Impact", "⏱️ Time Series",
                    "📦 Distributions", "📋 Raw Features"
                ])

                with tab1:
                    if show_shap:
                        st.markdown("""
                        <div style="font-size:.82rem;color:#64748b;margin-bottom:1rem;font-family:'JetBrains Mono',monospace;">
                        🔴 Red = pushes toward Malicious &nbsp;|&nbsp; 🔵 Blue = pushes toward Benign
                        </div>""", unsafe_allow_html=True)
                        sv, ev = create_shap_explanation(xgb_model, X, FEATURE_NAMES, background_data)
                        if sv is not None:
                            fig = plot_feature_importance(sv, FEATURE_NAMES, ev, xgb_prob)
                            if fig:
                                st.pyplot(fig); plt.close()
                        else:
                            st.info("SHAP explanation not available.")
                    else:
                        st.info("Enable SHAP in the sidebar to see feature impact analysis.")

                with tab2:
                    if show_timeseries:
                        fig = plot_packet_timeseries(packet_data)
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info("Enable Time Series in the sidebar.")

                with tab3:
                    if show_distributions:
                        # ── Row 1: Size + IAT histograms ──
                        c1, c2 = st.columns(2)

                        with c1:
                            fig_psd, psd_stats = plot_packet_size_distribution(packet_data)
                            st.plotly_chart(fig_psd, use_container_width=True)
                            # Stats panel below chart
                            if psd_stats:
                                stats_html = ''.join(
                                    f'<div style="padding:.15rem 0;font-size:.78rem;color:#94a3b8;font-family:\'JetBrains Mono\',monospace;">{line}</div>'
                                    for line in psd_stats
                                )
                                st.markdown(f"""
                                <div style="background:#0d1117;border:1px solid #1e2d40;border-radius:8px;padding:.8rem 1rem;margin-top:-.5rem;">
                                  <div style="font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:#38bdf8;font-weight:700;margin-bottom:.5rem;">📊 Size Statistics</div>
                                  {stats_html}
                                </div>""", unsafe_allow_html=True)

                        with c2:
                            fig_iat, iat_stats = plot_iat_distribution(packet_data)
                            if fig_iat:
                                st.plotly_chart(fig_iat, use_container_width=True)
                                if iat_stats:
                                    stats_html = ''.join(
                                        f'<div style="padding:.15rem 0;font-size:.78rem;color:#94a3b8;font-family:\'JetBrains Mono\',monospace;">{line}</div>'
                                        for line in iat_stats
                                    )
                                    st.markdown(f"""
                                    <div style="background:#0d1117;border:1px solid #1e2d40;border-radius:8px;padding:.8rem 1rem;margin-top:-.5rem;">
                                      <div style="font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:#818cf8;font-weight:700;margin-bottom:.5rem;">⏱️ Timing Statistics</div>
                                      {stats_html}
                                    </div>""", unsafe_allow_html=True)

                        # ── Row 2: Flags ──
                        fig_flags, flag_vals, total_flags = plot_flags(X)
                        st.plotly_chart(fig_flags, use_container_width=True)

                        # Flag stats mini-row
                        if total_flags > 0:
                            flag_cols = st.columns(6)
                            flag_labels = [
                                ('FIN', '🟡', flag_vals['FIN'], 'Connection teardown'),
                                ('SYN', '🔴', flag_vals['SYN'], 'New connection'),
                                ('RST', '🔴', flag_vals['RST'], 'Forced reset'),
                                ('PSH', '🔵', flag_vals['PSH'], 'Data push'),
                                ('ACK', '🟢', flag_vals['ACK'], 'Acknowledgement'),
                                ('URG', '🟠', flag_vals['URG'], 'Urgent pointer'),
                            ]
                            for col, (name, icon, val, desc) in zip(flag_cols, flag_labels):
                                pct = val / total_flags * 100
                                with col:
                                    st.markdown(f"""
                                    <div style="background:#0d1117;border:1px solid #1e2d40;border-radius:8px;padding:.6rem .8rem;text-align:center;">
                                      <div style="font-size:1.1rem;">{icon}</div>
                                      <div style="font-size:1rem;font-weight:700;color:#e2e8f0;font-family:'JetBrains Mono',monospace;">{int(val)}</div>
                                      <div style="font-size:.7rem;color:#38bdf8;font-weight:600;">{name}</div>
                                      <div style="font-size:.65rem;color:#475569;">{pct:.1f}% · {desc}</div>
                                    </div>""", unsafe_allow_html=True)
                    else:
                        st.info("Enable Distributions in the sidebar.")

                with tab4:
                    def highlight_row(row):
                        if row['Feature'] in ('SYN Count','RST Count','FIN Count') and row['Value'] > 10:
                            return ['background-color:#2d1515;color:#f87171'] * len(row)
                        elif row['Feature'] in ('Flow Bytes/s','Flow Packets/s') and row['Value'] > 10000:
                            return ['background-color:#2d2007;color:#fbbf24'] * len(row)
                        return ['']*len(row)

                    feat_df = pd.DataFrame({
                        'Feature': FEATURE_NAMES_DISPLAY,
                        'Value':   X[0].round(6),
                        'Unit':    FEATURE_UNITS
                    })
                    st.dataframe(feat_df.style.apply(highlight_row, axis=1),
                                 use_container_width=True, hide_index=True, height=540)

                # ── Export ──
                st.markdown("---")
                export_df = feat_df.copy()
                export_df['Prediction']       = 'Malicious' if final_prediction else 'Benign'
                export_df['XGB_Probability']  = xgb_prob
                export_df['Isolation_Score']  = iso_score
                csv = export_df.to_csv(index=False)
                st.download_button(
                    label="📥  Export Results as CSV",
                    data=csv,
                    file_name=f"nids_analysis_{time.strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

        except Exception as e:
            st.error(f"Capture error: {e}")
            st.info("On Linux/Mac run with `sudo`. On Windows ensure Npcap is installed in WinPcap-compatible mode.")

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown("""
<div style="margin-top:3rem;padding:1rem;border-top:1px solid #1e2d40;font-size:.75rem;color:#334155;text-align:center;font-family:'JetBrains Mono',monospace;">
  NetGuard IDS · 33-feature hybrid detection · XGBoost + Isolation Forest &nbsp;|&nbsp;
  Requires network capture privileges &nbsp;|&nbsp; For authorized use only
</div>
""", unsafe_allow_html=True)