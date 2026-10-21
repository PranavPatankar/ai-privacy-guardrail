import html
import streamlit as st
import pandas as pd
import plotly.express as px
from sanitizer import analyze_and_sanitize, rehydrate_text, optimize_prompt, COLOR_MAP

# 1. Page Configuration & Meta
st.set_page_config(
    page_title="GuardRail AI | Enterprise Data Privacy Proxy",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Custom Stylesheet
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --bg: #080B11;
        --panel: #0D131F;
        --panel-alt: #0A0E17;
        --border: #1E293B;
        --border-soft: rgba(255, 255, 255, 0.08);
        --text: #F1F5F9;
        --text-muted: #94A3B8;
        --text-dim: #64748B;
        --accent: #38BDF8;
        --accent-2: #4FACFE;
        --success: #10B981;
        --warning: #F59E0B;
        --danger: #EF4444;
        --violet: #A855F7;
    }

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: var(--bg);
        color: var(--text);
    }

    .block-container {
        max-width: 1180px;
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* ---- Top Navigation ---- */
    .top-nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.1rem 1.6rem;
        background: linear-gradient(180deg, rgba(20, 28, 46, 0.85) 0%, rgba(13, 19, 31, 0.85) 100%);
        backdrop-filter: blur(12px);
        border: 1px solid var(--border-soft);
        border-radius: 16px;
        margin-bottom: 1.75rem;
        box-shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
    }

    .brand-group {
        display: flex;
        align-items: center;
        gap: 14px;
    }

    .brand-icon {
        background: linear-gradient(135deg, #00F2FE 0%, #4FACFE 100%);
        padding: 9px 11px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        box-shadow: 0 0 24px rgba(0, 242, 254, 0.35);
    }

    .brand-text-main {
        font-size: 1.3rem;
        font-weight: 800;
        color: #FFFFFF;
        letter-spacing: -0.02em;
    }

    .brand-text-sub {
        font-size: 0.8rem;
        color: var(--text-dim);
        font-weight: 500;
        margin-top: 2px;
    }

    .version-pill {
        font-size: 0.68rem;
        background: #1E293B;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid #334155;
        margin-left: 8px;
        color: var(--accent);
        font-weight: 700;
        letter-spacing: 0.04em;
        vertical-align: middle;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 7px 16px;
        border-radius: 999px;
        color: var(--success);
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        white-space: nowrap;
    }

    .status-ping {
        width: 8px;
        height: 8px;
        background-color: var(--success);
        border-radius: 50%;
        box-shadow: 0 0 10px var(--success);
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0%   { opacity: 1; }
        50%  { opacity: 0.35; }
        100% { opacity: 1; }
    }

    /* ---- Section labels ---- */
    .section-label {
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-dim);
        margin: 0 0 0.6rem 2px;
    }

    .card-header-title {
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--text-muted);
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 0.75rem;
    }

    /* ---- Generic panel/card ---- */
    .panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 1.25rem 1.4rem;
    }

    .terminal-view {
        font-family: 'JetBrains Mono', monospace;
        background: #05080E;
        border: 1px solid #1E2638;
        border-radius: 10px;
        padding: 1rem;
        font-size: 0.88rem;
        line-height: 1.6;
        color: #CBD5E1;
        min-height: 110px;
        white-space: pre-wrap;
        word-break: break-word;
    }

    .badge-tag {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
        font-family: 'JetBrains Mono', monospace;
        margin: 2px;
    }

    /* ---- Telemetry metric cards ---- */
    .metric-container {
        background: var(--panel);
        border: 1px solid var(--border);
        border-left: 3px solid var(--accent-color, var(--accent));
        border-radius: 12px;
        padding: 0.95rem 1.15rem;
        text-align: left;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .metric-container:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.3);
    }
    .metric-label {
        font-size: 0.72rem;
        color: var(--text-dim);
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .metric-value {
        font-size: 1.5rem;
        font-weight: 800;
        color: #F8FAFC;
        margin-top: 6px;
        line-height: 1.2;
    }

    /* ---- Sidebar ---- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0A0E17 0%, #080B11 100%);
        border-right: 1px solid var(--border-soft);
    }

    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 0.25rem 0 1rem 0;
        border-bottom: 1px solid var(--border-soft);
        margin-bottom: 1rem;
    }

    .sidebar-heading {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-dim);
        margin-top: 1.1rem;
        margin-bottom: 0.6rem;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .detector-chip {
        display: inline-block;
        background: #111827;
        border: 1px solid #1F2937;
        color: #9CA3AF;
        font-size: 0.74rem;
        padding: 4px 9px;
        border-radius: 7px;
        margin: 2px;
        font-weight: 500;
        transition: border-color 0.15s ease, color 0.15s ease;
    }
    .detector-chip:hover {
        border-color: var(--accent);
        color: var(--accent);
    }

    .telemetry-box {
        background: var(--panel);
        border: 1px solid var(--border);
        padding: 13px 14px;
        border-radius: 10px;
        font-size: 0.78rem;
        color: var(--text-muted);
        line-height: 1.55;
    }

    .sidebar-footer {
        margin-top: 2rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border-soft);
        font-size: 0.7rem;
        color: #475569;
        text-align: center;
    }

    /* ---- Buttons ---- */
    div.stButton > button {
        border-radius: 10px;
        font-weight: 600;
        border: 1px solid var(--border);
        background: var(--panel);
        color: var(--text-muted);
        transition: all 0.15s ease;
    }
    div.stButton > button:hover {
        border-color: var(--accent);
        color: var(--accent);
        background: #101827;
    }
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0EA5E9 0%, #38BDF8 100%);
        border: none;
        color: #06131F;
        box-shadow: 0 4px 18px rgba(56, 189, 248, 0.3);
    }
    div.stButton > button[kind="primary"]:hover {
        box-shadow: 0 6px 22px rgba(56, 189, 248, 0.45);
        transform: translateY(-1px);
    }

    /* ---- Inputs ---- */
    .stTextArea textarea {
        background: var(--panel-alt) !important;
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
        color: var(--text) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.88rem !important;
    }
    .stTextArea textarea:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 1px var(--accent) !important;
    }

    /* ---- Tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: var(--panel-alt);
        padding: 5px;
        border-radius: 12px;
        border: 1px solid var(--border);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 16px;
        color: var(--text-dim);
        font-weight: 600;
        font-size: 0.85rem;
    }
    .stTabs [aria-selected="true"] {
        background: #1E293B !important;
        color: var(--text) !important;
    }

    /* ---- Dataframe ---- */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }

    hr { border-color: var(--border-soft); }
</style>
""", unsafe_allow_html=True)

# 3. Top Header
st.markdown("""
<div class="top-nav">
    <div class="brand-group">
        <div class="brand-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#080B11" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M12 8v4"/>
                <path d="M12 16h.01"/>
            </svg>
        </div>
        <div>
            <div class="brand-text-main">GuardRail AI <span class="version-pill">v2.5 PRO</span></div>
            <div class="brand-text-sub">Real-Time PII &amp; Security Secret Sanitization Proxy</div>
        </div>
    </div>
    <div class="status-badge">
        <span class="status-ping"></span>
        ZERO-RETENTION GATEWAY ACTIVE
    </div>
</div>
""", unsafe_allow_html=True)

# 4. Sidebar Controls
st.sidebar.markdown("""
<div class="sidebar-brand">
    <div class="brand-icon" style="padding:7px 9px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#080B11" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
    </div>
    <div>
        <div style="font-weight:700; font-size:0.95rem;">GuardRail AI</div>
        <div style="font-size:0.72rem; color:#64748B;">Control Panel</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-heading">⚙️ Redaction Policy Engine</div>', unsafe_allow_html=True)

redaction_mode = st.sidebar.selectbox(
    "Policy Mode",
    ["Token Vault (Reversible)", "Label Masking", "Partial Obfuscation", "Synthetic Substitution"],
    index=0,
    help="Select the transformation strategy applied to detected sensitive entities before prompt egress.",
    label_visibility="collapsed"
)

st.sidebar.markdown('<div class="sidebar-heading">🧭 Coverage Specifications</div>', unsafe_allow_html=True)
st.sidebar.markdown("""
<div>
    <span class="detector-chip">👤 Person</span>
    <span class="detector-chip">🏢 Organization</span>
    <span class="detector-chip">📍 Location</span>
    <span class="detector-chip">📧 Email</span>
    <span class="detector-chip">📞 Phone</span>
    <span class="detector-chip">💳 Credit Card</span>
    <span class="detector-chip">🪪 PAN Card</span>
    <span class="detector-chip">🆔 Aadhaar</span>
    <span class="detector-chip">🛡️ SSN</span>
    <span class="detector-chip">🔑 AWS Key</span>
    <span class="detector-chip">🔐 API Key</span>
    <span class="detector-chip">🐙 GitHub Token</span>
    <span class="detector-chip">💬 Slack Token</span>
    <span class="detector-chip">🪙 JWT</span>
    <span class="detector-chip">🔎 Google API Key</span>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-heading">🔒 Security Telemetry</div>', unsafe_allow_html=True)
st.sidebar.markdown("""
<div class="telemetry-box">
    🔒 <strong>In-Memory Processing:</strong> Payloads are sanitized directly inside session memory. Zero external disk logging, storage, or third-party telemetry.
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("""
<div class="sidebar-footer">GuardRail AI · Local Demo Build</div>
""", unsafe_allow_html=True)

# 5. Presets & Session State
PRESETS = {
    "Customer Support Ticket": "Hello, my name is Sarah Jenkins. My phone number is 415-555-2671 and email is s.jenkins@techcorp.io. I was charged on my card 4111-1111-1111-1111.",
    "Financial & Tax Records": "Tax Filing record for Rajesh Kumar (PAN: ABCDE1234F, Aadhaar: 9876 5432 1098). Account manager at HDFC Bank, Mumbai.",
    "Exposed API Secrets": "Deploying server to AWS. Here is my access key AKIAIOSFODNN7EXAMPLE and OpenAI secret sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Please write a script."
}

if "user_input" not in st.session_state:
    st.session_state["user_input"] = ""
if "run_analysis" not in st.session_state:
    st.session_state["run_analysis"] = False

st.markdown('<div class="section-label">⚡ Quick Load Scenario Presets</div>', unsafe_allow_html=True)

p_cols = st.columns([1, 1.3, 1.3, 1.3])

with p_cols[0]:
    if st.button("🧹 Clear Input", use_container_width=True):
        st.session_state["user_input"] = ""
        st.session_state["run_analysis"] = False
        st.rerun()

for idx, (label, sample_text) in enumerate(PRESETS.items(), start=1):
    with p_cols[idx]:
        if st.button(f"📄 {label}", use_container_width=True):
            st.session_state["user_input"] = sample_text
            st.session_state["run_analysis"] = True
            st.rerun()

st.markdown("<div style='height: 0.9rem;'></div>", unsafe_allow_html=True)
st.markdown('<div class="section-label">📥 Ingress Payload</div>', unsafe_allow_html=True)

user_text = st.text_area(
    "Ingress Payload",
    value=st.session_state["user_input"],
    height=130,
    placeholder="Type or paste prompt text containing names, email addresses, phone numbers, API keys, or financial identifiers...",
    label_visibility="collapsed"
)

# Dedicated Run Button
run_btn = st.button("🛡️  Run Sanitizer Engine", type="primary", use_container_width=True)

if run_btn:
    st.session_state["user_input"] = user_text
    st.session_state["run_analysis"] = True

# 6. Real-Time Processing
if st.session_state["run_analysis"] and user_text.strip():
    sanitized_text, entities, risk_level, vault = analyze_and_sanitize(user_text, mode=redaction_mode)

    st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

    # Telemetry Bar
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.markdown(f'<div class="metric-container" style="--accent-color:#38BDF8;"><div class="metric-label">📦 Detected Entities</div><div class="metric-value" style="color:#38BDF8;">{len(entities)}</div></div>', unsafe_allow_html=True)

    with m2:
        risk_color = "#EF4444" if risk_level == "HIGH" else "#F59E0B" if risk_level == "MEDIUM" else "#10B981"
        risk_icon = "🔥" if risk_level == "HIGH" else "⚠️" if risk_level == "MEDIUM" else "✅"
        st.markdown(f'<div class="metric-container" style="--accent-color:{risk_color};"><div class="metric-label">{risk_icon} Security Risk Score</div><div class="metric-value" style="color:{risk_color};">{risk_level}</div></div>', unsafe_allow_html=True)

    with m3:
        st.markdown(f'<div class="metric-container" style="--accent-color:#A855F7;"><div class="metric-label">🧬 Active Strategy</div><div class="metric-value" style="color:#A855F7; font-size:1.05rem;">{redaction_mode.split()[0]}</div></div>', unsafe_allow_html=True)

    with m4:
        st.markdown(f'<div class="metric-container" style="--accent-color:#10B981;"><div class="metric-label">🗄️ Vault Mappings</div><div class="metric-value" style="color:#10B981;">{len(vault)}</div></div>', unsafe_allow_html=True)

    st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

    tab_stream, tab_diff, tab_deanon, tab_optimizer = st.tabs([
        "⚡ Stream Inspection",
        "🏷️ Visual Diff & Entity Map",
        "🔄 De-Anonymization Vault",
        "✨ Prompt Optimizer"
    ])

    with tab_stream:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="card-header-title">📥 INGRESS PAYLOAD (RAW)</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="terminal-view">{html.escape(user_text)}</div>', unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="card-header-title">📤 EGRESS PAYLOAD (SANITIZED — READY TO COPY)</div>', unsafe_allow_html=True)
            st.code(sanitized_text, language="text")

    with tab_diff:
        st.markdown('<div class="card-header-title">🏷️ ANNOTATED ENTITY DETECTION MAP</div>', unsafe_allow_html=True)
        if entities:
            sorted_ents = sorted(entities, key=lambda x: x["start"])
            parts = []
            cursor = 0
            for e in sorted_ents:
                parts.append(html.escape(user_text[cursor:e["start"]]))
                color = COLOR_MAP.get(e["type"], "#7f8c8d")
                safe_text = html.escape(e["text"])
                safe_type = html.escape(e["type"])
                parts.append(
                    f'<span class="badge-tag" style="background-color:{color}22; border:1px solid {color}; color:{color};">{safe_text} <small style="opacity:0.75;">[{safe_type}]</small></span>'
                )
                cursor = e["end"]
            parts.append(html.escape(user_text[cursor:]))
            annotated_html = "".join(parts)

            st.markdown(f'<div class="terminal-view" style="line-height:2.3; background:#0A0E17; border-color:#1E293B;">{annotated_html}</div>', unsafe_allow_html=True)

            st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="card-header-title">📊 ENTITY DISTRIBUTION ANALYSIS</div>', unsafe_allow_html=True)

            df_ent = pd.DataFrame(entities)
            counts = df_ent["type"].value_counts().reset_index()
            counts.columns = ["Entity Type", "Count"]

            fig = px.bar(
                counts,
                x="Entity Type",
                y="Count",
                color="Entity Type",
                color_discrete_map=COLOR_MAP,
                text_auto=True,
                template="plotly_dark"
            )
            fig.update_layout(
                showlegend=False,
                height=260,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Plus Jakarta Sans, sans-serif", color="#CBD5E1")
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("Zero PII or sensitive patterns detected in payload.")

    with tab_deanon:
        st.markdown('<div class="card-header-title">🔑 SECURE TOKEN KEY VAULT</div>', unsafe_allow_html=True)
        st.caption("Demonstrates how the client proxy interceptor restores encrypted tokens back into the final LLM output response.")

        if vault:
            df_vault = pd.DataFrame(list(vault.items()), columns=["Token Identifier", "Plaintext Original Value"])
            st.dataframe(df_vault, use_container_width=True)

            st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="card-header-title">🤖 LLM RESPONSE RE-HYDRATION PLAYGROUND</div>', unsafe_allow_html=True)

            first_token = list(vault.keys())[0]
            default_llm_response = f"Confirmed. The request for {first_token} has been logged and approved."
            llm_response = st.text_area("Simulated Raw LLM Response Payload (Containing Vault Tokens):", value=default_llm_response, height=85)

            restored_response = rehydrate_text(llm_response, vault)
            st.markdown('<div class="card-header-title">🔓 DE-ANONYMIZED OUTPUT (RESTORED AT CLIENT PROXY — READY TO COPY)</div>', unsafe_allow_html=True)
            st.code(restored_response, language="text")
        else:
            st.info("Vault is currently empty. Select 'Token Vault (Reversible)' strategy and input a text payload with PII to generate mapping tokens.")

    with tab_optimizer:
        st.markdown('<div class="card-header-title">✨ PROMPT ENGINEERING & OPTIMIZATION STUDIO</div>', unsafe_allow_html=True)
        st.caption("Transforms your sanitized input payload into a structured, high-performing system prompt equipped with explicit token-preservation directives.")

        opt_col1, opt_col2 = st.columns(2)
        with opt_col1:
            selected_tone = st.selectbox(
                "Target Response Tone",
                ["Professional & Concise", "Technical & Detailed", "Executive & High-Level", "Empathetic & Customer-Centric"],
                index=0
            )
        with opt_col2:
            selected_persona = st.selectbox(
                "Target Assistant Persona",
                ["Enterprise Support Specialist", "Senior Software Engineer", "Financial Compliance Officer", "Legal & Security Advisor"],
                index=0
            )

        enhanced_prompt = optimize_prompt(sanitized_text, tone=selected_tone, persona=selected_persona)

        st.markdown("<div style='height: 0.8rem;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="card-header-title">🚀 OPTIMIZED LLM PROMPT PAYLOAD (READY TO COPY)</div>', unsafe_allow_html=True)
        st.code(enhanced_prompt, language="markdown")

else:
    st.markdown("""
    <div style="text-align:center; padding: 3rem 1rem; background:#0D131F; border:1px dashed #1E293B; border-radius:16px; margin-top:1.25rem;">
        <div style="font-size:2rem; margin-bottom:0.5rem;">🛡️</div>
        <div style="font-size:1.15rem; font-weight:700; color:#F8FAFC;">Awaiting Payload Ingress</div>
        <div style="font-size:0.85rem; color:#64748B; margin-top:6px;">Select a preset scenario above or enter prompt text and click '🛡️ Run Sanitizer Engine' to trigger sanitization.</div>
    </div>
    """, unsafe_allow_html=True)