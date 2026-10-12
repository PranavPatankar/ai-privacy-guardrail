import streamlit as st
import pandas as pd
import plotly.express as px
from sanitizer import analyze_and_sanitize, rehydrate_text, COLOR_MAP

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
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: #080B11;
        color: #F1F5F9;
    }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    .top-nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem 1.5rem;
        background: rgba(15, 23, 42, 0.75);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        margin-bottom: 1.5rem;
    }

    .brand-group {
        display: flex;
        align-items: center;
        gap: 14px;
    }

    .brand-icon {
        background: linear-gradient(135deg, #00F2FE 0%, #4FACFE 100%);
        padding: 8px 10px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        box-shadow: 0 0 20px rgba(0, 242, 254, 0.3);
    }

    .brand-text-main {
        font-size: 1.25rem;
        font-weight: 700;
        color: #FFFFFF;
        letter-spacing: -0.02em;
    }

    .brand-text-sub {
        font-size: 0.78rem;
        color: #64748B;
        font-weight: 500;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.25);
        padding: 6px 14px;
        border-radius: 9999px;
        color: #10B981;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }

    .status-ping {
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
        box-shadow: 0 0 10px #10B981;
    }

    .card-header-title {
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #94A3B8;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 0.75rem;
    }

    .terminal-view {
        font-family: 'JetBrains Mono', monospace;
        background: #05080E;
        border: 1px solid #1E2638;
        border-radius: 8px;
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

    .metric-container {
        background: #0D131F;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 0.9rem 1.1rem;
        text-align: left;
    }
    .metric-label {
        font-size: 0.75rem;
        color: #64748B;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        font-size: 1.35rem;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 4px;
    }

    .sidebar-heading {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #64748B;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }

    .detector-chip {
        display: inline-block;
        background: #111827;
        border: 1px solid #1F2937;
        color: #9CA3AF;
        font-size: 0.74rem;
        padding: 3px 8px;
        border-radius: 6px;
        margin: 2px;
        font-weight: 500;
    }
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
            <div class="brand-text-main">GuardRail AI <span style="font-size:0.7rem; background:#1E293B; padding:2px 6px; border-radius:4px; border:1px solid #334155; margin-left:6px; color:#38BDF8;">v2.4 PRO</span></div>
            <div class="brand-text-sub">Real-Time PII & Security Secret Sanitization Proxy</div>
        </div>
    </div>
    <div class="status-badge">
        <span class="status-ping"></span>
        ZERO-RETENTION GATEWAY ACTIVE
    </div>
</div>
""", unsafe_allow_html=True)

# 4. Sidebar Controls
st.sidebar.markdown('<div class="sidebar-heading">REDACTION POLICY ENGINE</div>', unsafe_allow_html=True)

redaction_mode = st.sidebar.selectbox(
    "Policy Mode",
    ["Token Vault (Reversible)", "Label Masking", "Partial Obfuscation", "Synthetic Substitution"],
    index=0,
    help="Select the transformation strategy applied to detected sensitive entities before prompt egress."
)

st.sidebar.markdown('<div class="sidebar-heading">COVERAGE SPECIFICATIONS</div>', unsafe_allow_html=True)
st.sidebar.markdown("""
<div>
    <span class="detector-chip">👤 Person</span>
    <span class="detector-chip">🏢 Organization</span>
    <span class="detector-chip">📍 Location</span>
    <span class="detector-chip">📧 Email</span>
    <span class="detector-chip">📞 Phone Number</span>
    <span class="detector-chip">💳 Credit Card</span>
    <span class="detector-chip">🪪 PAN Card</span>
    <span class="detector-chip">🆔 Aadhaar</span>
    <span class="detector-chip">🛡️ SSN</span>
    <span class="detector-chip">🔑 AWS Key</span>
    <span class="detector-chip">🔐 OpenAI Key</span>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-heading">SECURITY TELEMETRY</div>', unsafe_allow_html=True)
st.sidebar.markdown("""
<div style="background:#0D131F; border:1px solid #1E293B; padding:12px; border-radius:8px; font-size:0.78rem; color:#94A3B8; line-height:1.5;">
    🔒 <strong>In-Memory Processing:</strong> Payloads are sanitized directly inside session memory. Zero external disk logging, storage, or third-party telemetry.
</div>
""", unsafe_allow_html=True)

# 5. Presets & Session State
PRESETS = {
    "Customer Support Ticket": "Hello, my name is Sarah Jenkins. My phone number is 415-555-2671 and email is s.jenkins@techcorp.io. I was charged on my card 4532-7182-9910-1201.",
    "Financial & Tax Records": "Tax Filing record for Rajesh Kumar (PAN: ABCDE1234F, Aadhaar: 9876 5432 1098). Account manager at HDFC Bank, Mumbai.",
    "Exposed API Secrets": "Deploying server to AWS. Here is my access key AKIAIOSFODNN7EXAMPLE and OpenAI secret sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Please write a script."
}

if "user_input" not in st.session_state:
    st.session_state["user_input"] = ""
if "run_analysis" not in st.session_state:
    st.session_state["run_analysis"] = False

st.markdown("##### ⚡ Quick Load Scenario Presets")

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

user_text = st.text_area(
    "Ingress Payload (Prompt text sent to LLM Proxy):",
    value=st.session_state["user_input"],
    height=130,
    placeholder="Type or paste prompt text containing names, email addresses, phone numbers, API keys, or financial identifiers..."
)

# Dedicated Run Button
run_btn = st.button("🛡️ Run Sanitizer Engine", type="primary", use_container_width=True)

if run_btn:
    st.session_state["user_input"] = user_text
    st.session_state["run_analysis"] = True

# 6. Real-Time Processing
if st.session_state["run_analysis"] and user_text.strip():
    sanitized_text, entities, risk_level, vault = analyze_and_sanitize(user_text, mode=redaction_mode)

    st.markdown("<br>", unsafe_allow_html=True)

    # Telemetry Bar
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.markdown(f'<div class="metric-container"><div class="metric-label">Detected Entities</div><div class="metric-value" style="color:#38BDF8;">{len(entities)}</div></div>', unsafe_allow_html=True)

    with m2:
        risk_color = "#EF4444" if risk_level == "HIGH" else "#F59E0B" if risk_level == "MEDIUM" else "#10B981"
        st.markdown(f'<div class="metric-container"><div class="metric-label">Security Risk Score</div><div class="metric-value" style="color:{risk_color};">{risk_level}</div></div>', unsafe_allow_html=True)

    with m3:
        st.markdown(f'<div class="metric-container"><div class="metric-label">Active Strategy</div><div class="metric-value" style="color:#A855F7;">{redaction_mode.split()[0]}</div></div>', unsafe_allow_html=True)

    with m4:
        st.markdown(f'<div class="metric-container"><div class="metric-label">Vault Mappings</div><div class="metric-value" style="color:#10B981;">{len(vault)}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_stream, tab_diff, tab_deanon = st.tabs([
        "⚡ Stream Inspection",
        "🏷️ Visual Diff & Entity Map",
        "🔄 De-Anonymization Vault"
    ])

    with tab_stream:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="card-header-title">📥 INGRESS PAYLOAD (RAW)</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="terminal-view">{user_text}</div>', unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="card-header-title">📤 EGRESS PAYLOAD (SANITIZED — READY TO COPY)</div>', unsafe_allow_html=True)
            st.code(sanitized_text, language="text")

    with tab_diff:
        st.markdown('<div class="card-header-title">🏷️ ANNOTATED ENTITY DETECTION MAP</div>', unsafe_allow_html=True)
        if entities:
            annotated_html = user_text
            sorted_ents = sorted(entities, key=lambda x: x["start"], reverse=True)
            for e in sorted_ents:
                color = COLOR_MAP.get(e["type"], "#7f8c8d")
                span = f'<span class="badge-tag" style="background-color:{color}22; border:1px solid {color}; color:{color};">{e["text"]} <small style="opacity:0.75;">[{e["type"]}]</small></span>'
                annotated_html = annotated_html[:e["start"]] + span + annotated_html[e["end"]:]

            st.markdown(f'<div class="terminal-view" style="line-height:2.3; background:#0A0E17; border-color:#1E293B;">{annotated_html}</div>', unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
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
                plot_bgcolor="rgba(0,0,0,0)"
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

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="card-header-title">🤖 LLM RESPONSE RE-HYDRATION PLAYGROUND</div>', unsafe_allow_html=True)

            first_token = list(vault.keys())[0]
            default_llm_response = f"Confirmed. The request for {first_token} has been logged and approved."
            llm_response = st.text_area("Simulated Raw LLM Response Payload (Containing Vault Tokens):", value=default_llm_response, height=85)

            restored_response = rehydrate_text(llm_response, vault)
            st.markdown('<div class="card-header-title">🔓 DE-ANONYMIZED OUTPUT (RESTORED AT CLIENT PROXY — READY TO COPY)</div>', unsafe_allow_html=True)
            st.code(restored_response, language="text")
        else:
            st.info("Vault is currently empty. Select 'Token Vault (Reversible)' strategy and input a text payload with PII to generate mapping tokens.")
else:
    st.markdown("""
    <div style="text-align:center; padding: 2.5rem 1rem; background:#0D131F; border:1px dashed #1E293B; border-radius:12px; margin-top:1rem;">
        <div style="font-size:1.1rem; font-weight:600; color:#F8FAFC;">Awaiting Payload Ingress</div>
        <div style="font-size:0.85rem; color:#64748B; margin-top:6px;">Select a preset scenario above or enter prompt text and click '🛡️ Run Sanitizer Engine' to trigger sanitization.</div>
    </div>
    """, unsafe_allow_html=True)