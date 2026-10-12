import streamlit as st
import pandas as pd
import plotly.express as px
from sanitizer import analyze_and_sanitize, rehydrate_text, COLOR_MAP

st.set_page_config(
    page_title="AI Data Privacy Guardrail | Enterprise Security Proxy",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for SaaS UI Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Top Brand Header */
    .brand-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.5rem 0 1.2rem 0;
        border-bottom: 1px solid #232834;
        margin-bottom: 1.5rem;
    }
    .brand-title {
        font-size: 1.45rem;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .status-pill {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        color: #10B981;
        font-size: 0.75rem;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }

    /* Sidebar Styling */
    .sidebar-section-title {
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94A3B8;
        font-weight: 600;
        margin: 1.2rem 0 0.6rem 0;
    }

    .spec-badge {
        display: inline-block;
        background: #1E293B;
        border: 1px solid #334155;
        color: #CBD5E1;
        font-size: 0.75rem;
        padding: 4px 8px;
        border-radius: 6px;
        margin: 2px 2px;
        font-weight: 500;
    }

    /* Text Terminal Output */
    .terminal-box {
        font-family: 'JetBrains Mono', monospace;
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 1rem;
        font-size: 0.88rem;
        color: #E2E8F0;
        line-height: 1.6;
        min-height: 120px;
        white-space: pre-wrap;
    }

    .badge-tag {
        display: inline-block;
        padding: 2px 7px;
        border-radius: 5px;
        font-weight: 600;
        font-size: 0.8rem;
        font-family: 'JetBrains Mono', monospace;
        margin: 0 2px;
    }

    .stButton>button {
        border-radius: 6px;
        font-weight: 500;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Top Brand Header Bar
st.markdown("""
<div class="brand-header">
    <div class="brand-title">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M12 8v4"/>
            <path d="M12 16h.01"/>
        </svg>
        <span>AI Data Privacy Guardrail</span>
    </div>
    <div class="status-pill">
        <span style="height:6px; width:6px; background-color:#10B981; border-radius:50%; display:inline-block;"></span>
        PROXY ENGINE ACTIVE • ZERO-RETENTION PROCESSING
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar Design
st.sidebar.markdown('<div class="sidebar-section-title">REDACTION POLICY</div>', unsafe_allow_html=True)

redaction_mode = st.sidebar.radio(
    "Select Strategy",
    ["Token Vault (Reversible)", "Label Masking", "Partial Obfuscation", "Synthetic Substitution"],
    index=0,
    label_visibility="collapsed"
)

st.sidebar.markdown('<div class="sidebar-section-title">COVERAGE DETECTORS</div>', unsafe_allow_html=True)

st.sidebar.markdown("""
<div>
    <span class="spec-badge">👤 Person</span>
    <span class="spec-badge">🏢 Organization</span>
    <span class="spec-badge">📍 Location</span>
    <span class="spec-badge">📧 Email</span>
    <span class="spec-badge">📞 Phone</span>
    <span class="spec-badge">💳 Credit Card</span>
    <span class="spec-badge">🪪 PAN Card</span>
    <span class="spec-badge">🆔 Aadhaar</span>
    <span class="spec-badge">🛡️ SSN</span>
    <span class="spec-badge">🔑 AWS Secret</span>
    <span class="spec-badge">🔐 OpenAI API Key</span>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-section-title">SECURITY STATUS</div>', unsafe_allow_html=True)
st.sidebar.info("🔒 Engine operates locally in memory. No prompt payloads or token keys are logged or persisted.")

# Main Application Space
st.markdown("##### Scenario Presets")

PRESETS = {
    "Customer Support Ticket": "Hello, my name is Sarah Jenkins. My phone number is 415-555-2671 and email is s.jenkins@techcorp.io. I was charged on my card 4532-7182-9910-1201.",
    "Financial & Tax Records": "Tax Filing for Rajesh Kumar (PAN: ABCDE1234F, Aadhaar: 9876 5432 1098). Account manager at HDFC Bank, Mumbai.",
    "Exposed API Secrets": "Deploying server to AWS. Here is my access key AKIAIOSFODNN7EXAMPLE and OpenAI secret sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Please write a script."
}

if "user_input" not in st.session_state:
    st.session_state["user_input"] = ""

# Interactive Action Buttons
cols = st.columns(len(PRESETS) + 1)
with cols[0]:
    if st.button("Clear Input", type="secondary", use_container_width=True):
        st.session_state["user_input"] = ""
        st.rerun()

for idx, (label, sample_text) in enumerate(PRESETS.items(), start=1):
    with cols[idx]:
        if st.button(label, use_container_width=True):
            st.session_state["user_input"] = sample_text
            st.rerun()

user_text = st.text_area(
    "Input Payload (Prompt text sent to LLM proxy):",
    value=st.session_state["user_input"],
    height=130,
    placeholder="Paste prompt containing sensitive personal information, customer records, or API credentials..."
)

if user_text.strip():
    sanitized_text, entities, risk_level, vault = analyze_and_sanitize(user_text, mode=redaction_mode)

    st.markdown("---")

    # Metrics Bar
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Detected Entities", len(entities))
    with m2:
        risk_badge = f"🔴 {risk_level}" if risk_level == "HIGH" else f"🟡 {risk_level}" if risk_level == "MEDIUM" else f"🟢 {risk_level}"
        st.metric("Security Risk Score", risk_badge)
    with m3:
        st.metric("Active Strategy", redaction_mode.split()[0])
    with m4:
        st.metric("Vault Mappings", len(vault))

    st.markdown("---")

    tab_inspect, tab_visual, tab_vault = st.tabs(["⚡ Stream Inspection", "🏷️ Visual Diff & Entity Map", "🔄 De-Anonymization Vault"])

    with tab_inspect:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("###### INGRESS (RAW TEXT)")
            st.markdown(f'<div class="terminal-box">{user_text}</div>', unsafe_allow_html=True)
        with c2:
            st.markdown("###### EGRESS (SANITIZED PAYLOAD)")
            st.markdown(f'<div class="terminal-box" style="border-color:#10B981; background-color:#064E3B11;">{sanitized_text}</div>', unsafe_allow_html=True)
            st.write("")
            st.download_button(
                label="📥 Download Clean Payload",
                data=sanitized_text,
                file_name="sanitized_prompt.txt",
                mime="text/plain",
                use_container_width=True
            )

    with tab_visual:
        st.markdown("###### ANNOTATED ENTITY DETECTION MAPPING")
        if entities:
            annotated_html = user_text
            sorted_ents = sorted(entities, key=lambda x: x["start"], reverse=True)
            for e in sorted_ents:
                color = COLOR_MAP.get(e["type"], "#7f8c8d")
                span = f'<span class="badge-tag" style="background-color:{color}22; border:1px solid {color}; color:{color};">{e["text"]} <small style="opacity:0.8;">[{e["type"]}]</small></span>'
                annotated_html = annotated_html[:e["start"]] + span + annotated_html[e["end"]:]

            st.markdown(f'<div style="line-height:2.4; font-size:1rem; background-color:#0F172A; padding:18px; border-radius:8px; border:1px solid #1E293B;">{annotated_html}</div>', unsafe_allow_html=True)

            st.markdown("###### DISTRIBUTION BY CATEGORY")
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
            st.success("No sensitive entities detected in payload.")

    with tab_vault:
        st.markdown("###### SECURE RE-HYDRATION PROXY PLAYGROUND")
        st.caption("Demonstrates end-to-end payload sanitization before sending to an external LLM and automatic re-hydration of response tokens back to the client.")

        if vault:
            st.markdown("##### 🔑 Key Vault Map")
            df_vault = pd.DataFrame(list(vault.items()), columns=["Token Key", "Original Value"])
            st.dataframe(df_vault, use_container_width=True)

            st.markdown("---")
            st.markdown("##### 🤖 Simulated Outgoing Response")

            first_token = list(vault.keys())[0]
            default_llm_response = f"Confirmed. The request for {first_token} has been processed successfully."
            llm_response = st.text_area("LLM Output Payload (Containing Vault Tokens):", value=default_llm_response, height=80)

            restored_response = rehydrate_text(llm_response, vault)
            st.markdown("**De-Anonymized Output (Restored at Client Proxy):**")
            st.success(restored_response)
        else:
            st.info("Vault is currently empty. Select 'Token Vault (Reversible)' strategy and input text with PII to generate tokens.")
else:
    st.info("👈 Select a scenario preset button above or type a prompt payload to run the guardrail engine.")