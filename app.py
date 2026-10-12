import streamlit as st
import pandas as pd
import plotly.express as px
from sanitizer import analyze_and_sanitize, rehydrate_text, COLOR_MAP

st.set_page_config(
    page_title="AI Data Privacy Guardrail",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.85em;
        margin: 0 2px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI Data Privacy Guardrail")
st.caption("Real-Time PII & Security Secret Interception Engine for LLM Pipelines")

PRESETS = {
    "Select a Preset Scenario...": "",
    "📋 Customer Support Ticket": "Hello, my name is Sarah Jenkins. My phone number is 415-555-2671 and email is s.jenkins@techcorp.io. I was charged on my card 4532-7182-9910-1201.",
    "💳 Financial & Tax Document": "Tax Filing for Rajesh Kumar (PAN: ABCDE1234F, Aadhaar: 9876 5432 1098). Account manager at HDFC Bank, Mumbai.",
    "🔑 Leaked API Secrets Prompt": "Deploying server to AWS. Here is my access key AKIAIOSFODNN7EXAMPLE and OpenAI secret sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Please write a script.",
}

st.sidebar.header("⚙️ Guardrail Settings")

redaction_mode = st.sidebar.radio(
    "Redaction Strategy",
    ["Token Vault (Reversible)", "Label Masking", "Partial Obfuscation", "Synthetic Substitution"],
    help="Choose how sensitive entities are obfuscated in the outgoing prompt."
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Supported Identifiers")
st.sidebar.markdown("""
- 👤 **Names & Entities:** Person, Org, Location
- 📧 **Contact:** Email, Phone Number
- 💳 **Financial:** Credit Cards, PAN, Aadhaar, SSN
- 🔑 **Secrets:** AWS Keys, OpenAI API Keys
""")

col_select, _ = st.columns([2, 1])
with col_select:
    selected_preset = st.selectbox("Quick Load Preset Scenario", list(PRESETS.keys()))

if "user_input" not in st.session_state:
    st.session_state["user_input"] = ""

if selected_preset and PRESETS[selected_preset]:
    st.session_state["user_input"] = PRESETS[selected_preset]

user_text = st.text_area(
    "Enter Prompt / Text Payload:",
    value=st.session_state["user_input"],
    height=140,
    placeholder="Type or paste text containing names, emails, phone numbers, or API keys..."
)

if user_text:
    sanitized_text, entities, risk_level, vault = analyze_and_sanitize(user_text, mode=redaction_mode)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Detected Entities", len(entities))
    with m2:
        risk_color = "🟢" if risk_level == "LOW" else "🟡" if risk_level == "MEDIUM" else "🔴"
        st.metric("Risk Level", f"{risk_color} {risk_level}")
    with m3:
        st.metric("Redaction Mode", redaction_mode.split()[0])
    with m4:
        st.metric("Vault Tokens", len(vault))

    st.markdown("---")

    tab_inspect, tab_visual, tab_vault = st.tabs(["🔍 Prompt Inspection", "🏷️ Visual Entity Map", "🔄 LLM Proxy & Re-hydration"])

    with tab_inspect:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Original Input Payload")
            st.info(user_text)
        with c2:
            st.subheader("Sanitized Output (LLM Ready)")
            st.success(sanitized_text)

            st.download_button(
                label="📥 Download Sanitized Text",
                data=sanitized_text,
                file_name="sanitized_prompt.txt",
                mime="text/plain"
            )

    with tab_visual:
        st.subheader("Annotated Visual Entity Map")
        if entities:
            annotated_html = user_text
            sorted_ents = sorted(entities, key=lambda x: x["start"], reverse=True)
            for e in sorted_ents:
                color = COLOR_MAP.get(e["type"], "#7f8c8d")
                span = f'<span class="badge" style="background-color:{color}22; border:1px solid {color}; color:{color};">{e["text"]} <small>({e["type"]})</small></span>'
                annotated_html = annotated_html[:e["start"]] + span + annotated_html[e["end"]:]

            st.markdown(f'<div style="line-height:2.2; font-size:1.05em; background-color:#0E1117; padding:15px; border-radius:8px; border:1px solid #262730;">{annotated_html}</div>', unsafe_allow_html=True)

            st.markdown("### Entity Type Breakdown")
            df_ent = pd.DataFrame(entities)
            counts = df_ent["type"].value_counts().reset_index()
            counts.columns = ["Entity Type", "Count"]

            fig = px.bar(
                counts,
                x="Entity Type",
                y="Count",
                color="Entity Type",
                color_discrete_map=COLOR_MAP,
                text_auto=True
            )
            fig.update_layout(showlegend=False, height=300, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("Zero PII or sensitive patterns detected in payload.")

    with tab_vault:
        st.subheader("Token Mapping & LLM Re-hydration Playground")
        st.caption("Demonstrates how a secure privacy proxy intercepts LLM outputs and restores original entity values.")

        if vault:
            st.markdown("#### 🔑 Active Token Vault Mapping")
            df_vault = pd.DataFrame(list(vault.items()), columns=["Token Placeholder", "Original Plaintext Value"])
            st.dataframe(df_vault, use_container_width=True)

            st.markdown("---")
            st.markdown("#### 🤖 Simulated LLM Response Re-hydration")

            first_token = list(vault.keys())[0]
            default_llm_response = f"Hello, I have processed the request for {first_token}. A confirmation record has been generated."
            llm_response = st.text_area("Simulated Raw LLM Response (containing tokens):", value=default_llm_response, height=80)

            restored_response = rehydrate_text(llm_response, vault)
            st.markdown("**Restored Response (Post De-Anonymization):**")
            st.success(restored_response)
        else:
            st.info("No tokens active in vault. Select 'Token Vault (Reversible)' strategy and enter text containing PII.")