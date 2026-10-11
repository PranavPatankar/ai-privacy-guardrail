import streamlit as st
import pandas as pd
import plotly.express as px
from sanitizer import sanitize_text

# Page Configuration
st.set_page_config(
    page_title="AI Data Privacy Guardrail",
    page_icon="🛡️",
    layout="wide"
)

# Application Header
st.title("🛡️ Real-Time PII Sanitizer & AI Safety Guardrail")
st.markdown(
    "Detect and redact sensitive Personally Identifiable Information (PII) "
    "from prompts before sending them to external AI models."
)

st.divider()

# Sidebar Settings & Info
with st.sidebar:
    st.header("⚙️ Guardrail Info")
    st.info(
        "This tool uses local Regex patterns and spaCy Named Entity Recognition (NER) "
        "to sanitize text without sending data to third-party servers."
    )
    st.markdown("---")
    st.subheader("Supported Entities:")
    st.markdown("- 👤 Names (`PERSON`)")
    st.markdown("- 📧 Emails (`EMAIL`)")
    st.markdown("- 📞 Phone Numbers (`PHONE`)")
    st.markdown("- 💳 Credit Cards (`CARD`)")
    st.markdown("- 📍 Locations (`GPE / LOC`)")
    st.markdown("- 🏢 Organizations (`ORG`)")

# Input Text Box
default_sample = (
    "Hello, my name is Bruce Wayne representing Wayne Enterprises located in Gotham City. "
    "You can reach out to bruce@wayne.com or call 555-839-2001. "
    "Billing account card number is 4111-2222-3333-4444."
)

user_input = st.text_area(
    "Enter raw text or LLM prompt to scan:",
    value=default_sample,
    height=140
)

# Process Button
if st.button("🛡️ Sanitize & Audit Text", type="primary"):
    if not user_input.strip():
        st.warning("Please enter text to scan.")
    else:
        # Run sanitizer backend engine
        results = sanitize_text(user_input)
        
        # Display Key Metric Cards
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Redactions", results["total_redactions"])
        
        risk = results["risk_level"]
        if risk == "HIGH":
            m2.metric("Risk Assessment", risk, delta="Sensitive Financial/Phone Data", delta_color="inverse")
        elif risk == "MEDIUM":
            m2.metric("Risk Assessment", risk, delta="Moderate PII Detected", delta_color="off")
        else:
            m2.metric("Risk Assessment", risk, delta="Clean Output", delta_color="normal")
            
        m3.metric("Engine Architecture", "spaCy + Regex")

        st.divider()

        # Side-by-Side Comparison Layout
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Original Input Prompt")
            st.text_area("Input", value=user_input, height=200, disabled=True, label_visibility="collapsed")

        with col_right:
            st.subheader("Sanitized Output Text")
            st.text_area("Output", value=results["sanitized_text"], height=200, disabled=True, label_visibility="collapsed")
            
            # Download Sanitized File Button
            st.download_button(
                label="📥 Download Sanitized Text",
                data=results["sanitized_text"],
                file_name="sanitized_prompt.txt",
                mime="text/plain"
            )

        st.divider()

        # Entity Breakdown Bar Chart
        st.subheader("📊 Entity Detection Analytics")
        
        df_audit = pd.DataFrame(
            list(results["audit_log"].items()),
            columns=["Entity Type", "Count"]
        )
        
        fig = px.bar(
            df_audit,
            x="Entity Type",
            y="Count",
            color="Entity Type",
            text="Count",
            title="Distribution of Redacted Entities"
        )
        fig.update_traces(textposition='outside')
        st.plotly_chart(fig, use_container_width=True)