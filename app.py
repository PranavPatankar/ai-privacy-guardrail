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

# 2. Bespoke Theme & UI Stylesheet
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Typography & Background */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: #080B11;
        color: #F1F5F9;
    }

    /* Hide Default Streamlit Chrome */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Enterprise Navigation Header Bar */
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

    /* Cards & Containers */
    .console-card {
        background: #0D131F;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 1.2rem;
        margin-bottom: 1rem;
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

    /* Terminal Code Display */
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

    /* Custom Metric Styling */
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

    /* Sidebar Refinement */
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

# 3. Top Navigation Header
st.markdown("""
<div class="top-nav">
    <div class="brand-group">
        <div class="brand-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#080B11" stroke-width="2.5