\# 🛡️ AI Data Privacy Guardrail (Real-Time PII Sanitizer)



\[!\[Streamlit App](https://static.streamlit.io/badges/streamlit\_badge\_black\_white.svg)](https://ai-privacy-guardrail.streamlit.app/)



An end-to-end NLP privacy guardrail that intercepts, audits, and redacts sensitive Personally Identifiable Information (PII) before sending text inputs to Large Language Models (LLMs).



🔗 \*\*Live Demo:\*\* \[ai-privacy-guardrail.streamlit.app](https://ai-privacy-guardrail.streamlit.app/)



\---



\## ✨ Features

\* \*\*Hybrid Sanitization Engine:\*\* Combines spaCy Named Entity Recognition (NER) for contextual entities with high-precision Regex rules for structured data.

\* \*\*Redacts 6 PII Types:\*\* Names (`PERSON`), Locations (`GPE`/`LOC`), Organizations (`ORG`), Emails, Phone Numbers, and Credit Cards.

\* \*\*Risk Assessment Engine:\*\* Dynamically rates sanitization urgency (`LOW`, `MEDIUM`, `HIGH`) based on detected sensitive financial or contact vector counts.

\* \*\*Interactive Dashboard:\*\* Side-by-side prompt inspection, detection metrics, entity breakdown visualizations, and sanitized text export (`.txt`).

\* \*\*Privacy-First Architecture:\*\* Runs zero-retention local text processing with $0 third-party server leakage.



\---



\## 🛠️ Tech Stack

\* \*\*Language:\*\* Python 3.10+

\* \*\*NLP \& Regex:\*\* spaCy (`en\_core\_web\_sm`), Python `re` module

\* \*\*Frontend \& Dashboard:\*\* Streamlit, Pandas, Plotly Express

\* \*\*Deployment:\*\* GitHub, Streamlit Community Cloud



\---



\## 📁 Repository Structure

```text

ai-privacy-guardrail/

│

├── app.py              # Streamlit Web UI \& Analytics Engine

├── sanitizer.py        # Core PII Detection \& Redaction Backend

├── requirements.txt    # Cloud Dependency Configuration

├── .gitignore          # Environment \& System File Exclusions

└── README.md           # Project Documentation

