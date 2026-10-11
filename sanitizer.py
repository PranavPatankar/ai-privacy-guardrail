import re
import spacy

# Load spaCy NLP model with cloud fallback
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")
# Define Regular Expressions for structured data patterns
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
PHONE_REGEX = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
CARD_REGEX = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'


def sanitize_text(text: str) -> dict:
    """
    Scans input text for sensitive entities (PII) using Regex and spaCy NER.
    Returns sanitized text, entity counts, total redactions, and a risk level.
    """
    audit_log = {
        "EMAILS": 0,
        "PHONES": 0,
        "CARDS": 0,
        "NAMES": 0,
        "LOCATIONS": 0,
        "ORGS": 0
    }

    # -------------------------------------------------------------
    # STAGE 1: Regex Pattern Matching (Structured PII)
    # -------------------------------------------------------------
    
    # 1. Redact Emails
    emails = re.findall(EMAIL_REGEX, text)
    audit_log["EMAILS"] = len(emails)
    working_text = re.sub(EMAIL_REGEX, "[REDACTED_EMAIL]", text)

    # 2. Redact Phone Numbers
    phones = re.findall(PHONE_REGEX, working_text)
    audit_log["PHONES"] = len(phones)
    working_text = re.sub(PHONE_REGEX, "[REDACTED_PHONE]", working_text)

    # 3. Redact Credit Cards
    cards = re.findall(CARD_REGEX, working_text)
    audit_log["CARDS"] = len(cards)
    working_text = re.sub(CARD_REGEX, "[REDACTED_CARD]", working_text)

    # -------------------------------------------------------------
    # STAGE 2: SpaCy Named Entity Recognition (Unstructured PII)
    # -------------------------------------------------------------
    
    # Process intermediate text through spaCy NLP pipeline
    doc = nlp(working_text)
    entities_to_replace = []

    # Extract character offsets for Names, Locations, and Organizations
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            entities_to_replace.append((ent.start_char, ent.end_char, "[REDACTED_NAME]"))
            audit_log["NAMES"] += 1
        elif ent.label_ in ["GPE", "LOC"]:
            entities_to_replace.append((ent.start_char, ent.end_char, "[REDACTED_LOCATION]"))
            audit_log["LOCATIONS"] += 1
        elif ent.label_ == "ORG":
            entities_to_replace.append((ent.start_char, ent.end_char, "[REDACTED_ORG]"))
            audit_log["ORGS"] += 1

    # Replace entities backwards by start index so earlier text indices remain accurate
    sanitized_text = working_text
    for start, end, label in sorted(entities_to_replace, key=lambda x: x[0], reverse=True):
        sanitized_text = sanitized_text[:start] + label + sanitized_text[end:]

    # -------------------------------------------------------------
    # STAGE 3: Risk Level Calculation
    # -------------------------------------------------------------
    
    total_redactions = sum(audit_log.values())

    if audit_log["CARDS"] > 0 or audit_log["PHONES"] > 0:
        risk_level = "HIGH"
    elif total_redactions > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "sanitized_text": sanitized_text,
        "audit_log": audit_log,
        "total_redactions": total_redactions,
        "risk_level": risk_level
    }


# Local execution test block
if __name__ == "__main__":
    sample_prompt = (
        "Hello, my name is Bruce Wayne representing Wayne Enterprises located in Gotham City. "
        "You can reach out to bruce@wayne.com or call 555-839-2001. "
        "Billing account card number is 4111-2222-3333-4444."
    )

    print("Executing local test...\n")
    results = sanitize_text(sample_prompt)

    print("=" * 60)
    print("ORIGINAL INPUT PROMPT:")
    print("=" * 60)
    print(sample_prompt)

    print("\n" + "=" * 60)
    print("SANITIZED OUTPUT TEXT:")
    print("=" * 60)
    print(results["sanitized_text"])

    print("\n" + "=" * 60)
    print("AUDIT METRICS & RISK EVALUATION:")
    print("=" * 60)
    print(f"Total Entities Redacted: {results['total_redactions']}")
    print(f"Assigned Risk Level:    {results['risk_level']}")
    print("Entity Breakdown:")
    for key, val in results["audit_log"].items():
        print(f"  - {key}: {val}")
    print("=" * 60)