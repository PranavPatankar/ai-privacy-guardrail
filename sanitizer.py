import re
import spacy
from faker import Faker

# Load spaCy NLP model with automated fallback
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

fake = Faker()

# Extended High-Precision Regex Patterns
REGEX_PATTERNS = {
    "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
    "PHONE": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "CREDIT_CARD": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    "PAN_CARD": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "AADHAAR": r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "AWS_KEY": r'\bAKIA[0-9A-Z]{16}\b',
    "API_KEY": r'\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b',
    "GITHUB_TOKEN": r'\bgh[pousr]_[A-Za-z0-9]{36,}\b',
    "SLACK_TOKEN": r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
    "JWT": r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
    "GOOGLE_API_KEY": r'\bAIza[0-9A-Za-z_-]{35}\b'
}

COLOR_MAP = {
    "PERSON": "#FF4B4B",
    "EMAIL": "#00C0F2",
    "PHONE": "#00D4B1",
    "CREDIT_CARD": "#FF8700",
    "ORG": "#7D3C98",
    "GPE": "#2ECC71",
    "LOC": "#2ECC71",
    "PAN_CARD": "#E74C3C",
    "AADHAAR": "#D35400",
    "SSN": "#C0392B",
    "AWS_KEY": "#F39C12",
    "API_KEY": "#F1C40F",
    "GITHUB_TOKEN": "#6E5494",
    "SLACK_TOKEN": "#ECB22E",
    "JWT": "#16A085",
    "GOOGLE_API_KEY": "#4285F4"
}

def _passes_luhn(digits):
    """Validates a numeric string against the Luhn checksum to cut credit-card false positives."""
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        d = int(d)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def obfuscate_value(value, entity_type):
    """Partially masks sensitive data (e.g. j***n@gmail.com)."""
    if entity_type == "EMAIL" and "@" in value:
        name, domain = value.split("@", 1)
        return f"{name[0]}***{name[-1] if len(name)>1 else ''}@{domain}"
    elif entity_type in ["CREDIT_CARD", "PAN_CARD", "AADHAAR", "SSN"]:
        return f"****-****-{value[-4:]}"
    elif len(value) > 3:
        return f"{value[0]}***{value[-1]}"
    return "***"

def get_synthetic_value(entity_type):
    """Generates realistic fake data using Faker."""
    mapping = {
        "PERSON": fake.name(),
        "EMAIL": fake.email(),
        "PHONE": fake.phone_number(),
        "CREDIT_CARD": fake.credit_card_number(),
        "ORG": fake.company(),
        "GPE": fake.city(),
        "LOC": fake.city(),
        "PAN_CARD": "ABCDE1234F",
        "AADHAAR": "9999 8888 7777",
        "SSN": "000-12-3456",
        "AWS_KEY": "AKIAIOSFODNN7EXAMPLE",
        "API_KEY": "sk-proj-FAKEKEY12345678901234567890",
        "GITHUB_TOKEN": "ghp_FAKEGITHUBTOKEN1234567890123456",
        "SLACK_TOKEN": "xoxb-FAKE-SLACK-TOKEN-0000000000",
        "JWT": "eyJFAKE.eyJQQVlMT0FE.FAKESIGNATURE",
        "GOOGLE_API_KEY": "AIzaFAKEGOOGLEAPIKEY000000000000000"
    }
    return mapping.get(entity_type, "[REDACTED]")

def analyze_and_sanitize(text, mode="Token Vault (Reversible)"):
    """
    Scans text for PII & secrets, redacts them according to selected strategy,
    and returns detected metadata, sanitized text, and vault mapping.
    """
    if not text.strip():
        return text, [], "LOW", {}

    doc = nlp(text)
    detected_entities = []
    vault = {}
    counters = {}

    # 1. Detect SpaCy NER Entities
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "ORG", "GPE", "LOC"]:
            detected_entities.append({
                "start": ent.start_char,
                "end": ent.end_char,
                "text": ent.text,
                "type": ent.label_
            })

    # 2. Detect Regex Entities
    for ent_type, pattern in REGEX_PATTERNS.items():
        for match in re.finditer(pattern, text):
            if ent_type == "CREDIT_CARD":
                digits = re.sub(r'[-\s]', '', match.group())
                if not _passes_luhn(digits):
                    continue
            if not any(e["start"] <= match.start() < e["end"] for e in detected_entities):
                detected_entities.append({
                    "start": match.start(),
                    "end": match.end(),
                    "text": match.group(),
                    "type": ent_type
                })

    detected_entities.sort(key=lambda x: x["start"], reverse=True)

    sanitized_text = text

    for ent in detected_entities:
        e_type = ent["type"]
        val = ent["text"]
        counters[e_type] = counters.get(e_type, 0) + 1
        idx = counters[e_type]

        if mode == "Token Vault (Reversible)":
            token = f"{{{{{e_type}_{idx}}}}}"
            replacement = token
            vault[token] = val
        elif mode == "Label Masking":
            replacement = f"[{e_type}_REDACTED]"
        elif mode == "Partial Obfuscation":
            replacement = obfuscate_value(val, e_type)
        elif mode == "Synthetic Substitution":
            replacement = get_synthetic_value(e_type)
        else:
            replacement = "[REDACTED]"

        sanitized_text = sanitized_text[:ent["start"]] + replacement + sanitized_text[ent["end"]:]

    total_count = len(detected_entities)
    critical_types = {
        "CREDIT_CARD", "PAN_CARD", "AADHAAR", "SSN", "AWS_KEY", "API_KEY",
        "GITHUB_TOKEN", "SLACK_TOKEN", "JWT", "GOOGLE_API_KEY"
    }
    has_critical = any(e["type"] in critical_types for e in detected_entities)

    if total_count == 0:
        risk = "LOW"
    elif has_critical or total_count >= 4:
        risk = "HIGH"
    else:
        risk = "MEDIUM"

    detected_entities.sort(key=lambda x: x["start"])

    return sanitized_text, detected_entities, risk, vault

def rehydrate_text(sanitized_text, vault):
    """Replaces tokens back with original values from vault."""
    restored = sanitized_text
    for token, original in vault.items():
        restored = restored.replace(token, original)
    return restored