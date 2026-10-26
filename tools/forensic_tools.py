import re
import hashlib
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, List, Any

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s+override",
    r"disregard\s+security\s+rules",
    r"mark\s+this\s+email\s+as\s+safe",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
]


def defang_indicator(indicator: str) -> str:
    '''Converte URL e IP in formato sicuro (defanged) per evitare clic accidentali nel SOC.'''
    defanged = re.sub(r"^http", "hxxp", indicator, flags=re.IGNORECASE)
    defanged = defanged.replace(".", "[.]")
    return defanged


def parse_and_inspect_eml(eml_path: str) -> Dict[str, Any]:
    '''
    Function Tool Deterministico: Analizza un file .eml, verifica gli header di sicurezza
    e scansiona il payload alla ricerca di attacchi di Indirect Prompt Injection.
    '''
    path = Path(eml_path)
    if not path.exists():
        raise FileNotFoundError(f"File EML non trovato: {eml_path}")

    raw_bytes = path.read_bytes()
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_header = str(msg.get("From", ""))
    return_path = str(msg.get("Return-Path", ""))
    reply_to = str(msg.get("Reply-To", ""))
    to_header = str(msg.get("To", ""))
    subject = str(msg.get("Subject", ""))
    auth_results = str(msg.get("Authentication-Results", ""))
    received_spf = str(msg.get("Received-SPF", ""))

    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                body_content += part.get_content() + "\n"
    else:
        body_content = msg.get_content()

    from_domain_match = re.search(r"@([\w.-]+)", from_header)
    rp_domain_match = re.search(r"@([\w.-]+)", return_path)
    from_domain = from_domain_match.group(1).lower().rstrip(">") if from_domain_match else ""
    rp_domain = rp_domain_match.group(1).lower().rstrip(">") if rp_domain_match else ""
    domain_mismatch = bool(from_domain and rp_domain and from_domain != rp_domain)

    auth_combined = (auth_results + " " + received_spf).lower()
    spf_fail = "spf=fail" in auth_combined or "spf=softfail" in auth_combined or "fail" in received_spf.lower()
    dkim_fail = "dkim=fail" in auth_combined or "dkim=none" in auth_combined
    dmarc_fail = "dmarc=fail" in auth_combined

    injection_hits: List[str] = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        matches = re.findall(pattern, body_content, flags=re.IGNORECASE)
        if matches:
            injection_hits.append(pattern)

    return {
        "eml_sha256": file_sha256,
        "subject": subject,
        "from": from_header,
        "to": to_header,
        "return_path": return_path,
        "reply_to": reply_to,
        "security_flags": {
            "domain_mismatch_spoofing": domain_mismatch,
            "spf_fail": spf_fail,
            "dkim_fail": dkim_fail,
            "dmarc_fail": dmarc_fail,
            "prompt_injection_detected": len(injection_hits) > 0,
            "injection_patterns_matched": injection_hits,
        },
        "raw_headers_Text": f"{auth_results} | {received_spf}",
        "raw_body_text": body_content,
    }


def extract_and_defang_iocs(raw_text: str, headers_text: str = "") -> Dict[str, Any]:
    '''
    Function Tool Deterministico: Estrae IPv4 pubblici, URL e domini tramite Regex
    e restituisce sia la versione grezza sia quella defanged.
    '''
    combined = f"{headers_text}\n{raw_text}"

    ip_regex = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    all_ips = sorted(set(re.findall(ip_regex, combined)))
    public_ips = [
        ip for ip in all_ips
        if not (ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."))
    ]

    url_regex = r"https?://[^\s\"'<>]+"
    urls = sorted(set(re.findall(url_regex, raw_text)))

    domains = sorted({
        re.sub(r"^https?://([^/:]+).*$", r"\1", u).lower()
        for u in urls
    })

    return {
        "raw_iocs": {
            "ips": public_ips,
            "urls": urls,
            "domains": domains,
        },
        "defanged_iocs": {
            "ips": [defang_indicator(ip) for ip in public_ips],
            "urls": [defang_indicator(u) for u in urls],
            "domains": [defang_indicator(d) for d in domains],
        },
    }


def calculate_deterministic_risk(
    security_flags: Dict[str, Any],
    threat_intel_report: Dict[str, Any]
) -> Dict[str, Any]:
    '''
    Function Tool Deterministico: Calcola un Risk Score (0-100) spiegabile e verificabile.
    '''
    score = 0
    reasons: List[str] = []

    if security_flags.get("domain_mismatch_spoofing"):
        score += 20
        reasons.append("Disallineamento tra dominio From e Return-Path (+20)")

    if security_flags.get("spf_fail") or security_flags.get("dmarc_fail"):
        score += 20
        reasons.append("Fallimento autenticazione SPF/DMARC (+20)")

    if security_flags.get("prompt_injection_detected"):
        score += 25
        reasons.append("Rilevato payload di Indirect Prompt Injection nel corpo dell'email (+25)")

    if threat_intel_report.get("malicious_ip_found"):
        score += 20
        reasons.append("IP mittente classificato come malevolo nel feed Threat Intel (+20)")

    if threat_intel_report.get("malicious_domain_found"):
        score += 20
        reasons.append("Dominio di phishing confermato nel feed Threat Intel (+20)")

    if threat_intel_report.get("impossible_travel_detected"):
        score += 25
        reasons.append("Correlazione SIEM: rilevato evento di Impossible Travel / Anomalous Sign-in sull'utente target (+25)")

    final_score = min(score, 100)
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": final_score,
        "severity": severity,
        "requires_human_approval": final_score >= 50,
        "scoring_breakdown": reasons,
    }
