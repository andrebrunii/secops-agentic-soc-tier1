from pathlib import Path
from tools.forensic_tools import (
    defang_indicator,
    parse_and_inspect_eml,
    extract_and_defang_iocs,
)


def test_defang_indicator():
    assert defang_indicator("https://evil.com/login") == "hxxps://evil[.]com/login"
    assert defang_indicator("185.220.101.42") == "185[.]220[.]101[.]42"


def test_eml_parsing_and_prompt_injection_detection():
    sample_eml = Path(__file__).resolve().parent.parent / "sample_data" / "phishing_ceo_fraud.eml"
    res = parse_and_inspect_eml(str(sample_eml))

    assert res["security_flags"]["domain_mismatch_spoofing"] is True
    assert res["security_flags"]["spf_fail"] is True
    assert res["security_flags"]["prompt_injection_detected"] is True


def test_ioc_extraction():
    iocs = extract_and_defang_iocs(
        raw_text="Visita https://login-microsoft-security-update.com/auth",
        headers_text="Received from 185.220.101.42",
    )
    assert "185.220.101.42" in iocs["raw_iocs"]["ips"]
    assert "185[.]220[.]101[.]42" in iocs["defanged_iocs"]["ips"]
