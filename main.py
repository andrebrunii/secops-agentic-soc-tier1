from pathlib import Path
from agents.triage_orchestrator import SOCAutonomousTriageOrchestrator


def format_incident_report_md(report: dict) -> str:
    ef = report["email_forensics"]
    iocs = report["defanged_iocs"]
    risk = report["risk_assessment"]
    siem = report["a2a_threat_intel_artifacts"]["siem_entra_id_correlation"]

    breakdown_md = "\n".join(f"- {item}" for item in risk["scoring_breakdown"])
    ips_md = ", ".join(f"`{ip}`" for ip in iocs["ips"]) or "Nessuno"
    urls_md = "\n".join(f"- `{u}`" for u in iocs["urls"]) or "- Nessuno"

    return f'''
================================================================================
🛡️  SOC TIER-1 INCIDENT REPORT (AUTONOMOUS TRIAGE)
================================================================================
• Skill Applicata      : {report['skill_applied']['skill_name']} (v{report['skill_applied']['version']})
• Verdetto Finale      : {risk['severity']} (Risk Score: {risk['risk_score']}/100)
• Human-in-the-Loop    : {'⚠️ APPROVAZIONE RICHIESTA PRIMA DEL BLOCCO' if risk['requires_human_approval'] else 'Nessuna azione critica'}

1. ANALISI FORENSE EMAIL & GUARDRAIL AI
--------------------------------------------------------------------------------
• Oggetto              : {ef['subject']}
• Mittente dichiarato  : {ef['from']}
• Return-Path reale    : {ef['return_path']}
• Utente Target        : {ef['target_user']}
• SHA-256 EML          : {ef['sha256']}
• Spoofing Rilevato    : {ef['security_flags']['domain_mismatch_spoofing']}
• Prompt Injection     : {'🚨 RILEVATA E BLOCCATA (' + ', '.join(ef['security_flags']['injection_patterns_matched']) + ')' if ef['security_flags']['prompt_injection_detected'] else 'Assente'}

2. INDICATORI DI COMPROMISSIONE (DEFANGED IoCs)
--------------------------------------------------------------------------------
• IP Estratti          : {ips_md}
• URL Estratti         :
{urls_md}

3. CORRELAZIONE SIEM (MICROSOFT ENTRA ID via MCP + A2A)
--------------------------------------------------------------------------------
• Eventi Trovati       : {siem.get('total_events_found', 0)}
• Paesi Rilevati       : {', '.join(siem.get('distinct_countries', []))}
• Impossible Travel    : {'🚨 CONFERMATO (Possibile furto sessione AiTM)' if siem.get('impossible_travel_detected') else 'No'}

4. MOTIVAZIONI DEL RISK SCORE (DETERMINISTICHE)
--------------------------------------------------------------------------------
{breakdown_md}

5. AZIONI DI REMEDIATION PROPOSTE (PENDING HUMAN APPROVAL)
--------------------------------------------------------------------------------
[ ] 1. Entra ID: Revoca immediata dei Refresh Token per '{ef['target_user']}' (Revoke-MgUserSignInSession).
[ ] 2. Firewall / Conditional Access: Blocca l'IP {ips_md}.
[ ] 3. Exchange Online: Hard-delete dell'email con SHA-256 {ef['sha256'][:16]}... da tutte le mailbox.
================================================================================
'''


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    skill_file = base_dir / "skills" / "nist_phishing_triage.md"
    sample_eml = base_dir / "sample_data" / "phishing_ceo_fraud.eml"

    orchestrator = SOCAutonomousTriageOrchestrator(skill_path=str(skill_file))
    result = orchestrator.run_incident_triage(eml_file_path=str(sample_eml))
    print(format_incident_report_md(result))
