import re
import uuid
from pathlib import Path
from typing import Dict, Any

from tools.forensic_tools import (
    parse_and_inspect_eml,
    extract_and_defang_iocs,
    calculate_deterministic_risk,
)
from agents.threat_intel_a2a_agent import ThreatIntelA2AAgent


class SOCAutonomousTriageOrchestrator:
    '''
    Agente Primario SOC Tier-1.
    Carica dinamicamente la Skill in Markdown, esegue i Function Tools forensi
    e delega l'arricchimento SIEM/ThreatIntel tramite protocollo A2A.
    '''

    def __init__(self, skill_path: str):
        self.skill_path = Path(skill_path)
        self.skill_metadata = self._load_markdown_skill()
        self.a2a_peer = ThreatIntelA2AAgent()

    def _load_markdown_skill(self) -> Dict[str, Any]:
        content = self.skill_path.read_text(encoding="utf-8")
        name_match = re.search(r"^name:\s*(.+)$", content, flags=re.MULTILINE)
        version_match = re.search(r"^version:\s*(.+)$", content, flags=re.MULTILINE)
        return {
            "skill_file": self.skill_path.name,
            "skill_name": name_match.group(1).strip() if name_match else "unknown-skill",
            "version": version_match.group(1).strip() if version_match else "1.0.0",
            "instructions_length_chars": len(content),
        }

    def run_incident_triage(self, eml_file_path: str) -> Dict[str, Any]:
        print(f"\n[1/5] 📚 Caricamento Skill Markdown: {self.skill_metadata['skill_name']} (v{self.skill_metadata['version']})")

        print("[2/5] 🔍 Esecuzione Function Tools forensi sul file EML...")
        eml_data = parse_and_inspect_eml(eml_file_path)
        iocs = extract_and_defang_iocs(
            raw_text=eml_data["raw_body_text"],
            headers_text=eml_data["raw_headers_Text"],
        )

        if eml_data["security_flags"]["prompt_injection_detected"]:
            print("      ⚠️  [GUARDRAIL ALERT] Rilevato tentativo di Indirect Prompt Injection nel corpo dell'email! Neutralizzato.")

        to_email_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", eml_data["to"])
        target_user = to_email_match.group(0) if to_email_match else eml_data["to"]

        agent_card = self.a2a_peer.get_agent_card()
        print(f"[3/5] 🤝 Handshake A2A con '{agent_card['name']}' (Access Level: {agent_card['securityPolicy']['accessLevel']})")

        a2a_request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tasks/send",
            "params": {
                "taskId": f"soc-triage-{uuid.uuid4().hex[:8]}",
                "senderAgent": "secops-triage-orchestrator",
                "payload": {
                    "ips": iocs["raw_iocs"]["ips"],
                    "domains": iocs["raw_iocs"]["domains"],
                    "target_user": target_user,
                },
            },
        }

        print("[4/5] 🛰️  Invio Task A2A -> Interrogazione Server MCP (Threat Intel + Log Entra ID)...")
        a2a_response = self.a2a_peer.handle_a2a_task(a2a_request)
        artifacts = a2a_response["result"]["artifacts"]

        print("[5/5] 🧮 Calcolo Risk Score deterministico e generazione Playbook di Remediation...")
        risk_assessment = calculate_deterministic_risk(
            security_flags=eml_data["security_flags"],
            threat_intel_report=artifacts["summary_flags"],
        )

        return {
            "skill_applied": self.skill_metadata,
            "email_forensics": {
                "sha256": eml_data["eml_sha256"],
                "subject": eml_data["subject"],
                "from": eml_data["from"],
                "return_path": eml_data["return_path"],
                "target_user": target_user,
                "security_flags": eml_data["security_flags"],
            },
            "defanged_iocs": iocs["defanged_iocs"],
            "a2a_threat_intel_artifacts": artifacts,
            "risk_assessment": risk_assessment,
        }
