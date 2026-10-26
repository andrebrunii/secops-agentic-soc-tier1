import json
from pathlib import Path
from typing import Dict, Any, List
from mcp_servers.secops_mcp_server import (
    lookup_ioc_reputation,
    query_entra_id_user_signins,
)

AGENT_CARD_PATH = Path(__file__).resolve().parent / "agent_card.json"


class ThreatIntelA2AAgent:
    '''
    Agente secondario che implementa il protocollo A2A (Agent-to-Agent).
    Accetta Task JSON-RPC 2.0, verifica la propria AgentCard e interroga il Server MCP.
    '''

    def get_agent_card(self) -> Dict[str, Any]:
        return json.loads(AGENT_CARD_PATH.read_text(encoding="utf-8"))

    def handle_a2a_task(self, jsonrpc_request: Dict[str, Any]) -> Dict[str, Any]:
        req_id = jsonrpc_request.get("id", "task-001")
        method = jsonrpc_request.get("method")
        params = jsonrpc_request.get("params", {})

        if method != "tasks/send":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Metodo A2A non supportato: {method}"},
            }

        payload = params.get("payload", {})
        ips: List[str] = payload.get("ips", [])
        domains: List[str] = payload.get("domains", [])
        target_user: str = payload.get("target_user", "")

        ip_results = [lookup_ioc_reputation(ip) for ip in ips]
        malicious_ip_found = any(r.get("reputation") == "MALICIOUS" for r in ip_results)

        domain_results = [lookup_ioc_reputation(d) for d in domains]
        malicious_domain_found = any(r.get("reputation") == "MALICIOUS" for r in domain_results)

        siem_correlation = query_entra_id_user_signins(target_user) if target_user else {}
        impossible_travel = siem_correlation.get("impossible_travel_detected", False)

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "taskId": params.get("taskId", "a2a-subtask-1"),
                "status": "COMPLETED",
                "responderAgent": "secops-threat-intel-agent",
                "artifacts": {
                    "ip_enrichment": ip_results,
                    "domain_enrichment": domain_results,
                    "siem_entra_id_correlation": siem_correlation,
                    "summary_flags": {
                        "malicious_ip_found": malicious_ip_found,
                        "malicious_domain_found": malicious_domain_found,
                        "impossible_travel_detected": impossible_travel,
                    },
                },
            },
        }
