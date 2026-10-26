import json
from pathlib import Path
from typing import Dict, Any, List

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("SecOps-SIEM-and-ThreatIntel-MCP")
except ImportError:
    # Fallback leggero se l'utente esegue la demo senza aver installato il pacchetto mcp
    class DummyMCP:
        def resource(self, *args, **kwargs):
            return lambda f: f
        def tool(self, *args, **kwargs):
            return lambda f: f
        def run(self, *args, **kwargs):
            pass
    mcp = DummyMCP()

BASE_DIR = Path(__file__).resolve().parent.parent
SIEM_LOGS_PATH = BASE_DIR / "sample_data" / "entra_id_signin_logs.json"

THREAT_INTEL_DB: Dict[str, Dict[str, Any]] = {
    "185.220.101.42": {
        "type": "ip",
        "reputation": "MALICIOUS",
        "confidence": 98,
        "threat_actor": "Midnight Blizzard / APT29 Infrastructure",
        "tags": ["tor-exit-node", "credential-harvesting", "phishing-relay"],
    },
    "login-microsoft-security-update.com": {
        "type": "domain",
        "reputation": "MALICIOUS",
        "confidence": 100,
        "threat_actor": "Tycoon 2FA Phishing Kit (AiTM)",
        "tags": ["aitm-phishing", "entra-id-spoof", "newly-registered-domain"],
    },
}


@mcp.resource("siem://entra-id/recent-signins")
def get_recent_signin_logs_resource() -> str:
    '''Risorsa MCP in sola lettura che espone i log grezzi di accesso Cloud (Entra ID).'''
    if not SIEM_LOGS_PATH.exists():
        return json.dumps({"error": "Log file not found"})
    return SIEM_LOGS_PATH.read_text(encoding="utf-8")


@mcp.tool()
def lookup_ioc_reputation(indicator: str) -> Dict[str, Any]:
    '''Interroga il feed di Threat Intelligence per un IP o un dominio (Read-Only).'''
    clean_ind = indicator.strip().lower()
    if clean_ind in THREAT_INTEL_DB:
        return {
            "indicator": clean_ind,
            "found": True,
            **THREAT_INTEL_DB[clean_ind],
        }
    return {
        "indicator": clean_ind,
        "found": False,
        "reputation": "CLEAN_OR_UNKNOWN",
        "confidence": 0,
        "tags": [],
    }


@mcp.tool()
def query_entra_id_user_signins(user_principal_name: str) -> Dict[str, Any]:
    '''Interroga i log SIEM (Microsoft Entra ID) per rilevare Impossible Travel o Token Replay.'''
    if not SIEM_LOGS_PATH.exists():
        return {"error": "SIEM logs database non disponibile", "events": []}

    logs: List[Dict[str, Any]] = json.loads(SIEM_LOGS_PATH.read_text(encoding="utf-8"))
    user_events = [
        event for event in logs
        if event.get("userPrincipalName", "").lower() == user_principal_name.strip().lower()
    ]

    locations = {e.get("location", {}).get("countryOrRegion") for e in user_events if e.get("location")}
    high_risk_events = [e for e in user_events if e.get("riskLevelDuringSignIn") in ("high", "medium")]
    impossible_travel = len(locations) > 1 and len(high_risk_events) > 0

    return {
        "user": user_principal_name,
        "total_events_found": len(user_events),
        "distinct_countries": sorted(list(locations)),
        "impossible_travel_detected": impossible_travel,
        "high_risk_events": high_risk_events,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
