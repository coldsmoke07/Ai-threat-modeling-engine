"""STRIDE Threat Modeling AI Module.

Analyzes the candidate architecture graph (nodes, data flows, trust zones)
and requirements to identify potential security threats using the STRIDE framework:
- Spoofing Identity
- Tampering with Data
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from ollama_utils import check_ollama_status, select_model
except ImportError:
    def check_ollama_status() -> tuple[bool, str]:
        return False, "ollama_utils unavailable"

    def select_model() -> str:
        return "qwen3:4b"

BASE_DIR = Path(__file__).resolve().parent
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "threat_model.json"
OLLAMA_URL = "http://localhost:11434/api/chat"


def load_json(path: Path, name: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing {name} file: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def analyze_threats(architecture: dict[str, Any], requirements: dict[str, Any]) -> dict[str, Any]:
    online, status_msg = check_ollama_status()
    if not online:
        print(f"Notice: Ollama unavailable ({status_msg}). Generating heuristic STRIDE threat model.")
        return generate_heuristic_threats(architecture)

    model_name = select_model()
    print(f"Running STRIDE Threat Modeling with model '{model_name}'...")

    system_prompt = """You are an expert Cybersecurity & Cloud Threat Modeling Engine specializing in STRIDE analysis.

Analyze the provided architecture graph (nodes, edges, trust boundaries) and requirements to identify potential threats.
Map each threat to the STRIDE categories:
- S: Spoofing (Identity imposter, unauthenticated access)
- T: Tampering (Data alteration in transit or at rest)
- R: Repudiation (Lack of auditing, logging, or non-repudiation controls)
- I: Information Disclosure (Data leak, unencrypted communication)
- D: Denial of Service (Resource exhaustion, single point of failure)
- E: Elevation of Privilege (Authorization bypass, RBAC weaknesses)

Return JSON ONLY using this exact schema:
{
  "summary": {
    "total_threats": 0,
    "high_severity": 0,
    "medium_severity": 0,
    "low_severity": 0
  },
  "threats": [
    {
      "threat_id": "THR-001",
      "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "title": "Short threat title",
      "target_type": "node|edge|trust_zone",
      "target_id": "exact target node/edge ID",
      "description": "Detailed explanation of potential risk",
      "severity": "HIGH|MEDIUM|LOW",
      "mitigation": "Recommended mitigation control",
      "requirement_id": "REQ-001 or N/A"
    }
  ]
}"""

    user_prompt = f"""Target Architecture: {architecture.get('architecture_name', 'System')}
Style: {architecture.get('architecture_style', 'Distributed')}

NODES:
{json.dumps(architecture.get('nodes', []), indent=2)}

DATA FLOWS / EDGES:
{json.dumps(architecture.get('edges', []), indent=2)}

TRUST ZONES:
{json.dumps(architecture.get('trust_zones', []), indent=2)}

SECURITY REQUIREMENTS:
{json.dumps(requirements.get('security_requirements', []), indent=2)}
"""

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": 0.1},
        "stream": False,
    }

    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            content = result.get("message", {}).get("content", "")
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            threat_data = json.loads(content)
            threats = threat_data.get("threats", [])
            if not isinstance(threats, list) or not threats:
                return generate_heuristic_threats(architecture)

            high = sum(1 for t in threats if str(t.get("severity", "")).upper() == "HIGH")
            med = sum(1 for t in threats if str(t.get("severity", "")).upper() == "MEDIUM")
            low = sum(1 for t in threats if str(t.get("severity", "")).upper() == "LOW")
            threat_data["summary"] = {
                "total_threats": len(threats),
                "high_severity": high,
                "medium_severity": med,
                "low_severity": low,
            }
            threat_data["generated_at"] = datetime.now(timezone.utc).isoformat()
            threat_data["model_used"] = model_name
            return threat_data
    except Exception as err:
        print(f"Warning: AI Threat Modeling failed or timed out ({err}). Generating heuristic fallback STRIDE threat model.")
        return generate_heuristic_threats(architecture)


def generate_heuristic_threats(architecture: dict[str, Any]) -> dict[str, Any]:
    """Comprehensive rule-based STRIDE threat analyzer across edges and nodes."""
    threats = []
    nodes = {str(n.get("id")): n for n in architecture.get("nodes", []) if isinstance(n, dict)}
    edges = architecture.get("edges", [])

    count = 1
    for edge in edges:
        edge_id = str(edge.get("id", f"edge_{count}"))
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        protocol = str(edge.get("protocol", "HTTPS")).upper()
        encryption = str(edge.get("encryption", "")).upper()
        auth = str(edge.get("authentication", "")).upper()
        is_boundary = bool(edge.get("trust_boundary_crossing", False))
        req_ids = edge.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"

        # 1. Information Disclosure on boundary-crossing or unencrypted flows
        if protocol in {"HTTP", "TCP", "UDP"} or "NONE" in encryption or is_boundary:
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Information Disclosure",
                "title": f"Data Interception / Eavesdropping Risk on {edge_id}",
                "target_type": "edge",
                "target_id": edge_id,
                "description": (
                    f"Flow '{edge_id}' from '{source_id}' to '{target_id}' crosses a trust boundary over {protocol} "
                    "and requires strict TLS 1.2+ certificate validation to prevent sensitive data exposure."
                ),
                "severity": "HIGH" if is_boundary else "MEDIUM",
                "mitigation": "Enforce TLS 1.3 with strict certificate validation and mutual workload identity.",
                "requirement_id": req_id,
            })
            count += 1

        # 2. Spoofing on external/client entry flows or weak authentication
        if auth in {"NONE", "OPTIONAL", ""} or any(k in source_id.upper() for k in ("CLIENT", "GUEST", "STAFF", "WEB", "PORTAL")):
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Spoofing",
                "title": f"Identity Spoofing / Session Hijacking at {edge_id}",
                "target_type": "edge",
                "target_id": edge_id,
                "description": f"Entry flow '{edge_id}' from '{source_id}' could be targeted by credential stuffing or forged tokens.",
                "severity": "HIGH" if is_boundary else "MEDIUM",
                "mitigation": "Enforce OIDC/OAuth2 session tokens, MFA for staff roles, and short-lived JWT validation.",
                "requirement_id": req_id,
            })
            count += 1

        # 3. Tampering on boundary-crossing data flows
        if is_boundary:
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Tampering",
                "title": f"In-Transit Payload Modification on {edge_id}",
                "target_type": "edge",
                "target_id": edge_id,
                "description": f"Requests or records traversing '{edge_id}' across trust zones could be replayed or modified.",
                "severity": "MEDIUM",
                "mitigation": "Enforce cryptographic payload integrity checks, idempotency keys, and mTLS.",
                "requirement_id": req_id,
            })
            count += 1

    # Node-level STRIDE checks
    for node_id, node in nodes.items():
        name = str(node.get("name", node_id))
        ntype = str(node.get("type", "")).lower()
        tzone = str(node.get("trust_zone", "")).lower()
        req_ids = node.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"

        # Data Store Tampering & Information Disclosure
        if any(k in ntype for k in ("database", "data store", "store", "sql", "storage", "cache", "vault", "secret")):
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Tampering",
                "title": f"Unauthorized Data or Secret Modification in {name}",
                "target_type": "node",
                "target_id": node_id,
                "description": f"Persistent store '{name}' requires encryption at rest and strict write access controls.",
                "severity": "HIGH",
                "mitigation": "Enforce encryption at rest (CMK/TDE), least-privilege workload identity, and immutable backups.",
                "requirement_id": req_id,
            })
            count += 1

        # Denial of Service on Edge, Ingress, Public, or Core Services
        if any(k in ntype or k in tzone for k in ("ingress", "gateway", "public", "edge", "waf", "client", "service", "api")):
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Denial of Service",
                "title": f"Resource Exhaustion / Availability Degradation at {name}",
                "target_type": "node",
                "target_id": node_id,
                "description": f"Component '{name}' could experience request flooding or concurrency contention.",
                "severity": "HIGH" if ("edge" in tzone or "public" in tzone or "gateway" in ntype) else "MEDIUM",
                "mitigation": "Enforce WAF rate limiting, horizontal autoscaling, and health-aware failover.",
                "requirement_id": req_id,
            })
            count += 1

        # Elevation of Privilege on Services, Gateways, Identity, and Management Components
        if any(k in ntype or k in tzone for k in ("service", "identity", "auth", "admin", "management", "gateway", "security")):
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Elevation of Privilege",
                "title": f"Authorization Bypass / Privilege Escalation in {name}",
                "target_type": "node",
                "target_id": node_id,
                "description": f"Insufficient RBAC or property/tenant boundary checks in '{name}' could allow unauthorized actions.",
                "severity": "HIGH",
                "mitigation": "Enforce deny-by-default RBAC, property-level authorization checks, and least-privilege workload identities.",
                "requirement_id": req_id,
            })
            count += 1

        # Repudiation on Audit, Monitoring, Payment, Reservation, or Order nodes
        if any(k in ntype or k in name.lower() for k in ("audit", "monitor", "log", "payment", "reservation", "inventory", "order")):
            threats.append({
                "threat_id": f"THR-{count:03d}",
                "category": "Repudiation",
                "title": f"Audit Trail Gaps or Repudiation Risk in {name}",
                "target_type": "node",
                "target_id": node_id,
                "description": f"Security-critical operations in '{name}' must be linked to an actor/workload identity with tamper-proof timestamps.",
                "severity": "MEDIUM",
                "mitigation": "Write correlation-linked, append-only audit logs with >=365-day retention.",
                "requirement_id": req_id,
            })
            count += 1

    high = sum(1 for t in threats if t["severity"] == "HIGH")
    med = sum(1 for t in threats if t["severity"] == "MEDIUM")
    low = sum(1 for t in threats if t["severity"] == "LOW")

    return {
        "summary": {
            "total_threats": len(threats),
            "high_severity": high,
            "medium_severity": med,
            "low_severity": low,
        },
        "threats": threats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_used": "Heuristic Rules Engine",
    }


def main():
    print("STRIDE Threat Modeling Engine")
    print("----------------------------")
    if not ARCHITECTURE_FILE.exists():
        print(f"Error: {ARCHITECTURE_FILE} does not exist. Run architecture synthesis first.")
        raise SystemExit(1)

    architecture = load_json(ARCHITECTURE_FILE, "architecture")
    requirements = load_json(REQUIREMENTS_FILE, "requirements") if REQUIREMENTS_FILE.exists() else {}

    threat_report = analyze_threats(architecture, requirements)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(threat_report, f, indent=4, ensure_ascii=False)

    print(f"\nThreat Modeling complete! Output saved to: {OUTPUT_FILE.relative_to(BASE_DIR)}")
    summary = threat_report.get("summary", {})
    print(
        f"Summary: {summary.get('total_threats', 0)} threats found "
        f"({summary.get('high_severity', 0)} High, {summary.get('medium_severity', 0)} Medium, {summary.get('low_severity', 0)} Low)."
    )


if __name__ == "__main__":
    main()
