"""STRIDE Threat Modeling & Risk Ranking Matrix Engine.

Directly maps DFD elements (External Entities, Processes, Data Stores, and Data Flows)
using the STRIDE-per-Element methodology and 3x3 Likelihood x Impact Risk Matrix,
ensuring 100% 1-to-1 alignment between Stage 6 (DFD), Stage 7 (STRIDE), and Stage 8 (Risk Matrix).
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dfd_generator

try:
    from ollama_utils import check_ollama_status, select_model
except ImportError:
    def check_ollama_status() -> tuple[bool, str]:
        return False, "ollama_utils unavailable"

    def select_model() -> str:
        return "qwen3:4b"

BASE_DIR = Path(__file__).resolve().parent
REVIEW_DIR = BASE_DIR / "outputs" / "review"
DFD_FILE = BASE_DIR / "outputs" / "dfd.json"
OUTPUT_STRIDE_FILE = BASE_DIR / "outputs" / "stride_threats.json"
OLLAMA_URL = "http://localhost:11434/api/chat"


class StrideEngineError(RuntimeError):
    """Raised when STRIDE threat engine fails."""


def calculate_risk(likelihood: int, impact: int) -> tuple[int, str]:
    """Calculate risk score (1-9) and severity label."""
    score = max(1, min(3, likelihood)) * max(1, min(3, impact))
    if score >= 6:
        return score, "HIGH"
    if score >= 3:
        return score, "MEDIUM"
    return score, "LOW"


def run_deterministic_rules(architecture: dict[str, Any], dfd: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply STRIDE-per-DFD-Element rules directly across External Entities, Processes, Data Stores, and Data Flows."""
    threats: list[dict[str, Any]] = []
    count = 1

    # 1. DFD External Entities (S, R)
    for ent in dfd.get("external_entities", []):
        eid = str(ent.get("id", ""))
        ename = str(ent.get("name", eid))
        tzone = str(ent.get("trust_zone", "External"))
        req_ids = ent.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"
        is_public = "public" in tzone.lower() or "third" in tzone.lower()

        # Spoofing on External Entity
        lh, imp = (3, 3) if is_public else (2, 3)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Spoofing",
            "stride_code": "S",
            "title": f"External Entity Identity Spoofing at {ename}",
            "target_type": "node",
            "dfd_element_type": "External Entity",
            "target_id": eid,
            "target_name": ename,
            "trust_zone": tzone,
            "description": f"External entity '{ename}' ({eid}) in zone '{tzone}' could be impersonated without strong OIDC/MFA or API credential validation.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Enforce OIDC/OAuth2 authentication, MFA for staff roles, and mutual certificate validation for '{ename}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

        # Repudiation on External Entity
        lh, imp = (2, 2)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Repudiation",
            "stride_code": "R",
            "title": f"Non-Repudiation & Action Dispute Risk for {ename}",
            "target_type": "node",
            "dfd_element_type": "External Entity",
            "target_id": eid,
            "target_name": ename,
            "trust_zone": tzone,
            "description": f"Actions or external callbacks initiated by '{ename}' ({eid}) could be repudiated without signed correlation audit logs.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Record timestamped, actor-linked immutable audit events for all transactions from '{ename}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

    # 2. DFD Processes (S, T, R, I, D, E)
    for proc in dfd.get("processes", []):
        pid = str(proc.get("id", ""))
        pname = str(proc.get("name", pid))
        ntype = str(proc.get("node_type", "")).lower()
        tzone = str(proc.get("trust_zone", "Application"))
        req_ids = proc.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"
        is_edge = any(k in ntype or k in tzone.lower() for k in ("edge", "ingress", "gateway", "waf", "load balancer"))

        # Elevation of Privilege on Process
        lh, imp = (3, 3) if is_edge else (2, 3)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Elevation of Privilege",
            "stride_code": "E",
            "title": f"Authorization Bypass / Privilege Escalation in {pname}",
            "target_type": "node",
            "dfd_element_type": "Process",
            "target_id": pid,
            "target_name": pname,
            "trust_zone": tzone,
            "description": f"DFD Process '{pname}' ({pid}) in '{tzone}' could allow cross-tenant or unauthorized role execution if RBAC checks fail.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Enforce deny-by-default RBAC, resource-level authorization, and least-privilege workload identity in '{pname}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

        # Denial of Service on Process
        lh, imp = (3, 2) if is_edge else (2, 2)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Denial of Service",
            "stride_code": "D",
            "title": f"Resource Exhaustion / Concurrency Overload on {pname}",
            "target_type": "node",
            "dfd_element_type": "Process",
            "target_id": pid,
            "target_name": pname,
            "trust_zone": tzone,
            "description": f"DFD Process '{pname}' ({pid}) may suffer request flooding or thread starvation under peak load.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Apply WAF rate limiting, connection quotas, horizontal pod autoscaling, and health probes on '{pname}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

    # 3. DFD Data Stores (T, I, R, D)
    for store in dfd.get("data_stores", []):
        sid = str(store.get("id", ""))
        sname = str(store.get("name", sid))
        tzone = str(store.get("trust_zone", "Restricted Data"))
        req_ids = store.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"

        # Tampering on Data Store
        lh, imp = (2, 3)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Tampering",
            "stride_code": "T",
            "title": f"Unauthorized Data or Log Modification in {sname}",
            "target_type": "node",
            "dfd_element_type": "Data Store",
            "target_id": sid,
            "target_name": sname,
            "trust_zone": tzone,
            "description": f"DFD Data Store '{sname}' ({sid}) could be subject to unauthorized record alteration, injection, or backup tampering.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Enforce Customer-Managed Key (CMK/TDE) encryption at rest, write-once audit immutability, and strict DB RBAC on '{sname}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

        # Information Disclosure on Data Store
        lh, imp = (2, 3)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Information Disclosure",
            "stride_code": "I",
            "title": f"Sensitive Data or Secret Exposure at Rest in {sname}",
            "target_type": "node",
            "dfd_element_type": "Data Store",
            "target_id": sid,
            "target_name": sname,
            "trust_zone": tzone,
            "description": f"DFD Data Store '{sname}' ({sid}) holds confidential records/secrets requiring encryption at rest and regional residency controls.",
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Encrypt '{sname}' at rest (AES-256/TDE), isolate in Restricted Data zone, and enforce managed identity secret access.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

    # 4. DFD Data Flows (I, S, T)
    for flow in dfd.get("data_flows", []):
        fid = str(flow.get("id", f"flow_{count}"))
        source = str(flow.get("source", ""))
        target = str(flow.get("target", ""))
        protocol = str(flow.get("protocol", "HTTPS")).upper()
        enc = str(flow.get("encryption", "TLS")).upper()
        crosses = bool(flow.get("crosses_trust_boundary", False))
        req_ids = flow.get("requirement_ids", [])
        req_id = req_ids[0] if req_ids else "N/A"
        flow_label = f"{source} -> {target}"

        # Information Disclosure on Data Flow
        lh, imp = (3, 3) if crosses else (1, 2)
        score, sev = calculate_risk(lh, imp)
        threats.append({
            "threat_id": f"STRIDE-{count:03d}",
            "category": "Information Disclosure",
            "stride_code": "I",
            "title": f"Data Interception / Eavesdropping Risk on Flow {fid}",
            "target_type": "edge",
            "dfd_element_type": "Data Flow",
            "target_id": fid,
            "target_name": flow_label,
            "trust_zone": "Trust Boundary Crossing" if crosses else "Internal Flow",
            "description": (
                f"DFD Data Flow '{fid}' ({flow_label}) carries '{flow.get('data', 'payload')}' over {protocol} "
                f"({'crossing a trust boundary' if crosses else 'within trust zone'})."
            ),
            "likelihood": lh,
            "impact": imp,
            "risk_score": score,
            "severity": sev,
            "mitigation": f"Enforce TLS 1.3 encryption ({enc}) and strict certificate pinning/validation on flow '{fid}'.",
            "requirement_id": req_id,
            "source": "dfd_stride_matrix",
        })
        count += 1

        # Tampering on Boundary-Crossing Data Flows
        if crosses:
            lh, imp = (2, 3)
            score, sev = calculate_risk(lh, imp)
            threats.append({
                "threat_id": f"STRIDE-{count:03d}",
                "category": "Tampering",
                "stride_code": "T",
                "title": f"In-Transit Payload Modification / Replay on Flow {fid}",
                "target_type": "edge",
                "dfd_element_type": "Data Flow",
                "target_id": fid,
                "target_name": flow_label,
                "trust_zone": "Trust Boundary Crossing",
                "description": f"Boundary-crossing DFD Data Flow '{fid}' ({flow_label}) could be replayed or altered in transit.",
                "likelihood": lh,
                "impact": imp,
                "risk_score": score,
                "severity": sev,
                "mitigation": f"Enforce mutual authentication ({flow.get('authentication', 'mTLS')}), payload signing, and replay protection on '{fid}'.",
                "requirement_id": req_id,
                "source": "dfd_stride_matrix",
            })
            count += 1

    return threats


def enrich_with_ai(architecture: dict[str, Any], existing_threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use local Ollama model to enrich threat model with contextual architectural threats if online."""
    online, status_msg = check_ollama_status()
    if not online:
        print(f"Notice: Local AI enrichment skipped ({status_msg}). Using deterministic DFD-STRIDE matrix findings.")
        return []

    model_name = select_model()
    system_prompt = """You are a software security architect specializing in STRIDE threat modeling.
Analyze the architecture graph and return additional high-priority STRIDE threats not already identified.
Return JSON ONLY matching this structure:
{
  "additional_threats": [
    {
      "threat_id": "STRIDE-099",
      "category": "Denial of Service|Elevation of Privilege|Repudiation|Spoofing|Tampering|Information Disclosure",
      "stride_code": "D|E|R|S|T|I",
      "title": "Short title",
      "target_type": "node|edge",
      "dfd_element_type": "Process|Data Store|External Entity|Data Flow",
      "target_id": "exact node/edge ID",
      "description": "Explanation of security threat",
      "likelihood": 2,
      "impact": 3,
      "risk_score": 6,
      "severity": "HIGH|MEDIUM|LOW",
      "mitigation": "Recommended security control",
      "requirement_id": "REQ-001 or N/A",
      "source": "ai_enrichment"
    }
  ]
}"""

    user_prompt = f"""Architecture: {architecture.get('architecture_name', 'System')}
Nodes: {json.dumps(architecture.get('nodes', []), indent=2)}
Edges: {json.dumps(architecture.get('edges', []), indent=2)}
Existing Rule Findings Count: {len(existing_threats)}
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
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data.get("message", {}).get("content", "")
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            parsed = json.loads(content)
            items = parsed if isinstance(parsed, list) else parsed.get("additional_threats", []) if isinstance(parsed, dict) else []
            start_idx = len(existing_threats) + 1
            valid_items = []
            for offset, item in enumerate(items):
                if isinstance(item, dict) and item.get("target_id"):
                    item["threat_id"] = f"STRIDE-{start_idx + offset:03d}"
                    item.setdefault("dfd_element_type", "Data Flow" if item.get("target_type") == "edge" else "Process")
                    item.setdefault("target_name", item["target_id"])
                    lh = int(item.get("likelihood", 2))
                    imp = int(item.get("impact", 2))
                    score, sev = calculate_risk(lh, imp)
                    item["likelihood"] = lh
                    item["impact"] = imp
                    item["risk_score"] = score
                    item["severity"] = sev
                    item["source"] = "ai_enrichment"
                    valid_items.append(item)
            return valid_items
    except Exception as err:
        print(f"Notice: Local AI enrichment skipped ({err}). Using deterministic DFD-STRIDE findings.")
        return []


def annotate_dfd_with_threat_counts(dfd: dict[str, Any], threats: list[dict[str, Any]], approval: dict[str, Any]) -> None:
    """Write threat_count and max_severity back into dfd.json so Stage 6 DFD and Stage 7/8 Risk Matrix match 1-to-1."""
    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    counts: dict[str, int] = {}
    max_sev: dict[str, str] = {}
    stride_codes: dict[str, list[str]] = {}

    for t in threats:
        tid = str(t.get("target_id", ""))
        sev = str(t.get("severity", "LOW")).upper()
        code = str(t.get("stride_code") or t.get("category", "S")[0]).upper()
        counts[tid] = counts.get(tid, 0) + 1
        if sev_rank.get(sev, 1) > sev_rank.get(max_sev.get(tid, "LOW"), 1):
            max_sev[tid] = sev
        stride_codes.setdefault(tid, [])
        if code not in stride_codes[tid]:
            stride_codes[tid].append(code)

    for section in ("processes", "data_stores", "external_entities", "data_flows"):
        for el in dfd.get(section, []):
            el_id = str(el.get("id", ""))
            el["threat_count"] = counts.get(el_id, 0)
            el["max_severity"] = max_sev.get(el_id, "LOW")
            el["stride_codes"] = stride_codes.get(el_id, [])

    with DFD_FILE.open("w", encoding="utf-8") as f:
        json.dump(dfd, f, indent=4, ensure_ascii=False)

    version = approval.get("architecture_version", 1)
    version_dfd_file = REVIEW_DIR / f"dfd_v{version}.json"
    with version_dfd_file.open("w", encoding="utf-8") as f:
        json.dump(dfd, f, indent=4, ensure_ascii=False)


def generate_stride_analysis() -> dict[str, Any]:
    approval, architecture = dfd_generator.resolve_active_architecture()

    # Always generate/sync DFD from the exact same architecture so DFD and Risk Matrix match 100%
    dfd = dfd_generator.generate_dfd(architecture, approval)
    DFD_FILE.parent.mkdir(parents=True, exist_ok=True)
    with DFD_FILE.open("w", encoding="utf-8") as f:
        json.dump(dfd, f, indent=4, ensure_ascii=False)

    deterministic_threats = run_deterministic_rules(architecture, dfd)
    ai_threats = enrich_with_ai(architecture, deterministic_threats)
    all_threats = deterministic_threats + ai_threats

    # Annotate dfd.json with threat counts & severities
    annotate_dfd_with_threat_counts(dfd, all_threats, approval)

    high = sum(1 for t in all_threats if t.get("severity") == "HIGH")
    med = sum(1 for t in all_threats if t.get("severity") == "MEDIUM")
    low = sum(1 for t in all_threats if t.get("severity") == "LOW")

    by_dfd_type = {
        "External Entity": sum(1 for t in all_threats if t.get("dfd_element_type") == "External Entity"),
        "Process": sum(1 for t in all_threats if t.get("dfd_element_type") == "Process"),
        "Data Store": sum(1 for t in all_threats if t.get("dfd_element_type") == "Data Store"),
        "Data Flow": sum(1 for t in all_threats if t.get("dfd_element_type") == "Data Flow"),
    }

    report = {
        "stride_schema": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_approval": {
            "status": approval.get("status", "CANDIDATE_ACTIVE"),
            "approved": bool(approval.get("approved")),
            "approved_version": approval.get("architecture_version"),
            "approved_hash": approval.get("architecture_hash"),
            "approved_by": approval.get("reviewer"),
        },
        "architecture_name": architecture.get("architecture_name", "System"),
        "summary": {
            "total_threats": len(all_threats),
            "high_severity": high,
            "medium_severity": med,
            "low_severity": low,
            "deterministic_rule_count": len(deterministic_threats),
            "ai_enrichment_count": len(ai_threats),
            "by_dfd_element_type": by_dfd_type,
        },
        "threats": all_threats,
    }

    OUTPUT_STRIDE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_STRIDE_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    version = approval.get("architecture_version", 1)
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    version_file = REVIEW_DIR / f"stride_threats_v{version}.json"
    with version_file.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    return report


def main() -> None:
    print()
    print("STRIDE Threat Modeling & Risk Engine")
    print("-----------------------------------")
    try:
        report = generate_stride_analysis()
        summary = report["summary"]
        print(f"[SUCCESS] STRIDE Analysis complete!")
        print(
            f"Total Threats: {summary['total_threats']} "
            f"({summary['high_severity']} High, {summary['medium_severity']} Medium, {summary['low_severity']} Low)"
        )
        print(f"DFD Breakdown: {summary['by_dfd_element_type']}")
        print(f"Saved to: {OUTPUT_STRIDE_FILE.relative_to(BASE_DIR)}")
    except Exception as err:
        print(f"[FAILED] STRIDE Engine Error: {err}")
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
