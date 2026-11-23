"""Data Flow Diagram (DFD) Generation Engine.

Generates Data Flow Diagrams (processes, data stores, external entities, data flows,
and trust boundaries) derived from the active or approved architecture model.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
REVIEW_DIR = BASE_DIR / "outputs" / "review"
STATE_FILE = REVIEW_DIR / "review_state.json"
APPROVED_ARCH_FILE = REVIEW_DIR / "approved_architecture.json"
APPROVAL_FILE = REVIEW_DIR / "approval.json"
OUTPUT_DFD_FILE = BASE_DIR / "outputs" / "dfd.json"


class DfdGenerationError(RuntimeError):
    """Raised when DFD generation fails."""


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_json(path: Path, description: str) -> dict[str, Any]:
    if not path.exists():
        raise DfdGenerationError(f"Missing {description}: {path.name}")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as err:
        raise DfdGenerationError(f"Could not read {description}: {err}") from err


def resolve_active_architecture() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (approval_meta, architecture) for the approved or active review architecture."""
    if STATE_FILE.exists():
        state = load_json(STATE_FILE, "review state")
        if state.get("approved") and APPROVAL_FILE.exists() and APPROVED_ARCH_FILE.exists():
            approval = load_json(APPROVAL_FILE, "approval record")
            architecture = load_json(APPROVED_ARCH_FILE, "approved architecture")
            actual_hash = canonical_hash(architecture)
            if actual_hash == approval.get("architecture_hash"):
                approval["status"] = "APPROVED_AND_SIGNED"
                return approval, architecture

        # Active review version (or pending preview if staged)
        pending = state.get("pending_preview")
        if isinstance(pending, dict) and (BASE_DIR / pending["files"]["architecture"]).exists():
            arch_path = BASE_DIR / pending["files"]["architecture"]
            ver = pending.get("proposed_version", state.get("current_version", 1))
        else:
            arch_rel = state.get("current_files", {}).get("architecture", "outputs/architecture_v1.json")
            arch_path = BASE_DIR / arch_rel
            ver = state.get("current_version", 1)

        if arch_path.exists():
            architecture = load_json(arch_path, "active review architecture")
            arch_hash = canonical_hash(architecture)
            return {
                "approved": bool(state.get("approved")),
                "status": "APPROVED_AND_SIGNED" if state.get("approved") else "CANDIDATE_ACTIVE",
                "architecture_version": ver,
                "architecture_hash": arch_hash,
                "reviewer": state.get("approved_by") or "Pending Human Sign-Off",
                "approved_at": state.get("approved_at") or datetime.now(timezone.utc).isoformat(),
            }, architecture

    draft_arch_file = BASE_DIR / "outputs" / "architecture_v1.json"
    if not draft_arch_file.exists():
        raise DfdGenerationError("No architecture file found. Please run PDF pipeline first.")

    architecture = load_json(draft_arch_file, "candidate architecture")
    return {
        "approved": False,
        "status": "CANDIDATE_ACTIVE",
        "architecture_version": 1,
        "architecture_hash": canonical_hash(architecture),
        "reviewer": "Pending Human Sign-Off",
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }, architecture


def categorize_node_dfd_type(node_type: str, node_name: str = "") -> str:
    """Map architecture node types to standard DFD element kinds."""
    val = f"{node_type or ''} {node_name or ''}".lower()
    if any(k in val for k in ("client", "actor", "user", "browser", "external", "portal", "provider", "gateway")):
        if "api gateway" not in val and "edge waf" not in val and "ingress" not in val:
            return "external_entity"
    if any(k in val for k in ("database", "data store", "sql", "cosmos", "cache", "redis", "store", "storage", "vault", "registry", "log", "audit", "monitor")):
        return "data_store"
    return "process"


def generate_dfd(architecture: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    nodes = architecture.get("nodes", [])
    edges = architecture.get("edges", [])
    trust_zones = architecture.get("trust_zones", [])

    processes = []
    data_stores = []
    external_entities = []
    node_dfd_map = {}

    for node in nodes:
        node_id = str(node.get("id", ""))
        name = str(node.get("name", node_id))
        ntype = str(node.get("type", "Process"))
        category = categorize_node_dfd_type(ntype, name)
        trust_zone = str(node.get("trust_zone", "Default"))
        req_ids = node.get("requirement_ids", [])

        dfd_label = {
            "external_entity": "External Entity",
            "data_store": "Data Store",
            "process": "Process",
        }[category]

        element = {
            "id": node_id,
            "name": name,
            "node_type": ntype,
            "dfd_kind": category,
            "dfd_label": dfd_label,
            "trust_zone": trust_zone,
            "requirement_ids": req_ids,
            "threat_count": 0,
            "max_severity": "LOW",
        }
        node_dfd_map[node_id] = element

        if category == "external_entity":
            external_entities.append(element)
        elif category == "data_store":
            data_stores.append(element)
        else:
            processes.append(element)

    dfd_flows = []
    for edge in edges:
        edge_id = str(edge.get("id", ""))
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        protocol = str(edge.get("protocol", "HTTPS"))
        data = str(edge.get("data", "Data"))
        auth = str(edge.get("authentication", "None"))
        enc = str(edge.get("encryption", "TLS"))
        crosses_boundary = bool(edge.get("trust_boundary_crossing", False))
        req_ids = edge.get("requirement_ids", [])

        source_el = node_dfd_map.get(source, {})
        target_el = node_dfd_map.get(target, {})

        dfd_flows.append({
            "id": edge_id,
            "source": source,
            "source_name": source_el.get("name", source),
            "source_dfd_type": source_el.get("dfd_label", "Element"),
            "target": target,
            "target_name": target_el.get("name", target),
            "target_dfd_type": target_el.get("dfd_label", "Element"),
            "dfd_kind": "data_flow",
            "dfd_label": "Data Flow",
            "protocol": protocol,
            "data": data,
            "authentication": auth,
            "encryption": enc,
            "crosses_trust_boundary": crosses_boundary,
            "requirement_ids": req_ids,
            "threat_count": 0,
            "max_severity": "LOW",
        })

    return {
        "dfd_schema": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_approval": {
            "status": approval.get("status", "CANDIDATE_ACTIVE"),
            "approved": bool(approval.get("approved")),
            "approved_version": approval.get("architecture_version"),
            "approved_hash": approval.get("architecture_hash"),
            "approved_by": approval.get("reviewer"),
            "approved_at": approval.get("approved_at"),
        },
        "architecture_name": architecture.get("architecture_name", "System DFD"),
        "summary": {
            "total_processes": len(processes),
            "total_data_stores": len(data_stores),
            "total_external_entities": len(external_entities),
            "total_data_flows": len(dfd_flows),
            "total_trust_boundaries": len(trust_zones),
            "total_elements": len(processes) + len(data_stores) + len(external_entities) + len(dfd_flows),
        },
        "processes": processes,
        "data_stores": data_stores,
        "external_entities": external_entities,
        "data_flows": dfd_flows,
        "trust_boundaries": trust_zones,
    }


def main() -> None:
    print()
    print("Data Flow Diagram (DFD) Generator")
    print("---------------------------------")

    try:
        approval, architecture = resolve_active_architecture()
        print(f"Architecture: {architecture.get('architecture_name')}")
        print(f"Gate Status: {approval.get('status')} (v{approval.get('architecture_version')})")
        print(f"Bound to SHA-256 Hash: {str(approval.get('architecture_hash'))[:16]}...")

        dfd = generate_dfd(architecture, approval)

        OUTPUT_DFD_FILE.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT_DFD_FILE.open("w", encoding="utf-8") as f:
            json.dump(dfd, f, indent=4, ensure_ascii=False)

        version = approval.get("architecture_version", 1)
        REVIEW_DIR.mkdir(parents=True, exist_ok=True)
        version_dfd_file = REVIEW_DIR / f"dfd_v{version}.json"
        with version_dfd_file.open("w", encoding="utf-8") as f:
            json.dump(dfd, f, indent=4, ensure_ascii=False)

        print()
        print(f"[SUCCESS] DFD successfully generated for version v{version}!")
        print(
            f"Summary: {dfd['summary']['total_processes']} processes, "
            f"{dfd['summary']['total_data_stores']} data stores, "
            f"{dfd['summary']['total_external_entities']} external entities, "
            f"{dfd['summary']['total_data_flows']} flows."
        )
        print(f"Saved to: {OUTPUT_DFD_FILE.relative_to(BASE_DIR)}")

    except DfdGenerationError as err:
        print()
        print(f"[FAILED] DFD Generation Error: {err}")
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
