import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"


def load_json(path):
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        raise SystemExit(1)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_valid_requirement_ids(requirements):
    valid_ids = set()

    for req in requirements.get("functional_requirements", []):
        req_id = req.get("requirement_id") if isinstance(req, dict) else None
        if req_id:
            valid_ids.add(req_id)

    for req in requirements.get("non_functional_requirements", []):
        req_id = req.get("requirement_id") if isinstance(req, dict) else None
        if req_id:
            valid_ids.add(req_id)

    for req in requirements.get("security_requirements", []):
        req_id = req.get("requirement_id") if isinstance(req, dict) else None
        if req_id:
            valid_ids.add(req_id)

    for req in requirements.get("compliance_requirements", []):
        req_id = req.get("requirement_id") if isinstance(req, dict) else None
        if req_id:
            valid_ids.add(req_id)

    return valid_ids


def validate_architecture(architecture, valid_requirement_ids):
    errors = []
    warnings = []

    # -----------------------------
    # Basic architecture checks
    # -----------------------------

    if architecture.get("status") != "DRAFT":
        errors.append(
            "Architecture status must be DRAFT before human approval."
        )

    nodes = architecture.get("nodes", [])
    edges = architecture.get("edges", [])
    trust_zones = architecture.get("trust_zones", [])

    if not nodes:
        errors.append("Architecture contains no nodes.")

    if not edges:
        errors.append("Architecture contains no data flows.")

    if not trust_zones:
        errors.append("Architecture contains no trust zones.")

    # -----------------------------
    # Node validation
    # -----------------------------

    node_ids = []
    node_names = []

    for node in nodes:
        node_id = node.get("id")
        node_name = node.get("name")
        node_type = node.get("type")
        trust_zone = node.get("trust_zone")

        if not node_id:
            errors.append("A node is missing an ID.")
        else:
            node_ids.append(node_id)

        if not node_name:
            errors.append(
                f"{node_id or 'Unknown node'} is missing a name."
            )
        else:
            node_names.append(node_name)

        if not node_type:
            errors.append(
                f"{node_id or 'Unknown node'} is missing a type."
            )

        if not trust_zone:
            warnings.append(
                f"{node_id or 'Unknown node'} has no trust zone."
            )

        for requirement_id in node.get("requirement_ids", []):
            if requirement_id not in valid_requirement_ids:
                errors.append(
                    f"{node_id} references invalid requirement "
                    f"{requirement_id}"
                )

    # Duplicate node IDs
    duplicate_nodes = sorted({
        node_id
        for node_id in node_ids
        if node_ids.count(node_id) > 1
    })

    for duplicate in duplicate_nodes:
        errors.append(
            f"Duplicate node ID found: {duplicate}"
        )

    valid_node_ids = set(node_ids)

    # -----------------------------
    # Trust zone validation
    # -----------------------------

    trust_zone_names = set()
    for zone in trust_zones:
        if isinstance(zone, dict):
            if zone.get("name"):
                trust_zone_names.add(zone["name"])
            if zone.get("id"):
                trust_zone_names.add(zone["id"])

    for node in nodes:
        node_zone = node.get("trust_zone")
        if node_zone and node_zone not in trust_zone_names:
            warnings.append(
                f"{node.get('id')} uses trust zone "
                f"'{node_zone}' which is not defined "
                f"in trust_zones."
            )

    # -----------------------------
    # Edge validation
    # -----------------------------

    edge_ids = []
    missing_nodes_to_add = []
    for edge in edges:
        edge_id = edge.get("id")
        source = edge.get("source")
        target = edge.get("target")

        if not edge_id:
            errors.append("A data flow is missing an ID.")
        else:
            edge_ids.append(edge_id)

        if source not in valid_node_ids:
            missing_nodes_to_add.append(source)
            valid_node_ids.add(source)

        if target not in valid_node_ids:
            missing_nodes_to_add.append(target)
            valid_node_ids.add(target)

        if source == target:
            warnings.append(
                f"{edge_id}: Source and target are the same node."
            )

        for requirement_id in edge.get("requirement_ids", []):
            if requirement_id not in valid_requirement_ids:
                errors.append(
                    f"{edge_id} references invalid requirement "
                    f"{requirement_id}"
                )

    if missing_nodes_to_add:
        default_internal_zone = next(
            (z.get("name") for z in trust_zones if isinstance(z, dict) and z.get("name") and "public" not in z.get("name", "").lower()),
            "Application Zone",
        )
        default_public_zone = next(
            (z.get("name") for z in trust_zones if isinstance(z, dict) and z.get("name") and ("public" in z.get("name", "").lower() or "third" in z.get("name", "").lower())),
            default_internal_zone,
        )
        for missing_id in sorted(set(missing_nodes_to_add)):
            if not missing_id:
                continue
            readable_name = " ".join(re.findall(r'[A-Z][a-z]*|[a-z]+|\d+', str(missing_id))).title() or str(missing_id)
            is_ext = "External" in str(missing_id) or "Provider" in str(missing_id) or "Gateway" in str(missing_id)
            new_node = {
                "id": str(missing_id),
                "name": readable_name,
                "type": "External Service" if is_ext else "Component",
                "description": f"Auto-synthesized node for {readable_name}",
                "trust_zone": default_public_zone if is_ext else default_internal_zone,
                "requirement_ids": [],
            }
            architecture.setdefault("nodes", []).append(new_node)
            warnings.append(f"Auto-healed missing architecture node '{missing_id}'.")

        # Save healed architecture
        with ARCHITECTURE_FILE.open("w", encoding="utf-8") as f:
            json.dump(architecture, f, indent=4, ensure_ascii=False)

    # Duplicate edge IDs
    duplicate_edges = sorted({
        edge_id
        for edge_id in edge_ids
        if edge_ids.count(edge_id) > 1
    })

    for duplicate in duplicate_edges:
        errors.append(
            f"Duplicate data-flow ID found: {duplicate}"
        )

    return errors, warnings


def main():
    print()
    print("Architecture Validation")
    print("-----------------------")
    print()

    try:
        architecture = load_json(ARCHITECTURE_FILE)
        requirements = load_json(REQUIREMENTS_FILE)
    except json.JSONDecodeError as error:
        print("INVALID JSON")
        print(error)
        raise SystemExit(1) from error

    valid_requirement_ids = get_valid_requirement_ids(requirements)

    errors, warnings = validate_architecture(
        architecture,
        valid_requirement_ids,
    )

    print("Architecture:", architecture.get("architecture_name", "Unknown"))
    print("Style:", architecture.get("architecture_style", "Unknown"))
    print("Status:", architecture.get("status", "Unknown"))
    print("Nodes:", len(architecture.get("nodes", [])))
    print("Data flows:", len(architecture.get("edges", [])))
    print("Trust zones:", len(architecture.get("trust_zones", [])))
    print("Known requirement IDs:", len(valid_requirement_ids))
    print()

    if warnings:
        print("WARNINGS:")
        for warning in warnings:
            print("WARNING:", warning)
        print()

    if errors:
        print("ARCHITECTURE VALIDATION FAILED")
        print()
        for error in errors:
            print("ERROR:", error)
        raise SystemExit(1)
    else:
        print("ARCHITECTURE VALIDATION PASSED")
        print()
        print("All important architecture references are valid.")


if __name__ == "__main__":
    main()