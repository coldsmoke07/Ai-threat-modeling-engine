import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "coverage_report.json"


def load_json(path):
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        raise SystemExit(1)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def build_requirement_catalog(requirements):
    catalog = {}

    for req in requirements.get("functional_requirements", []):
        if not isinstance(req, dict):
            continue
        req_id = req.get("requirement_id")
        if req_id:
            catalog[req_id] = {
                "title": req.get("title", ""),
                "description": req.get("description", ""),
                "category": "functional",
                "covered": False,
                "sources": [],
            }

    for req in requirements.get("non_functional_requirements", []):
        if not isinstance(req, dict):
            continue
        req_id = req.get("requirement_id")
        if req_id:
            catalog[req_id] = {
                "title": req.get("title", ""),
                "description": req.get("description", ""),
                "category": "non_functional",
                "covered": False,
                "sources": [],
            }

    for req in requirements.get("security_requirements", []):
        if not isinstance(req, dict):
            continue
        req_id = req.get("requirement_id")
        if req_id:
            cat = "compliance" if str(req_id).upper().startswith("COM-") or str(req.get("category", "")).lower() == "compliance" else "security"
            catalog[req_id] = {
                "title": req.get("title") or ("Compliance Requirement" if cat == "compliance" else "Security Requirement"),
                "description": req.get("description", ""),
                "category": cat,
                "covered": False,
                "sources": [],
            }

    for req in requirements.get("compliance_requirements", []):
        if not isinstance(req, dict):
            continue
        req_id = req.get("requirement_id")
        if req_id and req_id not in catalog:
            catalog[req_id] = {
                "title": req.get("title") or "Compliance Requirement",
                "description": req.get("description", ""),
                "category": "compliance",
                "covered": False,
                "sources": [],
            }

    return catalog


def apply_node_coverage(catalog, architecture):
    for node in architecture.get("nodes", []):
        node_id = node.get("id", "")
        node_name = node.get("name", "")
        node_type = node.get("type", "")

        for req_id in node.get("requirement_ids", []):
            if req_id in catalog:
                catalog[req_id]["covered"] = True
                catalog[req_id]["sources"].append({
                    "source_type": "node",
                    "id": node_id,
                    "name": node_name,
                    "node_type": node_type,
                })


def apply_edge_coverage(catalog, architecture):
    for edge in architecture.get("edges", []):
        edge_id = edge.get("id", "")
        source = edge.get("source", "")
        target = edge.get("target", "")
        protocol = edge.get("protocol", "")
        data = edge.get("data", "")

        for req_id in edge.get("requirement_ids", []):
            if req_id in catalog:
                catalog[req_id]["covered"] = True
                catalog[req_id]["sources"].append({
                    "source_type": "edge",
                    "id": edge_id,
                    "name": f"{source} -> {target}",
                    "protocol": protocol,
                    "data": data,
                })


def generate_report(requirements, architecture):
    catalog = build_requirement_catalog(requirements)

    apply_node_coverage(catalog, architecture)
    apply_edge_coverage(catalog, architecture)

    total = len(catalog)
    covered = sum(1 for req in catalog.values() if req["covered"])
    missing = total - covered
    percentage = round((covered / total) * 100, 2) if total > 0 else 0.0

    covered_requirements = {}
    missing_requirements = {}
    for req_id, info in catalog.items():
        if info["covered"]:
            covered_requirements[req_id] = info
        else:
            missing_requirements[req_id] = info

    valid_req_ids = set(catalog.keys())
    unknown_req_refs = []
    unmapped_nodes = []
    unmapped_edges = []

    for node in architecture.get("nodes", []):
        node_id = str(node.get("id", ""))
        req_ids = node.get("requirement_ids", [])
        if not req_ids:
            unmapped_nodes.append(node_id)
        for req_id in req_ids:
            if req_id not in valid_req_ids:
                unknown_req_refs.append({"element_type": "node", "id": node_id, "requirement_id": req_id})

    for edge in architecture.get("edges", []):
        edge_id = str(edge.get("id", ""))
        req_ids = edge.get("requirement_ids", [])
        if not req_ids:
            unmapped_edges.append(edge_id)
        for req_id in req_ids:
            if req_id not in valid_req_ids:
                unknown_req_refs.append({"element_type": "edge", "id": edge_id, "requirement_id": req_id})

    return {
        "project_name": requirements.get("project_name", "Unknown"),
        "architecture_name": architecture.get("architecture_name", "Unknown"),
        "summary": {
            "total_requirements": total,
            "covered_requirements": covered,
            "missing_requirements": missing,
            "coverage_percentage": percentage,
            "unmapped_nodes_count": len(unmapped_nodes),
            "unmapped_edges_count": len(unmapped_edges),
            "unknown_requirement_references_count": len(unknown_req_refs),
        },
        "covered_requirements": covered_requirements,
        "missing_requirements": missing_requirements,
        "unmapped_nodes": unmapped_nodes,
        "unmapped_edges": unmapped_edges,
        "unknown_requirement_references": unknown_req_refs,
    }


def save_report(report):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def print_report(report):
    summary = report["summary"]

    print()
    print("Requirement Coverage Report")
    print("---------------------------")
    print()
    print("Project:", report["project_name"])
    print("Architecture:", report["architecture_name"])
    print()
    print("Total requirements:", summary["total_requirements"])
    print("Covered requirements:", summary["covered_requirements"])
    print("Missing requirements:", summary["missing_requirements"])
    print("Coverage percentage:", f'{summary["coverage_percentage"]}%')
    print()

    if report["missing_requirements"]:
        print("Missing Requirement IDs:")
        for req_id in report["missing_requirements"]:
            print("-", req_id)
    else:
        print("All requirements are covered.")

    print()
    print("Detailed report saved to:")
    print(OUTPUT_FILE.relative_to(BASE_DIR))


def main():
    print("Starting coverage analysis...")
    requirements = load_json(REQUIREMENTS_FILE)
    architecture = load_json(ARCHITECTURE_FILE)
    report = generate_report(requirements, architecture)
    save_report(report)
    print_report(report)


if __name__ == "__main__":
    main()