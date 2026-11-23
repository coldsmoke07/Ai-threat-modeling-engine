"""Build presentation-only metadata from the validated architecture model.

This file never changes the architecture graph.  It classifies existing nodes
and edges into visual groups so renderers can create reviewer-friendly views
without treating decorative containers as real architecture components.
"""

import copy
import json
import re
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
OUTPUT_FILE = BASE_DIR / "outputs" / "presentation" / "presentation_v1.json"


CATEGORY_STYLES = {
    "client": {"fill": "#E8F3FF", "border": "#0078D4", "accent": "#0078D4"},
    "network": {"fill": "#EAF7FF", "border": "#0099BC", "accent": "#0099BC"},
    "ingress": {"fill": "#F0F5FF", "border": "#4F6BED", "accent": "#4F6BED"},
    "compute": {"fill": "#EEF7EE", "border": "#107C10", "accent": "#107C10"},
    "database": {"fill": "#FFF4E5", "border": "#D83B01", "accent": "#D83B01"},
    "monitoring": {"fill": "#F3EEFF", "border": "#735BC1", "accent": "#735BC1"},
    "search": {"fill": "#FFF8D9", "border": "#B8860B", "accent": "#B8860B"},
    "identity": {"fill": "#FCEEF4", "border": "#C239B3", "accent": "#C239B3"},
    "security": {"fill": "#FFF0F0", "border": "#D13438", "accent": "#D13438"},
    "registry": {"fill": "#EAF4FF", "border": "#0063B1", "accent": "#0063B1"},
    "cicd": {"fill": "#F0F6FF", "border": "#005A9E", "accent": "#005A9E"},
    "deployment": {"fill": "#F5F0FF", "border": "#8764B8", "accent": "#8764B8"},
    "orchestration": {"fill": "#E8F5FF", "border": "#0078D4", "accent": "#0078D4"},
    "other": {"fill": "#F3F4F6", "border": "#687078", "accent": "#687078"},
}


GROUP_SPECS = [
    {
        "id": "public_entry",
        "label": "Public Entry",
        "parent_id": None,
        "group_type": "trust_zone",
        "region": "public",
        "order": 10,
        "fill_color": "#F7FBFF",
        "border_color": "#D13438",
        "line_style": "dashed",
    },
    {
        "id": "azure_environment",
        "label": "Private Environment - Internal Trust Zone",
        "parent_id": None,
        "group_type": "trust_zone",
        "region": "internal",
        "order": 20,
        "fill_color": "#F8FBFE",
        "border_color": "#5B9BD5",
        "line_style": "dashed",
    },
    {
        "id": "aks_platform",
        "label": "Application Platform",
        "parent_id": "azure_environment",
        "group_type": "platform",
        "region": "aks",
        "order": 10,
        "fill_color": "#EDF6FF",
        "border_color": "#0078D4",
        "line_style": "solid",
    },
    {
        "id": "frontend_ingress",
        "label": "Frontend / Ingress",
        "parent_id": "aks_platform",
        "group_type": "namespace",
        "region": "aks_ingress",
        "order": 10,
        "fill_color": "#F8FBFF",
        "border_color": "#8CBFE6",
        "line_style": "solid",
    },
    {
        "id": "backend_services",
        "label": "Backend Services",
        "parent_id": "aks_platform",
        "group_type": "namespace",
        "region": "aks_backend",
        "order": 20,
        "fill_color": "#F6FBF6",
        "border_color": "#82C782",
        "line_style": "solid",
    },
    {
        "id": "kubernetes_platform",
        "label": "Kubernetes Platform / Features",
        "parent_id": "aks_platform",
        "group_type": "platform_features",
        "region": "aks_platform",
        "order": 30,
        "fill_color": "#F5FAFF",
        "border_color": "#78A9D1",
        "line_style": "solid",
    },
    {
        "id": "utility_services",
        "label": "Utility Services",
        "parent_id": "aks_platform",
        "group_type": "namespace",
        "region": "aks_utility",
        "order": 40,
        "fill_color": "#FBFBF5",
        "border_color": "#C8B84A",
        "line_style": "solid",
    },
    {
        "id": "data_stores",
        "label": "Data Stores",
        "parent_id": "azure_environment",
        "group_type": "service_group",
        "region": "data",
        "order": 20,
        "fill_color": "#FFF9F2",
        "border_color": "#E59A62",
        "line_style": "solid",
    },
    {
        "id": "monitoring",
        "label": "Monitoring & Observability",
        "parent_id": "azure_environment",
        "group_type": "service_group",
        "region": "monitoring",
        "order": 30,
        "fill_color": "#F8F5FF",
        "border_color": "#9B85D1",
        "line_style": "solid",
    },
    {
        "id": "utility_search",
        "label": "Utility / Search",
        "parent_id": "azure_environment",
        "group_type": "service_group",
        "region": "utility",
        "order": 40,
        "fill_color": "#FFFDF2",
        "border_color": "#C9A227",
        "line_style": "solid",
    },
    {
        "id": "identity_security",
        "label": "Identity & Security",
        "parent_id": "azure_environment",
        "group_type": "service_group",
        "region": "identity",
        "order": 50,
        "fill_color": "#FFF7FA",
        "border_color": "#CE79B3",
        "line_style": "solid",
    },
    {
        "id": "cicd",
        "label": "CI/CD & Deployment",
        "parent_id": "azure_environment",
        "group_type": "delivery_lane",
        "region": "cicd",
        "order": 60,
        "fill_color": "#F5F8FC",
        "border_color": "#6B8EAD",
        "line_style": "solid",
    },
    {
        "id": "other_services",
        "label": "Approved External / Third-Party Services",
        "parent_id": "azure_environment",
        "group_type": "service_group",
        "region": "other",
        "order": 70,
        "fill_color": "#F7F7F7",
        "border_color": "#A0A0A0",
        "line_style": "solid",
    },
]


REGION_POSITIONS = {
    "public": {"center_x": 175, "center_y": 650, "columns": 1, "gap_x": 220, "gap_y": 140},
    "aks_ingress": {"center_x": 490, "center_y": 650, "columns": 1, "gap_x": 220, "gap_y": 130},
    "aks_backend": {"center_x": 885, "center_y": 690, "columns": 2, "gap_x": 235, "gap_y": 125},
    "aks_platform": {"center_x": 885, "center_y": 410, "columns": 2, "gap_x": 235, "gap_y": 120},
    "aks_utility": {"center_x": 885, "center_y": 240, "columns": 2, "gap_x": 235, "gap_y": 115},
    "other": {"center_x": 1490, "center_y": 960, "columns": 2, "gap_x": 235, "gap_y": 115},
    "data": {"center_x": 1490, "center_y": 720, "columns": 2, "gap_x": 235, "gap_y": 115},
    "monitoring": {"center_x": 1490, "center_y": 470, "columns": 2, "gap_x": 235, "gap_y": 115},
    "utility": {"center_x": 1490, "center_y": 340, "columns": 2, "gap_x": 235, "gap_y": 115},
    "identity": {"center_x": 1490, "center_y": 200, "columns": 2, "gap_x": 235, "gap_y": 115},
    "cicd": {"center_x": 760, "center_y": 960, "columns": 3, "gap_x": 235, "gap_y": 110},
}


def load_architecture():
    if not ARCHITECTURE_FILE.exists():
        raise RuntimeError(f"architecture JSON not found: {ARCHITECTURE_FILE}")

    try:
        with ARCHITECTURE_FILE.open("r", encoding="utf-8") as file:
            architecture = json.load(file)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"malformed architecture JSON: {error}") from error

    if not architecture.get("nodes"):
        raise RuntimeError("architecture contains no nodes")

    return architecture


def normalize(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def infer_category(node):
    node_type = normalize(node.get("type"))
    node_name = normalize(node.get("name"))
    combined = f"{node_type} {node_name}"

    if "external service" in node_type or "third party" in normalize(node.get("trust_zone")):
        if "identity" in combined:
            return "identity"
        return "other"

    rules = [
        ("cicd", ("ci cd", "pipeline", "build automation")),
        ("registry", ("registry", "container image")),
        ("deployment", ("deployment", "helm", "release manager")),
        ("ingress", ("ingress", "api gateway", "edge waf", "load balancer")),
        ("orchestration", ("kubernetes", "container platform", "aks")),
        ("security", ("secret management", "key vault", "secrets", "vault")),
        ("identity", ("identity", "active directory", "authentication provider", "entra")),
        ("monitoring", ("monitoring", "observability", "metrics", "monitor", "audit")),
        ("database", ("database", "data store", "sql", "cosmos db", "storage", "cache", "redis")),
        ("search", ("search", "elasticsearch", "indexing")),
        ("network", ("network", "load balancer", "firewall", "cdn")),
        ("client", ("client", "browser", "mobile app", "user interface", "portal")),
        ("compute", ("service", "compute", "backend", "worker", "function", "orchestration")),
    ]

    for category, terms in rules:
        if any(term in combined for term in terms):
            return category

    return "other"


def infer_group(category, node):
    trust_zone = normalize(node.get("trust_zone"))

    if category in {"client", "network"} and (
        "public" in trust_zone or category == "client"
    ):
        return "public_entry"

    return {
        "ingress": "frontend_ingress",
        "compute": "backend_services",
        "orchestration": "kubernetes_platform",
        "database": "data_stores",
        "monitoring": "monitoring",
        "search": "utility_search",
        "identity": "identity_security",
        "security": "identity_security",
        "registry": "cicd",
        "cicd": "cicd",
        "deployment": "cicd",
    }.get(category, "other_services")


def infer_node_order(category, node_name):
    category_order = {
        "client": 10,
        "network": 20,
        "ingress": 10,
        "compute": 20,
        "orchestration": 30,
        "database": 10,
        "monitoring": 10,
        "search": 10,
        "identity": 10,
        "security": 20,
        "cicd": 10,
        "registry": 20,
        "deployment": 30,
        "other": 90,
    }
    return category_order.get(category, 90), normalize(node_name)


def build_group_specs(architecture, categories_by_node):
    """Adapt generic visual containers to names already present in the model."""
    group_specs = copy.deepcopy(GROUP_SPECS)
    architecture_name = normalize(architecture.get("architecture_name"))
    nodes = architecture.get("nodes", [])
    uses_azure = "azure" in architecture_name or any(
        "azure" in normalize(node.get("name")) for node in nodes
    )
    orchestration_nodes = [
        node
        for node in nodes
        if categories_by_node.get(node.get("id")) == "orchestration"
    ]

    if orchestration_nodes:
        orchestrator_name = str(
            orchestration_nodes[0].get("name")
            or orchestration_nodes[0].get("type")
            or "Application"
        )
        if uses_azure and "kubernetes" in normalize(orchestrator_name):
            platform_label = "Azure Kubernetes Service (AKS)"
        elif "platform" in normalize(orchestrator_name):
            platform_label = orchestrator_name
        else:
            platform_label = f"{orchestrator_name} Platform"
    else:
        platform_label = "Application Platform"

    for group in group_specs:
        if group["id"] == "azure_environment" and uses_azure:
            group["label"] = "Azure Private Environment - Internal Trust Zone"
        elif group["id"] == "aks_platform":
            group["label"] = platform_label

    return group_specs


def infer_flow_type(edge, categories_by_node):
    source_category = categories_by_node.get(edge.get("source"), "other")
    target_category = categories_by_node.get(edge.get("target"), "other")
    categories = {source_category, target_category}
    flow_text = normalize(f"{edge.get('protocol', '')} {edge.get('data', '')}")

    deployment_categories = {"cicd", "registry", "deployment", "orchestration"}
    if categories.intersection(deployment_categories) and (
        categories.intersection({"cicd", "registry", "deployment"})
        or any(term in flow_text for term in ("container image", "helm", "deploy"))
    ):
        return "deployment"

    if categories.intersection({"monitoring", "identity", "security"}) or any(
        term in flow_text
        for term in ("metrics", "operational", "authentication", "token", "secret", "audit")
    ):
        return "management"

    return "data_request"


def display_protocol(protocol):
    normalized = normalize(protocol)
    if normalized in {"http https", "https http"}:
        return "HTTPS"
    return str(protocol or "").strip()


def build_edge_label(edge):
    protocol = display_protocol(edge.get("protocol"))
    data = str(edge.get("data") or "").strip()
    protocol_key = normalize(protocol)
    data_key = normalize(data)

    if "oauth" in protocol_key or "oidc" in protocol_key:
        return protocol
    if "helm chart" in data_key:
        return "Helm charts"
    if "container image" in data_key:
        return "Container images"
    if data_key == "metrics":
        return "Metrics"
    if "operational" in data_key:
        return "Operational data"
    if "secret" in data_key:
        return "Secrets"
    if protocol_key == "https" and "api request" in data_key:
        return "HTTPS / API requests"
    if protocol_key in {"https", "sql", "rest"}:
        return protocol

    return protocol or data


def build_presentation(architecture):
    node_ids = set()
    node_presentations = []
    categories_by_node = {}

    for node in architecture.get("nodes", []):
        node_id = node.get("id")
        if not node_id:
            raise RuntimeError("an architecture node is missing an ID")
        if node_id in node_ids:
            raise RuntimeError(f"duplicate architecture node ID: {node_id}")

        node_ids.add(node_id)
        category = infer_category(node)
        categories_by_node[node_id] = category
        order, _ = infer_node_order(category, node.get("name"))

        node_presentations.append(
            {
                "node_id": node_id,
                "label": node.get("name") or node_id,
                "category": category,
                "group_id": infer_group(category, node),
                "layout_order": order,
                "icon_key": category,
                "subtitle": str(node.get("type") or category).upper(),
            }
        )

    edge_ids = set()
    edge_presentations = []

    for edge in architecture.get("edges", []):
        edge_id = edge.get("id")
        source = edge.get("source")
        target = edge.get("target")

        if not edge_id:
            raise RuntimeError("an architecture edge is missing an ID")
        if source not in node_ids:
            readable = " ".join(re.findall(r'[A-Z][a-z]*|[a-z]+|\d+', str(source))).title() or str(source)
            node_ids.add(str(source))
            categories_by_node[str(source)] = "other"
            node_presentations.append({
                "node_id": str(source),
                "label": readable,
                "category": "other",
                "group_id": "other_services",
                "layout_order": 90,
                "icon_key": "other",
                "subtitle": "EXTERNAL SERVICE",
            })

        if target not in node_ids:
            readable = " ".join(re.findall(r'[A-Z][a-z]*|[a-z]+|\d+', str(target))).title() or str(target)
            node_ids.add(str(target))
            categories_by_node[str(target)] = "other"
            node_presentations.append({
                "node_id": str(target),
                "label": readable,
                "category": "other",
                "group_id": "other_services",
                "layout_order": 90,
                "icon_key": "other",
                "subtitle": "EXTERNAL SERVICE",
            })

        edge_ids.add(edge_id)
        edge_presentations.append(
            {
                "edge_id": edge_id,
                "flow_type": infer_flow_type(edge, categories_by_node),
                "visible_label": build_edge_label(edge),
                "show_label": True,
            }
        )

    node_presentations.sort(
        key=lambda item: (
            item["group_id"],
            item["layout_order"],
            normalize(item["label"]),
        )
    )

    return {
        "schema_version": "1.0",
        "architecture_name": architecture.get("architecture_name", "Software Architecture"),
        "source_architecture": "outputs/architecture_v1.json",
        "architecture_status": architecture.get("status"),
        "presentation_note": (
            "Groups, lanes, icons and positions are visualization-only metadata. "
            "All components and visible flows originate from the validated architecture."
        ),
        "layout": {
            "canvas": {"width": 1820, "height": 1120},
            "direction": "controlled_landscape",
            "coordinate_units": "points",
            "region_positions": REGION_POSITIONS,
        },
        "visual_groups": build_group_specs(architecture, categories_by_node),
        "node_presentations": node_presentations,
        "edge_presentations": edge_presentations,
        "theme": {
            "font_family": "Arial",
            "background": "#F5F8FC",
            "text": "#243447",
            "muted_text": "#5B6673",
            "category_styles": CATEGORY_STYLES,
            "flow_styles": {
                "data_request": {
                    "label": "Data / request flow",
                    "color": "#0078D4",
                    "line_style": "solid",
                    "pen_width": 2.0,
                },
                "management": {
                    "label": "Management / control flow",
                    "color": "#7A6F9B",
                    "line_style": "dashed",
                    "pen_width": 1.8,
                },
                "deployment": {
                    "label": "Deployment flow",
                    "color": "#C55A11",
                    "line_style": "dashed",
                    "pen_width": 2.2,
                },
            },
        },
    }


def save_presentation(presentation):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(presentation, file, indent=4, ensure_ascii=False)


def main():
    print()
    print("Presentation Model Generation")
    print("-----------------------------")
    print()

    try:
        print("Loading architecture...")
        architecture = load_architecture()
        print("Validating graph...")
        presentation = build_presentation(architecture)
        print("Building visual groups...")
        save_presentation(presentation)

        print()
        print("Presentation model generated successfully!")
        print()
        print("Architecture:")
        print(presentation["architecture_name"])
        print()
        print("Nodes:", len(presentation["node_presentations"]))
        print("Flows:", len(presentation["edge_presentations"]))
        print()
        print("Saved to:")
        print(OUTPUT_FILE.relative_to(BASE_DIR))
    except (OSError, RuntimeError) as error:
        print()
        print("ERROR:")
        print(error)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
