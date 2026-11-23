"""Milestone 6B-2: editable architecture review and approval workflow.

This single-file local application extends the existing Milestone 6B renderer.
It deliberately keeps ``outputs/architecture_v1.json`` unchanged and treats it
as the security/architecture source of truth.  Reviewer changes are saved as
new candidate versions under ``outputs/review``.

Workflow
--------
1. Generate a review PNG and an editable draw.io XML file.
2. Let a reviewer edit/move managed components in diagrams.net and upload it
   as a temporary preview; uploading alone never creates a real version.
3. Let the reviewer accept or discard the visible preview, or request semantic
   changes in natural language.  The local
   Ollama ``qwen3:4b`` model may return only a constrained graph patch.
4. Show AI changes as another preview, then validate the accepted candidate,
   calculate a structural diff, and verify that the
   patch did not alter unrelated graph elements.
5. Require explicit approval of the exact SHA-256 architecture hash.

Run from the backend folder:

    python architecture_review_workflow.py

Then open http://127.0.0.1:8081 (the browser normally opens automatically).
No cloud AI API or React installation is required.  The exact XML preview
loads the official draw.io viewer script from viewer.diagrams.net; the local
generated PNG remains available as an offline fallback.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import math
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as error:  # pragma: no cover - depends on the user's machine
    raise SystemExit(
        "Pillow is required. Activate .venv and run: "
        "python -m pip install pillow"
    ) from error


BASE_DIR = Path(__file__).resolve().parent
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"
PRESENTATION_FILE = (
    BASE_DIR / "outputs" / "presentation" / "presentation_v1.json"
)
REVIEW_DIR = BASE_DIR / "outputs" / "review"
STATE_FILE = REVIEW_DIR / "review_state.json"

OLLAMA_URL = "http://localhost:11434/api/chat"
try:
    from ollama_utils import select_model as _select_ollama_model
    OLLAMA_MODEL = _select_ollama_model()
except ImportError:
    OLLAMA_MODEL = "qwen3:4b"
MAX_REQUEST_BYTES = 15 * 1024 * 1024
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081

ALLOWED_NODE_CHANGES = {
    "name",
    "type",
    "description",
    "trust_zone",
    "requirement_ids",
}
ALLOWED_EDGE_CHANGES = {
    "source",
    "target",
    "protocol",
    "data",
    "authentication",
    "encryption",
    "trust_boundary_crossing",
    "requirement_ids",
}
ALLOWED_METADATA_CHANGES = {
    "architecture_name",
    "architecture_style",
    "description",
}
ALLOWED_OPERATIONS = {
    "ADD_NODE",
    "REMOVE_NODE",
    "UPDATE_NODE",
    "ADD_EDGE",
    "REMOVE_EDGE",
    "UPDATE_EDGE",
    "UPDATE_METADATA",
}

WRITE_LOCK = threading.RLock()


class WorkflowError(RuntimeError):
    """A clear, user-facing review workflow error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def relative_path(path: Path) -> str:
    try:
        value = path.relative_to(BASE_DIR)
    except ValueError:
        value = path
    return str(value).replace("\\", "/")


def load_json(path: Path, description: str) -> dict[str, Any]:
    if not path.exists():
        raise WorkflowError(f"Missing {description}: {relative_path(path)}")
    try:
        with path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except json.JSONDecodeError as error:
        raise WorkflowError(f"Malformed {description}: {error}") from error
    except OSError as error:
        raise WorkflowError(f"Could not read {description}: {error}") from error
    if not isinstance(value, dict):
        raise WorkflowError(f"{description} must contain one JSON object.")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(value, file, indent=4, ensure_ascii=False)
        file.write("\n")
    os.replace(temporary, path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def safe_identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def requirement_catalog(requirements: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    sections = (
        ("functional_requirements", "functional"),
        ("non_functional_requirements", "non_functional"),
        ("security_requirements", "security"),
    )
    for section, category in sections:
        values = requirements.get(section, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            requirement_id = str(item.get("requirement_id") or "").strip()
            if requirement_id:
                catalog[requirement_id] = {
                    "title": item.get("title", ""),
                    "description": item.get("description", ""),
                    "category": category,
                }
    return catalog


def validate_architecture(
    architecture: dict[str, Any],
    requirements: dict[str, Any],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    catalog = requirement_catalog(requirements)
    valid_requirement_ids = set(catalog)

    if not str(architecture.get("architecture_name") or "").strip():
        errors.append("Architecture name is missing.")
    status = str(architecture.get("status") or "").upper()
    if status not in {"DRAFT", "APPROVED"}:
        errors.append("Architecture status must be DRAFT or APPROVED.")

    nodes = architecture.get("nodes")
    edges = architecture.get("edges")
    trust_zones = architecture.get("trust_zones")
    if not isinstance(nodes, list) or not nodes:
        errors.append("Architecture contains no nodes.")
        nodes = []
    if not isinstance(edges, list) or not edges:
        errors.append("Architecture contains no data flows.")
        edges = []
    if not isinstance(trust_zones, list) or not trust_zones:
        errors.append("Architecture contains no trust zones.")
        trust_zones = []

    trust_zone_names = {
        str(zone.get("name") or zone.get("id") or "").strip()
        for zone in trust_zones
        if isinstance(zone, dict)
    }
    trust_zone_names.discard("")

    node_ids: list[str] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"Node at position {index + 1} is not an object.")
            continue
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            errors.append(f"Node at position {index + 1} is missing an ID.")
            continue
        node_ids.append(node_id)
        if not str(node.get("name") or "").strip():
            errors.append(f"Node '{node_id}' is missing a name.")
        if not str(node.get("type") or "").strip():
            errors.append(f"Node '{node_id}' is missing a type.")
        zone = str(node.get("trust_zone") or "").strip()
        if not zone:
            warnings.append(f"Node '{node_id}' has no trust zone.")
        elif zone not in trust_zone_names:
            matched = any(zone.lower() in z.lower() or z.lower() in zone.lower() for z in trust_zone_names)
            if not matched:
                warnings.append(f"Node '{node_id}' uses unlisted trust zone '{zone}'.")
        references = node.get("requirement_ids", [])
        if not isinstance(references, list):
            errors.append(f"Node '{node_id}' requirement_ids must be a list.")
        else:
            for requirement_id in references:
                if requirement_id not in valid_requirement_ids:
                    warnings.append(
                        f"Node '{node_id}' references unknown requirement "
                        f"'{requirement_id}'."
                    )

    duplicate_nodes = sorted(
        {node_id for node_id in node_ids if node_ids.count(node_id) > 1}
    )
    for node_id in duplicate_nodes:
        errors.append(f"Duplicate node ID: '{node_id}'.")
    valid_node_ids = set(node_ids)

    edge_ids: list[str] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"Data flow at position {index + 1} is not an object.")
            continue
        edge_id = str(edge.get("id") or "").strip()
        if not edge_id:
            errors.append(f"Data flow at position {index + 1} is missing an ID.")
            continue
        edge_ids.append(edge_id)
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if source not in valid_node_ids:
            errors.append(f"{edge_id}: source node '{source}' does not exist.")
        if target not in valid_node_ids:
            errors.append(f"{edge_id}: target node '{target}' does not exist.")
        if source and source == target:
            warnings.append(f"{edge_id}: source and target are the same node.")
        references = edge.get("requirement_ids", [])
        if not isinstance(references, list):
            errors.append(f"Edge '{edge_id}' requirement_ids must be a list.")
        else:
            for requirement_id in references:
                if requirement_id not in valid_requirement_ids:
                    warnings.append(
                        f"Edge '{edge_id}' references unknown requirement "
                        f"'{requirement_id}'."
                    )

    duplicate_edges = sorted(
        {edge_id for edge_id in edge_ids if edge_ids.count(edge_id) > 1}
    )
    for edge_id in duplicate_edges:
        errors.append(f"Duplicate edge ID: '{edge_id}'.")
    return errors, warnings


def calculate_coverage(
    architecture: dict[str, Any],
    requirements: dict[str, Any],
) -> dict[str, Any]:
    catalog = requirement_catalog(requirements)
    mappings: dict[str, list[dict[str, str]]] = {
        requirement_id: [] for requirement_id in catalog
    }
    for node in architecture.get("nodes", []):
        if not isinstance(node, dict):
            continue
        for requirement_id in node.get("requirement_ids", []):
            if requirement_id in mappings:
                mappings[requirement_id].append(
                    {"kind": "node", "id": str(node.get("id", ""))}
                )
    for edge in architecture.get("edges", []):
        if not isinstance(edge, dict):
            continue
        for requirement_id in edge.get("requirement_ids", []):
            if requirement_id in mappings:
                mappings[requirement_id].append(
                    {"kind": "edge", "id": str(edge.get("id", ""))}
                )
    covered = sorted(key for key, values in mappings.items() if values)
    missing = sorted(key for key, values in mappings.items() if not values)
    total = len(catalog)
    percentage = round((len(covered) / total * 100), 2) if total else 0.0
    return {
        "total_requirements": total,
        "covered_requirements": len(covered),
        "missing_requirements": len(missing),
        "coverage_percentage": percentage,
        "covered_ids": covered,
        "missing_ids": missing,
        "mappings": mappings,
    }


def load_optional_presentation(architecture: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(architecture, dict) and architecture.get("nodes"):
        try:
            import presentation_model
            return presentation_model.build_presentation(architecture)
        except Exception:
            pass
    if not PRESENTATION_FILE.exists():
        return {}
    try:
        return load_json(PRESENTATION_FILE, "presentation model")
    except WorkflowError:
        return {}


def category_for_node(node: dict[str, Any]) -> str:
    value = str(node.get("type") or "").lower()
    checks = (
        ("database", "database"),
        ("sql", "database"),
        ("monitor", "monitoring"),
        ("identity", "identity"),
        ("directory", "identity"),
        ("secret", "security"),
        ("vault", "security"),
        ("registry", "registry"),
        ("ci/cd", "cicd"),
        ("pipeline", "cicd"),
        ("deploy", "deployment"),
        ("orchestration", "orchestration"),
        ("kubernetes", "orchestration"),
        ("ingress", "ingress"),
        ("api", "ingress"),
        ("network", "network"),
        ("client", "client"),
        ("search", "search"),
        ("service", "compute"),
    )
    for needle, category in checks:
        if needle in value:
            return category
    return "other"


def presentation_indexes(
    presentation: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    node_metadata = {
        str(item.get("node_id")): item
        for item in presentation.get("node_presentations", [])
        if isinstance(item, dict) and item.get("node_id")
    }
    edge_metadata = {
        str(item.get("edge_id")): item
        for item in presentation.get("edge_presentations", [])
        if isinstance(item, dict) and item.get("edge_id")
    }
    groups = {
        str(item.get("id")): item
        for item in presentation.get("visual_groups", [])
        if isinstance(item, dict) and item.get("id")
    }
    return node_metadata, edge_metadata, groups


def fallback_region(node: dict[str, Any]) -> str:
    category = category_for_node(node)
    if "public" in str(node.get("trust_zone") or "").lower():
        return "public"
    return {
        "database": "data",
        "monitoring": "monitoring",
        "identity": "identity",
        "security": "identity",
        "registry": "cicd",
        "cicd": "cicd",
        "deployment": "cicd",
        "ingress": "aks_ingress",
        "compute": "aks_backend",
        "orchestration": "aks_platform",
        "search": "utility",
    }.get(category, "other")


def build_layout(
    architecture: dict[str, Any],
    presentation: dict[str, Any],
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    previous = previous or {}
    previous_nodes = previous.get("nodes", {})
    previous_edge_labels = previous.get("edge_labels", {})
    canvas_spec = presentation.get("layout", {}).get("canvas", {})
    canvas_width = max(1100, int(canvas_spec.get("width", 1820)))
    canvas_height = max(750, int(canvas_spec.get("height", 1120)))
    region_specs = presentation.get("layout", {}).get("region_positions", {})
    node_metadata, edge_metadata, groups = presentation_indexes(presentation)

    default_regions = {
        "public": {"center_x": 260, "center_y": canvas_height - 130, "columns": 2, "gap_x": 230, "gap_y": 100},
        "aks_ingress": {"center_x": 480, "center_y": canvas_height - 330, "columns": 2, "gap_x": 220, "gap_y": 100},
        "aks_backend": {"center_x": 760, "center_y": canvas_height - 330, "columns": 2, "gap_x": 220, "gap_y": 100},
        "aks_platform": {"center_x": 620, "center_y": canvas_height - 500, "columns": 2, "gap_x": 220, "gap_y": 100},
        "aks_utility": {"center_x": 900, "center_y": canvas_height - 500, "columns": 2, "gap_x": 220, "gap_y": 100},
        "data": {"center_x": 1260, "center_y": canvas_height - 230, "columns": 2, "gap_x": 230, "gap_y": 100},
        "monitoring": {"center_x": 1260, "center_y": canvas_height - 420, "columns": 2, "gap_x": 230, "gap_y": 100},
        "utility": {"center_x": 1260, "center_y": canvas_height - 590, "columns": 2, "gap_x": 230, "gap_y": 100},
        "identity": {"center_x": 1260, "center_y": canvas_height - 750, "columns": 2, "gap_x": 230, "gap_y": 100},
        "cicd": {"center_x": 690, "center_y": canvas_height - 900, "columns": 4, "gap_x": 225, "gap_y": 100},
        "other": {"center_x": 1260, "center_y": canvas_height - 900, "columns": 2, "gap_x": 230, "gap_y": 100},
    }

    buckets: dict[str, list[dict[str, Any]]] = {}
    for node in architecture.get("nodes", []):
        node_id = str(node.get("id", ""))
        metadata = node_metadata.get(node_id, {})
        group = groups.get(str(metadata.get("group_id") or ""), {})
        region = str(group.get("region") or fallback_region(node))
        buckets.setdefault(region, []).append(node)

    output_nodes: dict[str, dict[str, Any]] = {}
    node_width = 190
    node_height = 72
    for region, nodes in buckets.items():
        nodes.sort(
            key=lambda item: (
                node_metadata.get(str(item.get("id")), {}).get("layout_order", 999),
                str(item.get("name") or item.get("id") or ""),
            )
        )
        configured = region_specs.get(region, {})
        base = default_regions.get(region, default_regions["other"])
        center_x = float(configured.get("center_x", base["center_x"]))
        raw_center_y = float(configured.get("center_y", canvas_height - base["center_y"]))
        center_y = canvas_height - raw_center_y if configured else float(base["center_y"])
        columns = max(1, int(configured.get("columns", base["columns"])))
        gap_x = float(configured.get("gap_x", base["gap_x"]))
        gap_y = float(configured.get("gap_y", base["gap_y"]))
        rows = max(1, math.ceil(len(nodes) / columns))
        used_columns = min(columns, len(nodes))
        start_x = center_x - ((used_columns - 1) * gap_x) / 2 - node_width / 2
        start_y = center_y - ((rows - 1) * gap_y) / 2 - node_height / 2
        for index, node in enumerate(nodes):
            node_id = str(node.get("id", ""))
            if node_id in previous_nodes:
                prior = previous_nodes[node_id]
                output_nodes[node_id] = {
                    "x": float(prior.get("x", 0)),
                    "y": float(prior.get("y", 0)),
                    "width": float(prior.get("width", node_width)),
                    "height": float(prior.get("height", node_height)),
                }
                continue
            column = index % columns
            row = index // columns
            output_nodes[node_id] = {
                "x": round(max(30, start_x + column * gap_x), 2),
                "y": round(max(65, start_y + row * gap_y), 2),
                "width": node_width,
                "height": node_height,
            }

    edge_labels: dict[str, str] = {}
    for edge in architecture.get("edges", []):
        edge_id = str(edge.get("id", ""))
        metadata = edge_metadata.get(edge_id, {})
        edge_labels[edge_id] = str(
            previous_edge_labels.get(edge_id)
            or metadata.get("visible_label")
            or edge.get("protocol")
            or edge.get("data")
            or "Data flow"
        )
    return {
        "canvas": {"width": canvas_width, "height": canvas_height},
        "nodes": output_nodes,
        "edge_labels": edge_labels,
    }


def group_bounds(
    architecture: dict[str, Any],
    presentation: dict[str, Any],
    layout: dict[str, Any],
) -> list[dict[str, Any]]:
    node_metadata, _, groups = presentation_indexes(presentation)
    direct: dict[str, list[str]] = {group_id: [] for group_id in groups}
    children: dict[str, list[str]] = {group_id: [] for group_id in groups}
    for group_id, group in groups.items():
        parent = group.get("parent_id")
        if parent in children:
            children[str(parent)].append(group_id)
    for node in architecture.get("nodes", []):
        node_id = str(node.get("id", ""))
        group_id = str(node_metadata.get(node_id, {}).get("group_id") or "")
        if group_id in direct:
            direct[group_id].append(node_id)

    memo: dict[str, list[str]] = {}

    def descendants(group_id: str) -> list[str]:
        if group_id in memo:
            return memo[group_id]
        values = list(direct.get(group_id, []))
        for child in children.get(group_id, []):
            values.extend(descendants(child))
        memo[group_id] = values
        return values

    results: list[dict[str, Any]] = []
    for group_id, group in groups.items():
        node_ids = [value for value in descendants(group_id) if value in layout["nodes"]]
        if not node_ids:
            continue
        boxes = [layout["nodes"][node_id] for node_id in node_ids]
        group_type = str(group.get("group_type") or "")
        padding = 38 if group_type in {"trust_zone", "platform"} else 22
        header = 34
        x1 = min(box["x"] for box in boxes) - padding
        y1 = min(box["y"] for box in boxes) - padding - header
        x2 = max(box["x"] + box["width"] for box in boxes) + padding
        y2 = max(box["y"] + box["height"] for box in boxes) + padding
        depth = 0
        parent = group.get("parent_id")
        while parent in groups:
            depth += 1
            parent = groups[str(parent)].get("parent_id")
        results.append(
            {
                "id": group_id,
                "label": group.get("label", group_id),
                "x": round(max(5, x1), 2),
                "y": round(max(40, y1), 2),
                "width": round(x2 - x1, 2),
                "height": round(y2 - y1, 2),
                "fill": group.get("fill_color", "#F8FAFC"),
                "border": group.get("border_color", "#94A3B8"),
                "dashed": group.get("line_style") == "dashed",
                "depth": depth,
            }
        )
    results.sort(key=lambda item: (item["depth"], -(item["width"] * item["height"])))
    return results


def theme_styles(presentation: dict[str, Any]) -> dict[str, dict[str, str]]:
    configured = presentation.get("theme", {}).get("category_styles", {})
    defaults = {
        "client": {"fill": "#E8F3FF", "border": "#0078D4"},
        "network": {"fill": "#EAF7FF", "border": "#0099BC"},
        "ingress": {"fill": "#F0F5FF", "border": "#4F6BED"},
        "compute": {"fill": "#EEF7EE", "border": "#107C10"},
        "database": {"fill": "#FFF4E5", "border": "#D83B01"},
        "monitoring": {"fill": "#F3EEFF", "border": "#735BC1"},
        "search": {"fill": "#FFF8D9", "border": "#B8860B"},
        "identity": {"fill": "#FCEEF4", "border": "#C239B3"},
        "security": {"fill": "#FFF0F0", "border": "#D13438"},
        "registry": {"fill": "#EAF4FF", "border": "#0063B1"},
        "cicd": {"fill": "#F0F6FF", "border": "#005A9E"},
        "deployment": {"fill": "#F5F0FF", "border": "#8764B8"},
        "orchestration": {"fill": "#E8F5FF", "border": "#0078D4"},
        "other": {"fill": "#F3F4F6", "border": "#687078"},
    }
    for category, style in configured.items():
        if isinstance(style, dict):
            defaults.setdefault(category, {}).update(
                {key: str(value) for key, value in style.items()}
            )
    return defaults


def flow_style(
    edge_id: str,
    presentation: dict[str, Any],
) -> tuple[str, bool]:
    _, edge_metadata, _ = presentation_indexes(presentation)
    metadata = edge_metadata.get(edge_id, {})
    flow_type = str(metadata.get("flow_type") or "data_request")
    defaults = {
        "data_request": ("#0078D4", False),
        "management": ("#7A6F9B", True),
        "deployment": ("#C55A11", True),
    }
    color, dashed = defaults.get(flow_type, defaults["data_request"])
    configured = presentation.get("theme", {}).get("flow_styles", {}).get(flow_type, {})
    color = str(configured.get("color", color))
    dashed = str(configured.get("line_style", "dashed" if dashed else "solid")) == "dashed"
    return color, dashed


def parse_drawio_style(style: str) -> dict[str, str]:
    """Convert a draw.io style string into a small key/value dictionary."""
    values: dict[str, str] = {}
    for part in str(style or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            values[key.strip()] = value.strip()
        else:
            values[part] = "1"
    return values


def drawio_color(value: str | None, fallback: str) -> str:
    candidate = str(value or "").strip()
    if re.fullmatch(r"#[0-9A-Fa-f]{6}", candidate):
        return candidate
    return fallback


def create_drawio_xml(
    architecture: dict[str, Any],
    presentation: dict[str, Any],
    layout: dict[str, Any],
    architecture_hash: str,
    version: int,
) -> str:
    canvas = layout["canvas"]
    root = ET.Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "modified": utc_now(),
            "agent": "AI Threat Modeling G3",
            "version": "24.7.17",
            "type": "device",
            "compressed": "false",
            "archHash": architecture_hash,
            "reviewVersion": str(version),
        },
    )
    diagram = ET.SubElement(
        root,
        "diagram",
        {"id": str(uuid.uuid4()), "name": f"Architecture Review v{version}"},
    )
    graph_model = ET.SubElement(
        diagram,
        "mxGraphModel",
        {
            "dx": str(canvas["width"]),
            "dy": str(canvas["height"]),
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": str(canvas["width"]),
            "pageHeight": str(canvas["height"] + 120),
            "math": "0",
            "shadow": "0",
        },
    )
    model_root = ET.SubElement(graph_model, "root")
    ET.SubElement(model_root, "mxCell", {"id": "0"})
    ET.SubElement(model_root, "mxCell", {"id": "1", "parent": "0"})

    title = ET.SubElement(
        model_root,
        "mxCell",
        {
            "id": "review_title",
            "value": str(architecture.get("architecture_name") or "Architecture Review"),
            "style": "text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];autosize=1;fontSize=24;fontStyle=1;fontColor=#1F2937;",
            "vertex": "1",
            "parent": "1",
        },
    )
    ET.SubElement(
        title,
        "mxGeometry",
        {"x": "250", "y": "10", "width": "1100", "height": "40", "as": "geometry"},
    )

    for group in group_bounds(architecture, presentation, layout):
        style = (
            "swimlane;html=1;rounded=1;horizontal=1;startSize=28;"
            f"fillColor={group['fill']};strokeColor={group['border']};"
            "fontColor=#334155;fontStyle=1;opacity=55;"
            f"dashed={1 if group['dashed'] else 0};dashPattern=8 5;"
        )
        cell = ET.SubElement(
            model_root,
            "mxCell",
            {
                "id": safe_identifier("group", group["id"]),
                "value": str(group["label"]),
                "style": style,
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(group["x"]),
                "y": str(group["y"]),
                "width": str(group["width"]),
                "height": str(group["height"]),
                "as": "geometry",
            },
        )

    styles = theme_styles(presentation)
    node_metadata, _, _ = presentation_indexes(presentation)
    cell_ids: dict[str, str] = {}
    for node in architecture.get("nodes", []):
        node_id = str(node.get("id", ""))
        cell_id = safe_identifier("node", node_id)
        cell_ids[node_id] = cell_id
        box = layout["nodes"][node_id]
        category = str(node_metadata.get(node_id, {}).get("category") or category_for_node(node))
        style_value = styles.get(category, styles["other"])
        imported_style = str(box.get("drawio_style") or "")
        node_cell_style = imported_style or (
            "rounded=1;whiteSpace=wrap;html=1;arcSize=16;shadow=1;"
            f"fillColor={style_value.get('fill', '#F3F4F6')};"
            f"strokeColor={style_value.get('border', '#687078')};"
            "fontColor=#243447;fontSize=12;fontStyle=0;strokeWidth=2;"
        )
        subtitle = str(node.get("type") or "COMPONENT").upper()
        label = str(node.get("name") or node_id)
        object_element = ET.SubElement(
            model_root,
            "object",
            {
                "id": safe_identifier("object", node_id),
                "label": label,
                "archKind": "node",
                "archId": node_id,
                "originalName": label,
                "nodeType": str(node.get("type") or ""),
                "trustZone": str(node.get("trust_zone") or ""),
            },
        )
        cell = ET.SubElement(
            object_element,
            "mxCell",
            {
                "id": cell_id,
                "value": f"<b>{label}</b><br><font style='font-size:9px'>{subtitle}</font>",
                "style": node_cell_style,
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(box["x"]),
                "y": str(box["y"]),
                "width": str(box["width"]),
                "height": str(box["height"]),
                "as": "geometry",
            },
        )

    for edge in architecture.get("edges", []):
        edge_id = str(edge.get("id", ""))
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        color, dashed = flow_style(edge_id, presentation)
        label = str(layout.get("edge_labels", {}).get(edge_id) or edge.get("protocol") or "")
        imported_style = str(layout.get("edge_styles", {}).get(edge_id) or "")
        edge_cell_style = imported_style or (
            "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;"
            "jettySize=auto;html=1;endArrow=block;endFill=1;"
            f"strokeColor={color};strokeWidth=2;dashed={1 if dashed else 0};"
            "fontSize=10;labelBackgroundColor=#FFFFFF;"
        )
        object_element = ET.SubElement(
            model_root,
            "object",
            {
                "id": safe_identifier("edge_object", edge_id),
                "label": label,
                "archKind": "edge",
                "archId": edge_id,
                "originalLabel": label,
            },
        )
        cell = ET.SubElement(
            object_element,
            "mxCell",
            {
                "id": safe_identifier("edge", edge_id),
                "value": label,
                "style": edge_cell_style,
                "edge": "1",
                "parent": "1",
                "source": cell_ids[source],
                "target": cell_ids[target],
            },
        )
        ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def load_font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = (
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def draw_dashed_line(
    draw: ImageDraw.ImageDraw,
    points: tuple[tuple[float, float], tuple[float, float]],
    fill: str,
    width: int,
    dash: int = 10,
) -> None:
    (x1, y1), (x2, y2) = points
    distance = math.hypot(x2 - x1, y2 - y1)
    if distance == 0:
        return
    unit_x = (x2 - x1) / distance
    unit_y = (y2 - y1) / distance
    position = 0.0
    while position < distance:
        end = min(position + dash, distance)
        draw.line(
            (
                x1 + unit_x * position,
                y1 + unit_y * position,
                x1 + unit_x * end,
                y1 + unit_y * end,
            ),
            fill=fill,
            width=width,
        )
        position += dash * 1.8


def draw_arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[float, float],
    end: tuple[float, float],
    color: str,
    dashed: bool,
) -> None:
    if dashed:
        draw_dashed_line(draw, (start, end), color, 3)
    else:
        draw.line((start, end), fill=color, width=3)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    size = 11
    left = (
        end[0] - size * math.cos(angle - math.pi / 6),
        end[1] - size * math.sin(angle - math.pi / 6),
    )
    right = (
        end[0] - size * math.cos(angle + math.pi / 6),
        end[1] - size * math.sin(angle + math.pi / 6),
    )
    draw.polygon((end, left, right), fill=color)


def wrap_lines(text: str, width: int = 24) -> list[str]:
    words = str(text).split()
    if not words:
        return [""]
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        if len(current) + len(word) + 1 <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines[:3]


def render_png(
    path: Path,
    architecture: dict[str, Any],
    presentation: dict[str, Any],
    layout: dict[str, Any],
    version: int,
) -> None:
    canvas = layout["canvas"]
    width = int(canvas["width"])
    diagram_height = int(canvas["height"])
    header_height = 92
    footer_height = 42
    image = Image.new("RGB", (width, diagram_height + header_height + footer_height), "#F5F8FC")
    draw = ImageDraw.Draw(image)
    title_font = load_font(25, bold=True)
    subtitle_font = load_font(13)
    group_font = load_font(12, bold=True)
    node_font = load_font(12, bold=True)
    node_type_font = load_font(9)
    edge_font = load_font(9)
    footer_font = load_font(10)

    title = str(architecture.get("architecture_name") or "Architecture Review")
    title_box = draw.textbbox((0, 0), title, font=title_font)
    draw.text(((width - (title_box[2] - title_box[0])) / 2, 18), title, fill="#1F2937", font=title_font)
    subtitle = f"Editable Architecture Review — Version {version} — Status: {architecture.get('status', 'DRAFT')}"
    subtitle_box = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(((width - (subtitle_box[2] - subtitle_box[0])) / 2, 55), subtitle, fill="#5B6673", font=subtitle_font)

    for group in group_bounds(architecture, presentation, layout):
        box = (
            group["x"],
            group["y"] + header_height,
            group["x"] + group["width"],
            group["y"] + header_height + group["height"],
        )
        draw.rounded_rectangle(box, radius=12, fill=group["fill"], outline=group["border"], width=2)
        draw.text((group["x"] + 12, group["y"] + header_height + 8), str(group["label"]), fill="#334155", font=group_font)

    nodes_by_id = {
        str(node.get("id")): node
        for node in architecture.get("nodes", [])
        if isinstance(node, dict)
    }
    for edge in architecture.get("edges", []):
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        if source_id not in layout["nodes"] or target_id not in layout["nodes"]:
            continue
        source = layout["nodes"][source_id]
        target = layout["nodes"][target_id]
        start = (
            source["x"] + source["width"] / 2,
            source["y"] + source["height"] / 2 + header_height,
        )
        end = (
            target["x"] + target["width"] / 2,
            target["y"] + target["height"] / 2 + header_height,
        )
        angle = math.atan2(end[1] - start[1], end[0] - start[0])
        start = (
            start[0] + math.cos(angle) * 45,
            start[1] + math.sin(angle) * 30,
        )
        end = (
            end[0] - math.cos(angle) * 48,
            end[1] - math.sin(angle) * 32,
        )
        edge_id = str(edge.get("id", ""))
        color, dashed = flow_style(edge_id, presentation)
        imported_edge_style = parse_drawio_style(
            str(layout.get("edge_styles", {}).get(edge_id) or "")
        )
        color = drawio_color(imported_edge_style.get("strokeColor"), color)
        if "dashed" in imported_edge_style:
            dashed = imported_edge_style["dashed"] == "1"
        draw_arrow(draw, start, end, color, dashed)
        label = str(layout.get("edge_labels", {}).get(str(edge.get("id", "")), ""))
        if label:
            middle = ((start[0] + end[0]) / 2, (start[1] + end[1]) / 2)
            label_box = draw.textbbox((0, 0), label, font=edge_font)
            label_width = label_box[2] - label_box[0]
            label_height = label_box[3] - label_box[1]
            draw.rounded_rectangle(
                (
                    middle[0] - label_width / 2 - 4,
                    middle[1] - label_height / 2 - 3,
                    middle[0] + label_width / 2 + 4,
                    middle[1] + label_height / 2 + 3,
                ),
                radius=4,
                fill="#FFFFFF",
            )
            draw.text((middle[0] - label_width / 2, middle[1] - label_height / 2 - 1), label, fill=color, font=edge_font)

    styles = theme_styles(presentation)
    node_metadata, _, _ = presentation_indexes(presentation)
    for node_id, node in nodes_by_id.items():
        if node_id not in layout["nodes"]:
            continue
        box = layout["nodes"][node_id]
        category = str(node_metadata.get(node_id, {}).get("category") or category_for_node(node))
        style = styles.get(category, styles["other"])
        imported_style = parse_drawio_style(str(box.get("drawio_style") or ""))
        fill_color = drawio_color(imported_style.get("fillColor"), style.get("fill", "#F3F4F6"))
        border_color = drawio_color(imported_style.get("strokeColor"), style.get("border", "#687078"))
        font_color = drawio_color(imported_style.get("fontColor"), "#243447")
        rectangle = (
            box["x"],
            box["y"] + header_height,
            box["x"] + box["width"],
            box["y"] + header_height + box["height"],
        )
        shape = imported_style.get("shape", "")
        if "ellipse" in imported_style or shape == "ellipse":
            draw.ellipse(rectangle, fill=fill_color, outline=border_color, width=3)
        else:
            radius = 12 if imported_style.get("rounded", "1") == "1" else 0
            draw.rounded_rectangle(
                rectangle,
                radius=radius,
                fill=fill_color,
                outline=border_color,
                width=3,
            )
        lines = wrap_lines(str(node.get("name") or node_id), 23)
        total_text_height = len(lines) * 15 + 13
        current_y = box["y"] + header_height + (box["height"] - total_text_height) / 2
        for line in lines:
            text_box = draw.textbbox((0, 0), line, font=node_font)
            line_width = text_box[2] - text_box[0]
            draw.text((box["x"] + (box["width"] - line_width) / 2, current_y), line, fill=font_color, font=node_font)
            current_y += 15
        node_type = str(node.get("type") or "COMPONENT").upper()
        type_box = draw.textbbox((0, 0), node_type, font=node_type_font)
        draw.text((box["x"] + (box["width"] - (type_box[2] - type_box[0])) / 2, current_y + 2), node_type, fill="#5B6673", font=node_type_font)

    footer_y = diagram_height + header_height + 10
    footer = "Blue: data/request  |  Violet: management  |  Orange: deployment  |  Architecture JSON remains the source of truth"
    footer_box = draw.textbbox((0, 0), footer, font=footer_font)
    draw.text(((width - (footer_box[2] - footer_box[0])) / 2, footer_y), footer, fill="#52606D", font=footer_font)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.stem + ".tmp" + path.suffix)
    image.save(temporary, format="PNG")
    os.replace(temporary, path)


def architecture_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    metadata_changes: dict[str, dict[str, Any]] = {}
    for field in sorted(ALLOWED_METADATA_CHANGES | {"status"}):
        if before.get(field) != after.get(field):
            metadata_changes[field] = {"before": before.get(field), "after": after.get(field)}

    def keyed_changes(collection: str) -> dict[str, Any]:
        old = {
            str(item.get("id")): item
            for item in before.get(collection, [])
            if isinstance(item, dict) and item.get("id")
        }
        new = {
            str(item.get("id")): item
            for item in after.get(collection, [])
            if isinstance(item, dict) and item.get("id")
        }
        added = [copy.deepcopy(new[key]) for key in sorted(new.keys() - old.keys())]
        removed = [copy.deepcopy(old[key]) for key in sorted(old.keys() - new.keys())]
        modified: list[dict[str, Any]] = []
        for key in sorted(old.keys() & new.keys()):
            fields = sorted(set(old[key]) | set(new[key]))
            changes = {
                field: {"before": old[key].get(field), "after": new[key].get(field)}
                for field in fields
                if old[key].get(field) != new[key].get(field)
            }
            if changes:
                modified.append({"id": key, "changes": changes})
        return {"added": added, "removed": removed, "modified": modified}

    node_changes = keyed_changes("nodes")
    edge_changes = keyed_changes("edges")
    trust_zone_changes = keyed_changes("trust_zones")
    total = (
        len(metadata_changes)
        + sum(len(node_changes[key]) for key in ("added", "removed", "modified"))
        + sum(len(edge_changes[key]) for key in ("added", "removed", "modified"))
        + sum(len(trust_zone_changes[key]) for key in ("added", "removed", "modified"))
    )
    return {
        "metadata": metadata_changes,
        "nodes": node_changes,
        "edges": edge_changes,
        "trust_zones": trust_zone_changes,
        "total_change_groups": total,
        "summary": {
            "nodes_added": len(node_changes["added"]),
            "nodes_removed": len(node_changes["removed"]),
            "nodes_modified": len(node_changes["modified"]),
            "edges_added": len(edge_changes["added"]),
            "edges_removed": len(edge_changes["removed"]),
            "edges_modified": len(edge_changes["modified"]),
            "metadata_modified": len(metadata_changes),
        },
    }


def expected_changes(patch: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "nodes_added": set(),
        "nodes_removed": set(),
        "nodes_modified": {},
        "edges_added": set(),
        "edges_removed": set(),
        "edges_modified": {},
        "metadata_modified": set(),
    }
    for operation in patch.get("operations", []):
        op = operation.get("op")
        if op == "ADD_NODE":
            expected["nodes_added"].add(str(operation.get("node", {}).get("id", "")))
        elif op == "REMOVE_NODE":
            expected["nodes_removed"].add(str(operation.get("node_id", "")))
        elif op == "UPDATE_NODE":
            node_id = str(operation.get("node_id", ""))
            expected["nodes_modified"].setdefault(node_id, set()).update(operation.get("changes", {}).keys())
        elif op == "ADD_EDGE":
            expected["edges_added"].add(str(operation.get("edge", {}).get("id", "")))
        elif op == "REMOVE_EDGE":
            expected["edges_removed"].add(str(operation.get("edge_id", "")))
        elif op == "UPDATE_EDGE":
            edge_id = str(operation.get("edge_id", ""))
            expected["edges_modified"].setdefault(edge_id, set()).update(operation.get("changes", {}).keys())
        elif op == "UPDATE_METADATA":
            expected["metadata_modified"].update(operation.get("changes", {}).keys())
    return expected


def detect_unintended_changes(
    patch: dict[str, Any],
    diff: dict[str, Any],
) -> dict[str, Any]:
    expected = expected_changes(patch)
    unexpected: list[str] = []

    actual_added_nodes = {str(item.get("id")) for item in diff["nodes"]["added"]}
    actual_removed_nodes = {str(item.get("id")) for item in diff["nodes"]["removed"]}
    actual_added_edges = {str(item.get("id")) for item in diff["edges"]["added"]}
    actual_removed_edges = {str(item.get("id")) for item in diff["edges"]["removed"]}
    if actual_added_nodes - expected["nodes_added"]:
        unexpected.append("Unexpected added nodes: " + ", ".join(sorted(actual_added_nodes - expected["nodes_added"])))
    if actual_removed_nodes - expected["nodes_removed"]:
        unexpected.append("Unexpected removed nodes: " + ", ".join(sorted(actual_removed_nodes - expected["nodes_removed"])))
    if actual_added_edges - expected["edges_added"]:
        unexpected.append("Unexpected added edges: " + ", ".join(sorted(actual_added_edges - expected["edges_added"])))
    if actual_removed_edges - expected["edges_removed"]:
        unexpected.append("Unexpected removed edges: " + ", ".join(sorted(actual_removed_edges - expected["edges_removed"])))

    for item in diff["nodes"]["modified"]:
        node_id = str(item["id"])
        changed_fields = set(item["changes"])
        allowed_fields = expected["nodes_modified"].get(node_id, set())
        extra = changed_fields - allowed_fields
        if extra or node_id not in expected["nodes_modified"]:
            unexpected.append(
                f"Node '{node_id}' changed unexpected fields: "
                + ", ".join(sorted(extra or changed_fields))
            )
    for item in diff["edges"]["modified"]:
        edge_id = str(item["id"])
        changed_fields = set(item["changes"])
        allowed_fields = expected["edges_modified"].get(edge_id, set())
        extra = changed_fields - allowed_fields
        if extra or edge_id not in expected["edges_modified"]:
            unexpected.append(
                f"Edge '{edge_id}' changed unexpected fields: "
                + ", ".join(sorted(extra or changed_fields))
            )
    extra_metadata = set(diff["metadata"]) - expected["metadata_modified"]
    if extra_metadata:
        unexpected.append("Unexpected metadata changes: " + ", ".join(sorted(extra_metadata)))
    if diff["trust_zones"]["added"] or diff["trust_zones"]["removed"] or diff["trust_zones"]["modified"]:
        unexpected.append("Trust zones changed, but this patch format does not permit trust-zone changes.")
    return {
        "safe": not unexpected,
        "unexpected_changes": unexpected,
        "checked_at": utc_now(),
        "method": "Actual structural diff was compared with the exact allowed fields in the applied patch.",
    }


def validate_patch_shape(patch: dict[str, Any]) -> None:
    if not isinstance(patch, dict):
        raise WorkflowError("AI response must be one JSON object.")
    operations = patch.get("operations")
    if not isinstance(operations, list):
        raise WorkflowError("Patch must contain an operations list.")
    if len(operations) > 20:
        raise WorkflowError("Patch contains more than 20 operations; split the request into smaller changes.")
    for index, operation in enumerate(operations, start=1):
        if not isinstance(operation, dict):
            raise WorkflowError(f"Patch operation {index} is not an object.")
        op = operation.get("op")
        if op not in ALLOWED_OPERATIONS:
            raise WorkflowError(f"Patch operation {index} uses unsupported action '{op}'.")
        if op == "UPDATE_NODE":
            changes = operation.get("changes")
            if not isinstance(changes, dict) or not changes:
                raise WorkflowError(f"UPDATE_NODE operation {index} needs non-empty changes.")
            forbidden = set(changes) - ALLOWED_NODE_CHANGES
            if forbidden:
                raise WorkflowError("UPDATE_NODE cannot change: " + ", ".join(sorted(forbidden)))
        if op == "UPDATE_EDGE":
            changes = operation.get("changes")
            if not isinstance(changes, dict) or not changes:
                raise WorkflowError(f"UPDATE_EDGE operation {index} needs non-empty changes.")
            forbidden = set(changes) - ALLOWED_EDGE_CHANGES
            if forbidden:
                raise WorkflowError("UPDATE_EDGE cannot change: " + ", ".join(sorted(forbidden)))
        if op == "UPDATE_METADATA":
            changes = operation.get("changes")
            if not isinstance(changes, dict) or not changes:
                raise WorkflowError(f"UPDATE_METADATA operation {index} needs non-empty changes.")
            forbidden = set(changes) - ALLOWED_METADATA_CHANGES
            if forbidden:
                raise WorkflowError("UPDATE_METADATA cannot change: " + ", ".join(sorted(forbidden)))


def find_by_id(values: list[dict[str, Any]], item_id: str) -> dict[str, Any] | None:
    return next((item for item in values if str(item.get("id")) == item_id), None)


def apply_patch(
    architecture: dict[str, Any],
    patch: dict[str, Any],
) -> dict[str, Any]:
    validate_patch_shape(patch)
    candidate = copy.deepcopy(architecture)
    nodes = candidate.setdefault("nodes", [])
    edges = candidate.setdefault("edges", [])

    for operation in patch.get("operations", []):
        op = operation["op"]
        if op == "ADD_NODE":
            node = operation.get("node")
            if not isinstance(node, dict):
                raise WorkflowError("ADD_NODE requires a complete node object.")
            node_id = str(node.get("id") or "").strip()
            if not node_id or not str(node.get("name") or "").strip() or not str(node.get("type") or "").strip():
                raise WorkflowError("ADD_NODE requires id, name, and type.")
            if find_by_id(nodes, node_id):
                raise WorkflowError(f"Cannot add node '{node_id}': ID already exists.")
            clean_node = {key: copy.deepcopy(value) for key, value in node.items() if key in ({"id"} | ALLOWED_NODE_CHANGES)}
            clean_node.setdefault("description", "")
            clean_node.setdefault("requirement_ids", [])
            nodes.append(clean_node)
        elif op == "REMOVE_NODE":
            node_id = str(operation.get("node_id") or "").strip()
            if not find_by_id(nodes, node_id):
                raise WorkflowError(f"Cannot remove node '{node_id}': ID does not exist.")
            connected = [
                str(edge.get("id"))
                for edge in edges
                if edge.get("source") == node_id or edge.get("target") == node_id
            ]
            edge_removals = {
                str(item.get("edge_id"))
                for item in patch.get("operations", [])
                if item.get("op") == "REMOVE_EDGE"
            }
            for missing_edge_id in sorted(set(connected) - edge_removals):
                patch["operations"].append({"op": "REMOVE_EDGE", "edge_id": missing_edge_id})
            edges[:] = [edge for edge in edges if edge.get("source") != node_id and edge.get("target") != node_id]
            nodes[:] = [node for node in nodes if str(node.get("id")) != node_id]
        elif op == "UPDATE_NODE":
            node_id = str(operation.get("node_id") or "").strip()
            node = find_by_id(nodes, node_id)
            if not node:
                raise WorkflowError(f"Cannot update node '{node_id}': ID does not exist.")
            node.update(copy.deepcopy(operation["changes"]))
        elif op == "ADD_EDGE":
            edge = operation.get("edge")
            if not isinstance(edge, dict):
                raise WorkflowError("ADD_EDGE requires a complete edge object.")
            src_val = str(edge.get("source") or "").strip()
            tgt_val = str(edge.get("target") or "").strip()
            edge_id = str(edge.get("id") or f"{src_val}->{tgt_val}").strip()
            edge["id"] = edge_id
            if not edge_id or not src_val or not tgt_val:
                raise WorkflowError("ADD_EDGE requires id, source, and target.")
            if find_by_id(edges, edge_id):
                raise WorkflowError(f"Cannot add edge '{edge_id}': ID already exists.")
            clean_edge = {key: copy.deepcopy(value) for key, value in edge.items() if key in ({"id"} | ALLOWED_EDGE_CHANGES)}
            clean_edge.setdefault("protocol", "HTTPS")
            clean_edge.setdefault("data", "Data")
            clean_edge.setdefault("authentication", "None")
            clean_edge.setdefault("encryption", "TLS")
            clean_edge.setdefault("trust_boundary_crossing", False)
            clean_edge.setdefault("requirement_ids", [])
            edges.append(clean_edge)
        elif op == "REMOVE_EDGE":
            edge_id = str(operation.get("edge_id") or "").strip()
            if not find_by_id(edges, edge_id):
                raise WorkflowError(f"Cannot remove edge '{edge_id}': ID does not exist.")
            edges[:] = [edge for edge in edges if str(edge.get("id")) != edge_id]
        elif op == "UPDATE_EDGE":
            edge_id = str(operation.get("edge_id") or "").strip()
            edge = find_by_id(edges, edge_id)
            if not edge:
                raise WorkflowError(f"Cannot update edge '{edge_id}': ID does not exist.")
            edge.update(copy.deepcopy(operation["changes"]))
        elif op == "UPDATE_METADATA":
            candidate.update(copy.deepcopy(operation["changes"]))
    return candidate


def remove_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = remove_thinking(text)
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    if start < 0:
        raise WorkflowError("Ollama did not return a JSON patch.")
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(cleaned)):
        character = cleaned[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(cleaned[start : index + 1])
                except json.JSONDecodeError as error:
                    raise WorkflowError(f"Ollama returned invalid patch JSON: {error}") from error
                if not isinstance(value, dict):
                    raise WorkflowError("Ollama patch must be one JSON object.")
                return value
    raise WorkflowError("Ollama returned incomplete patch JSON.")


def request_patch_from_ollama(
    feedback: str,
    architecture: dict[str, Any],
    requirements: dict[str, Any],
) -> dict[str, Any]:
    feedback = feedback.strip()
    if not feedback:
        raise WorkflowError("Write the requested architecture change first.")
    catalog = requirement_catalog(requirements)
    system_prompt = """You are a controlled software-architecture patch generator.
Return JSON only. Never regenerate the full architecture. Apply only what the reviewer explicitly requests.
Allowed actions: ADD_NODE, REMOVE_NODE, UPDATE_NODE, ADD_EDGE, REMOVE_EDGE, UPDATE_EDGE, UPDATE_METADATA.
Never change an existing node or edge ID. To remove a node, explicitly remove every connected edge too.
Use only existing requirement IDs. Use an empty requirement_ids list when no existing requirement supports a new element.
Use an existing trust-zone name. Preserve all unrelated fields and elements.
Output exactly this shape:
{
  "summary": "short explanation",
  "operations": [
    {"op":"UPDATE_NODE","node_id":"exact ID","changes":{"description":"new value"}}
  ]
}
If no semantic graph change is required, return an empty operations list."""
    user_prompt = (
        "REVIEWER FEEDBACK:\n"
        + feedback
        + "\n\nVALID REQUIREMENT IDS:\n"
        + json.dumps(sorted(catalog), ensure_ascii=False)
        + "\n\nCURRENT ARCHITECTURE:\n"
        + json.dumps(architecture, indent=2, ensure_ascii=False)
    )
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": 0.1},
    }
    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as error:
        raise WorkflowError(
            "Could not connect to Ollama. Open another CMD, run "
            "'ollama run qwen3:4b', then try again. "
            f"Technical detail: {error}"
        ) from error
    except (TimeoutError, json.JSONDecodeError) as error:
        raise WorkflowError(f"Ollama returned an unreadable response: {error}") from error
    content = result.get("message", {}).get("content")
    if not isinstance(content, str):
        raise WorkflowError("Ollama response did not contain patch text.")
    patch = extract_json_object(content)
    patch["reviewer_feedback"] = feedback
    patch["model"] = OLLAMA_MODEL
    patch["generated_at"] = utc_now()
    validate_patch_shape(patch)
    return patch


def decode_graph_model(root: ET.Element) -> tuple[ET.Element, ET.Element]:
    if root.tag == "mxGraphModel":
        return root, root
    if root.tag != "mxfile":
        raise WorkflowError("Uploaded XML must contain an mxfile or mxGraphModel root.")
    diagram = root.find("diagram")
    if diagram is None:
        raise WorkflowError("The draw.io file contains no diagram page.")
    model = diagram.find("mxGraphModel")
    if model is not None:
        return root, model
    encoded = (diagram.text or "").strip()
    if not encoded:
        raise WorkflowError("The draw.io diagram page is empty.")
    try:
        compressed = urllib.parse.unquote(
            zlib.decompress(__import__("base64").b64decode(encoded), -15).decode("utf-8")
        )
        model = ET.fromstring(compressed)
    except Exception as error:
        raise WorkflowError(
            "Could not decode the compressed draw.io page. Export it again as an uncompressed .drawio or XML file."
        ) from error
    return root, model


def clean_drawio_label(value: str) -> str:
    value = html.unescape(str(value or ""))
    value = re.sub(r"<br\s*/?>", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def sync_downstream_artifacts() -> None:
    """Keep DFD, STRIDE Risk Matrix, Security Controls, and .TM7 XML + Visual Diagrams in sync."""
    try:
        import dfd_generator, stride_engine, security_controls, tm7_exporter
        dfd_generator.main()
        stride_engine.main()
        security_controls.main()
        tm7_exporter.main()
    except Exception as err:
        print(f"Notice: Downstream sync warning ({err})")


def infer_node_type_and_zone(name: str, feedback: str, architecture: dict[str, Any]) -> tuple[str, str]:
    combined = f"{name} {feedback}".lower()
    zones = [str(z.get("name") or z.get("id") or "") for z in architecture.get("trust_zones", []) if isinstance(z, dict)]
    zones = [z for z in zones if z]

    def match_zone(keywords: tuple[str, ...], fallback_idx: int = 0) -> str:
        for z in zones:
            if any(k in z.lower() for k in keywords):
                return z
        return zones[min(fallback_idx, len(zones) - 1)] if zones else "Application"

    if any(k in combined for k in ("redis", "cache", "sql", "cosmos", "database", "db", "postgres", "mongo", "storage", "store", "backup")):
        return "Database / Cache", match_zone(("data", "restricted", "store"), 2)
    if any(k in combined for k in ("waf", "firewall", "load balancer", "cdn", "front door", "ddos", "ingress", "gateway", "edge", "proxy")):
        return "Ingress / Gateway", match_zone(("edge", "ingress", "public", "app"), 1)
    if any(k in combined for k in ("vault", "secret", "kms", "key", "hsm")):
        return "Security / Vault", match_zone(("data", "restricted", "management", "security"), 2)
    if any(k in combined for k in ("auth", "identity", "idp", "oidc", "oauth", "entra", "active directory", "sso", "mfa")):
        return "Identity", match_zone(("third", "management", "identity", "app"), 2)
    if any(k in combined for k in ("monitor", "prometheus", "grafana", "log", "siem", "audit", "splunk", "sentinel", "telemetry")):
        return "Monitoring", match_zone(("management", "corporate", "monitor", "app"), 2)
    if any(k in combined for k in ("client", "browser", "mobile", "portal", "ui", "frontend", "web app")):
        return "Client", match_zone(("public", "client"), 0)
    if any(k in combined for k in ("external", "third-party", "provider", "stripe", "twilio", "sendgrid")):
        return "External Service", match_zone(("third", "external", "public"), 0)
    return "Service", match_zone(("app", "internal", "service"), 1)


def build_smart_nl_patch(
    feedback: str,
    architecture: dict[str, Any],
    requirements: dict[str, Any],
) -> dict[str, Any]:
    """Deterministically translate natural-language reviewer instructions into valid graph operations (ADD/REMOVE/UPDATE/CONNECT)."""
    fb = feedback.strip()
    fb_lower = fb.lower()
    nodes = [n for n in architecture.get("nodes", []) if isinstance(n, dict)]
    edges = [e for e in architecture.get("edges", []) if isinstance(e, dict)]
    catalog = requirement_catalog(requirements)
    valid_req_ids = sorted(catalog.keys())
    default_reqs = valid_req_ids[:2] if valid_req_ids else []

    def match_existing_nodes(text: str) -> list[dict[str, Any]]:
        t_low = text.lower()
        matched = []
        for n in nodes:
            nid = str(n.get("id", ""))
            nname = str(n.get("name", ""))
            tokens = [w for w in re.split(r"[^a-z0-9]+", f"{nid} {nname}".lower()) if len(w) >= 4 and w not in {"service", "platform", "system", "application", "zone", "store", "data"}]
            if nid.lower() in t_low or nname.lower() in t_low or any(tok in t_low for tok in tokens):
                matched.append(n)
        return matched

    operations: list[dict[str, Any]] = []

    # 1. Check REMOVE / DELETE intent
    if re.search(r"^\s*(?:remove|delete|drop)\b", fb_lower):
        targets = match_existing_nodes(fb)
        if targets:
            target_node = targets[0]
            tid = str(target_node["id"])
            for e in edges:
                if e.get("source") == tid or e.get("target") == tid:
                    operations.append({"op": "REMOVE_EDGE", "edge_id": str(e["id"])})
            operations.append({"op": "REMOVE_NODE", "node_id": tid})
            return {
                "summary": f"Removed component '{target_node.get('name', tid)}' and its connected data flows.",
                "operations": operations,
            }

    # 2. Check RENAME / UPDATE intent
    rename_match = re.search(r"(?:rename|change\s+name\s+of)\s+(.+?)\s+to\s+(.+)$", fb, flags=re.IGNORECASE)
    if rename_match:
        old_part, new_name = rename_match.group(1).strip(), rename_match.group(2).strip().rstrip(".")
        targets = match_existing_nodes(old_part)
        if targets and new_name:
            target_node = targets[0]
            tid = str(target_node["id"])
            operations.append({
                "op": "UPDATE_NODE",
                "node_id": tid,
                "changes": {"name": new_name},
            })
            return {
                "summary": f"Renamed '{target_node.get('name', tid)}' to '{new_name}'.",
                "operations": operations,
            }

    # 3. Check CONNECT / ADD FLOW between two existing nodes
    if re.search(r"^\s*(?:connect|link|add\s+(?:a\s+)?(?:flow|edge|connection))\b", fb_lower):
        matched = match_existing_nodes(fb)
        if len(matched) >= 2:
            src_node, tgt_node = matched[0], matched[1]
            edge_id = f"{src_node['id']}->{tgt_node['id']}"
            if not find_by_id(edges, edge_id):
                operations.append({
                    "op": "ADD_EDGE",
                    "edge": {
                        "id": edge_id,
                        "source": str(src_node["id"]),
                        "target": str(tgt_node["id"]),
                        "protocol": "HTTPS / mTLS" if "mtls" in fb_lower else "HTTPS",
                        "data": f"Authenticated service flow ({src_node.get('name', src_node['id'])} to {tgt_node.get('name', tgt_node['id'])})",
                        "authentication": "Mutual TLS (mTLS)",
                        "encryption": "TLS 1.3",
                        "trust_boundary_crossing": src_node.get("trust_zone") != tgt_node.get("trust_zone"),
                        "requirement_ids": default_reqs,
                    },
                })
                return {
                    "summary": f"Added data flow '{edge_id}' between '{src_node.get('name')}' and '{tgt_node.get('name')}'.",
                    "operations": operations,
                }

    # 4. Default / ADD COMPONENT intent (extract clean component name and wire edges automatically!)
    cleaned = re.sub(
        r"^\s*(?:please\s+)?(?:add|create|insert|introduce|include|deploy|place)\s+(?:a\s+|an\s+|new\s+|the\s+)?",
        "",
        fb,
        flags=re.IGNORECASE,
    )
    cleaned = re.split(
        r"\b(?:between|connected\s+to|connecting\s+to|from|to|in\s+front\s+of|behind|inside|in\s+the|for|with)\b",
        cleaned,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0].strip(" .,;:-")

    if not cleaned or len(cleaned) < 2:
        cleaned = re.sub(r"[^a-zA-Z0-9 ]", " ", fb).strip()[:30] or "Security Service"

    comp_name = cleaned[0].upper() + cleaned[1:] if cleaned else "Custom Component"
    slug = re.sub(r"[^a-zA-Z0-9]", "", comp_name.title())[:22] or "CustomNode"
    node_id = slug
    if find_by_id(nodes, node_id):
        node_id = f"{slug}_{len(nodes) + 1}"

    ntype, tzone = infer_node_type_and_zone(comp_name, fb, architecture)
    operations.append({
        "op": "ADD_NODE",
        "node": {
            "id": node_id,
            "name": comp_name,
            "type": ntype,
            "trust_zone": tzone,
            "description": fb,
            "requirement_ids": default_reqs,
        },
    })

    # Automatically wire the new node to mentioned existing nodes (or primary service node)
    referenced_nodes = match_existing_nodes(fb)
    if "between" in fb_lower and len(referenced_nodes) >= 2:
        n1, n2 = referenced_nodes[0], referenced_nodes[1]
        operations.append({
            "op": "ADD_EDGE",
            "edge": {
                "id": f"{n1['id']}->{node_id}",
                "source": str(n1["id"]),
                "target": node_id,
                "protocol": "HTTPS",
                "data": f"Request / data flow to {comp_name}",
                "authentication": "Workload Identity / mTLS",
                "encryption": "TLS 1.3",
                "trust_boundary_crossing": n1.get("trust_zone") != tzone,
                "requirement_ids": default_reqs,
            },
        })
        operations.append({
            "op": "ADD_EDGE",
            "edge": {
                "id": f"{node_id}->{n2['id']}",
                "source": node_id,
                "target": str(n2["id"]),
                "protocol": "HTTPS / TLS",
                "data": f"Forwarded / cached flow from {comp_name} to {n2.get('name', n2['id'])}",
                "authentication": "Workload Identity / mTLS",
                "encryption": "TLS 1.3",
                "trust_boundary_crossing": n2.get("trust_zone") != tzone,
                "requirement_ids": default_reqs,
            },
        })
    elif referenced_nodes:
        target_existing = referenced_nodes[0]
        if any(k in fb_lower for k in ("in front of", "before", "from")):
            src_id, tgt_id = node_id, str(target_existing["id"])
        else:
            src_id, tgt_id = str(target_existing["id"]), node_id
        operations.append({
            "op": "ADD_EDGE",
            "edge": {
                "id": f"{src_id}->{tgt_id}",
                "source": src_id,
                "target": tgt_id,
                "protocol": "HTTPS",
                "data": f"Data flow integrating {comp_name}",
                "authentication": "Workload Identity / mTLS",
                "encryption": "TLS 1.3",
                "trust_boundary_crossing": target_existing.get("trust_zone") != tzone,
                "requirement_ids": default_reqs,
            },
        })
    elif nodes:
        # Connect to the primary application service node so it's never an orphan box
        primary_service = next(
            (n for n in nodes if "service" in str(n.get("type", "")).lower() or "reservation" in str(n.get("id", "")).lower() or "backend" in str(n.get("id", "")).lower()),
            nodes[0],
        )
        operations.append({
            "op": "ADD_EDGE",
            "edge": {
                "id": f"{primary_service['id']}->{node_id}",
                "source": str(primary_service["id"]),
                "target": node_id,
                "protocol": "HTTPS",
                "data": f"Service integration with {comp_name}",
                "authentication": "Workload Identity / mTLS",
                "encryption": "TLS 1.3",
                "trust_boundary_crossing": primary_service.get("trust_zone") != tzone,
                "requirement_ids": default_reqs,
            },
        })

    return {
        "summary": f"Added '{comp_name}' ({ntype}) in '{tzone}' and wired connected data flows.",
        "operations": operations,
    }


def parse_drawio_upload(
    xml_text: str,
    current_architecture: dict[str, Any],
    current_layout: dict[str, Any],
    current_hash: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if len(xml_text.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise WorkflowError("The uploaded draw.io file is larger than 15 MB.")
    upper_prefix = xml_text[:4096].upper()
    if "<!DOCTYPE" in upper_prefix or "<!ENTITY" in upper_prefix:
        raise WorkflowError("DOCTYPE and ENTITY declarations are not allowed in uploaded XML.")
    try:
        parsed_root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise WorkflowError(f"Uploaded draw.io XML is malformed: {error}") from error
    outer_root, graph_model = decode_graph_model(parsed_root)

    current_nodes = {
        str(node.get("id")): node
        for node in current_architecture.get("nodes", [])
        if isinstance(node, dict) and node.get("id")
    }
    current_edges = {
        str(edge.get("id")): edge
        for edge in current_architecture.get("edges", [])
        if isinstance(edge, dict) and edge.get("id")
    }

    imported_nodes: dict[str, dict[str, Any]] = {}
    cell_id_to_arch_id: dict[str, str] = {}
    edge_labels = dict(current_layout.get("edge_labels", {}))
    edge_styles = dict(current_layout.get("edge_styles", {}))
    imported_edges: list[dict[str, Any]] = []

    # 1. First extract managed <object archKind="node/edge"> elements
    for object_element in graph_model.findall(".//object"):
        kind = object_element.get("archKind")
        item_id = str(object_element.get("archId") or object_element.get("id") or "")
        cell = object_element.find("mxCell")
        if cell is None:
            continue
        cid = str(object_element.get("id") or cell.get("id") or item_id)
        if kind == "node" or cell.get("vertex") == "1":
            geometry = cell.find("mxGeometry")
            if geometry is None:
                continue
            raw_label = clean_drawio_label(object_element.get("label") or cell.get("value") or object_element.get("originalName") or item_id)
            # Strip trailing uppercase subtitle if present from mxCell value
            ntype_hint = str(object_element.get("nodeType") or "").upper()
            if ntype_hint and raw_label.upper().endswith(" " + ntype_hint):
                raw_label = raw_label[: -(len(ntype_hint) + 1)].strip()
            arch_id = item_id or re.sub(r"[^a-zA-Z0-9_]", "", raw_label.title())[:24] or f"Node_{len(imported_nodes)+1}"
            cell_id_to_arch_id[cid] = arch_id
            if cell.get("id"):
                cell_id_to_arch_id[str(cell.get("id"))] = arch_id
            imported_nodes[arch_id] = {
                "label": raw_label or arch_id,
                "x": float(geometry.get("x", "120")),
                "y": float(geometry.get("y", "120")),
                "width": float(geometry.get("width", "190")),
                "height": float(geometry.get("height", "72")),
                "style": str(cell.get("style") or ""),
                "nodeType": str(object_element.get("nodeType") or ""),
                "trustZone": str(object_element.get("trustZone") or ""),
            }
        elif kind == "edge" or cell.get("edge") == "1":
            lbl = clean_drawio_label(object_element.get("label") or cell.get("value") or "")
            if item_id:
                edge_labels[item_id] = lbl
                edge_styles[item_id] = str(cell.get("style") or "")
            imported_edges.append({
                "arch_id": item_id,
                "source_cell": str(cell.get("source") or ""),
                "target_cell": str(cell.get("target") or ""),
                "label": lbl,
                "style": str(cell.get("style") or ""),
            })

    # 2. Also inspect standalone <mxCell> elements added by the user directly in draw.io
    managed_cells = {cell for obj in graph_model.findall(".//object") for cell in obj.findall("mxCell")}
    for cell in graph_model.findall(".//mxCell"):
        if cell in managed_cells:
            continue
        cid = str(cell.get("id") or "")
        if cid in {"0", "1", "review_title"} or cid.startswith("group_"):
            continue
        style_str = str(cell.get("style") or "")
        if "swimlane" in style_str or style_str.startswith("text;"):
            continue
        if cell.get("vertex") == "1":
            geometry = cell.find("mxGeometry")
            if geometry is None:
                continue
            raw_label = clean_drawio_label(cell.get("value") or cid)
            if not raw_label:
                continue
            # Match to existing node by name if possible, else create new node ID
            matched_id = next(
                (nid for nid, n in current_nodes.items() if str(n.get("name", "")).lower() == raw_label.lower() or nid.lower() == raw_label.lower()),
                None,
            )
            arch_id = matched_id or re.sub(r"[^a-zA-Z0-9]", "", raw_label.title())[:24] or f"CustomNode_{len(imported_nodes)+1}"
            cell_id_to_arch_id[cid] = arch_id
            imported_nodes[arch_id] = {
                "label": raw_label,
                "x": float(geometry.get("x", "160")),
                "y": float(geometry.get("y", "160")),
                "width": float(geometry.get("width", "190")),
                "height": float(geometry.get("height", "72")),
                "style": style_str,
                "nodeType": "",
                "trustZone": "",
            }
        elif cell.get("edge") == "1":
            imported_edges.append({
                "arch_id": "",
                "source_cell": str(cell.get("source") or ""),
                "target_cell": str(cell.get("target") or ""),
                "label": clean_drawio_label(cell.get("value") or "HTTPS"),
                "style": style_str,
            })

    if not imported_nodes:
        raise WorkflowError("No diagram components were found in the uploaded draw.io XML file.")

    operations: list[dict[str, Any]] = []
    new_layout = copy.deepcopy(current_layout)
    new_layout["nodes"] = {}
    new_layout["edge_labels"] = edge_labels
    new_layout["edge_styles"] = edge_styles

    requirements = load_json(REQUIREMENTS_FILE, "requirements") if REQUIREMENTS_FILE.exists() else {}
    valid_reqs = sorted(requirement_catalog(requirements).keys())
    default_reqs = valid_reqs[:2] if valid_reqs else []

    # Handle removed nodes (along with their connected edges)
    removed_node_ids = sorted(set(current_nodes) - set(imported_nodes))
    removed_edge_ids = set()
    for rem_id in removed_node_ids:
        for eid, edge in current_edges.items():
            if edge.get("source") == rem_id or edge.get("target") == rem_id:
                if eid not in removed_edge_ids:
                    operations.append({"op": "REMOVE_EDGE", "edge_id": eid})
                    removed_edge_ids.add(eid)
        operations.append({"op": "REMOVE_NODE", "node_id": rem_id})

    # Handle added and updated nodes
    for node_id, item in imported_nodes.items():
        new_layout["nodes"][node_id] = {
            "x": item["x"],
            "y": item["y"],
            "width": max(80.0, item["width"]),
            "height": max(40.0, item["height"]),
            "drawio_style": item["style"],
        }
        if node_id not in current_nodes:
            ntype, tzone = infer_node_type_and_zone(item["label"], item["label"], current_architecture)
            operations.append({
                "op": "ADD_NODE",
                "node": {
                    "id": node_id,
                    "name": item["label"] or node_id,
                    "type": item["nodeType"] or ntype,
                    "trust_zone": item["trustZone"] or tzone,
                    "description": f"Imported component '{item['label']}' from draw.io diagram.",
                    "requirement_ids": default_reqs,
                },
            })
        else:
            old_name = str(current_nodes[node_id].get("name") or node_id)
            new_name = item["label"]
            if new_name and new_name != old_name:
                operations.append({
                    "op": "UPDATE_NODE",
                    "node_id": node_id,
                    "changes": {"name": new_name},
                })

    # Handle new edges drawn in draw.io
    for e_item in imported_edges:
        src_arch = cell_id_to_arch_id.get(e_item["source_cell"])
        tgt_arch = cell_id_to_arch_id.get(e_item["target_cell"])
        if not src_arch or not tgt_arch or src_arch not in imported_nodes or tgt_arch not in imported_nodes:
            continue
        eid = e_item["arch_id"] if e_item["arch_id"] in current_edges else f"{src_arch}->{tgt_arch}"
        if eid not in current_edges and eid not in removed_edge_ids:
            operations.append({
                "op": "ADD_EDGE",
                "edge": {
                    "id": eid,
                    "source": src_arch,
                    "target": tgt_arch,
                    "protocol": e_item["label"] or "HTTPS",
                    "data": e_item["label"] or "Data flow",
                    "authentication": "Workload Identity / mTLS",
                    "encryption": "TLS 1.3",
                    "trust_boundary_crossing": True,
                    "requirement_ids": default_reqs,
                },
            })
            new_layout["edge_labels"][eid] = e_item["label"] or "HTTPS"
            if e_item["style"]:
                new_layout["edge_styles"][eid] = e_item["style"]
            current_edges[eid] = {"id": eid, "source": src_arch, "target": tgt_arch}

    patch = {
        "summary": f"Imported diagram edits from draw.io ({len(imported_nodes)} nodes, {len(operations)} graph changes).",
        "operations": operations,
        "source": "drawio_upload",
        "generated_at": utc_now(),
    }
    candidate = apply_patch(current_architecture, patch)
    return candidate, new_layout, patch, stamp_drawio_xml(xml_text, canonical_hash(candidate), 0)


def stamp_drawio_xml(xml_text: str, architecture_hash: str, version: int) -> str:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise WorkflowError(f"Could not stamp uploaded draw.io XML: {error}") from error
    if root.tag == "mxfile":
        root.set("archHash", architecture_hash)
        if version:
            root.set("reviewVersion", str(version))
        root.set("modified", utc_now())
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def drawio_xml_for_viewer(xml_text: str) -> str:
    """Return an uncompressed mxfile so the official viewer shows every cell."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise WorkflowError(f"Could not prepare the draw.io preview: {error}") from error
    if root.tag == "mxGraphModel":
        model = root
        root = ET.Element("mxfile", {"host": "app.diagrams.net", "compressed": "false"})
        diagram = ET.SubElement(root, "diagram", {"id": "review-preview", "name": "Preview"})
        diagram.append(model)
    elif root.tag == "mxfile":
        for diagram in root.findall("diagram"):
            if diagram.find("mxGraphModel") is not None:
                continue
            encoded = (diagram.text or "").strip()
            if not encoded:
                continue
            try:
                decoded = urllib.parse.unquote(
                    zlib.decompress(__import__("base64").b64decode(encoded), -15).decode("utf-8")
                )
                diagram.text = None
                diagram.append(ET.fromstring(decoded))
            except Exception as error:
                raise WorkflowError(
                    "Could not decode a compressed draw.io page for the exact UI preview."
                ) from error
        root.set("compressed", "false")
    else:
        raise WorkflowError("The draw.io preview must contain an mxfile or mxGraphModel root.")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def create_drawio_viewer_html(xml_text: str, fallback_png_url: str) -> str:
    """Build an isolated, read-only HTML preview from the actual draw.io XML."""
    viewer_config = {
        "highlight": "#0067b8",
        "lightbox": False,
        "nav": True,
        "resize": True,
        "toolbar": "pages zoom layers tags lightbox",
        "dark-mode": "auto",
        "xml": drawio_xml_for_viewer(xml_text),
    }
    config_attribute = html.escape(
        json.dumps(viewer_config, ensure_ascii=False, separators=(",", ":")),
        quote=True,
    )
    safe_fallback = html.escape(fallback_png_url, quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Exact draw.io preview</title>
  <style>
    html,body {{ margin:0; min-height:100%; font-family:Segoe UI,Arial,sans-serif; background:#f8fbff; color:#334155; }}
    #loading {{ position:fixed; z-index:2; top:12px; left:12px; padding:8px 11px; border-radius:7px; background:#eef6ff; border:1px solid #bdd7ee; font-size:13px; }}
    .mxgraph {{ width:100%; min-height:700px; border:0; background:white; }}
    #fallback {{ display:none; padding:20px; text-align:center; }}
    #fallback img {{ display:block; max-width:100%; max-height:650px; margin:12px auto 0; border:1px solid #d8e0ea; background:white; }}
  </style>
</head>
<body>
  <div id="loading">Loading the exact uploaded draw.io file…</div>
  <div class="mxgraph" data-mxgraph="{config_attribute}"></div>
  <div id="fallback">
    <b>The exact draw.io viewer could not load.</b><br>
    <span>Check the internet connection. The generated PNG fallback is shown below.</span>
    <img src="{safe_fallback}" alt="Generated PNG fallback">
  </div>
  <script>
    (function () {{
      const loading=document.getElementById('loading');
      const fallback=document.getElementById('fallback');
      let attempts=0;
      function check() {{
        const rendered=document.querySelector('.mxgraph svg,.mxgraph canvas');
        if (rendered) {{ loading.style.display='none'; fallback.style.display='none'; return; }}
        attempts += 1;
        if (attempts >= 30) {{ loading.style.display='none'; fallback.style.display='block'; return; }}
        setTimeout(check, 250);
      }}
      window.addEventListener('load', check);
      window.addEventListener('error', function () {{ loading.style.display='none'; fallback.style.display='block'; }});
    }})();
  </script>
  <script src="https://viewer.diagrams.net/js/viewer-static.min.js"></script>
</body>
</html>"""


def load_state() -> dict[str, Any]:
    return load_json(STATE_FILE, "review state")


def current_artifacts(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    architecture_path = BASE_DIR / state["current_files"]["architecture"]
    layout_path = BASE_DIR / state["current_files"]["layout"]
    return (
        load_json(architecture_path, "current review architecture"),
        load_json(layout_path, "current review layout"),
    )


def version_paths(version: int) -> dict[str, Path]:
    return {
        "architecture": REVIEW_DIR / f"architecture_review_v{version}.json",
        "drawio": REVIEW_DIR / f"architecture_review_v{version}.drawio",
        "png": REVIEW_DIR / f"architecture_review_v{version}.png",
        "layout": REVIEW_DIR / f"drawio_layout_v{version}.json",
        "diff": REVIEW_DIR / f"diff_to_v{version}.json",
        "patch": REVIEW_DIR / f"patch_v{version}.json",
        "unintended": REVIEW_DIR / f"unintended_change_report_v{version}.json",
        "validation": REVIEW_DIR / f"validation_v{version}.json",
        "coverage": REVIEW_DIR / f"coverage_v{version}.json",
    }


def preview_paths() -> dict[str, Path]:
    """Stable temporary paths used before the reviewer accepts a proposal."""
    return {
        "architecture": REVIEW_DIR / "pending_preview_architecture.json",
        "drawio": REVIEW_DIR / "pending_preview.drawio",
        "png": REVIEW_DIR / "pending_preview.png",
        "layout": REVIEW_DIR / "pending_preview_layout.json",
        "diff": REVIEW_DIR / "pending_preview_diff.json",
        "patch": REVIEW_DIR / "pending_preview_patch.json",
        "unintended": REVIEW_DIR / "pending_preview_unintended.json",
        "validation": REVIEW_DIR / "pending_preview_validation.json",
        "coverage": REVIEW_DIR / "pending_preview_coverage.json",
    }


def pending_artifacts(
    state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    pending = state.get("pending_preview")
    if not isinstance(pending, dict):
        raise WorkflowError("There is no uploaded or AI-generated preview to review.")
    files = pending.get("files", {})
    architecture = load_json(
        BASE_DIR / files["architecture"], "pending preview architecture"
    )
    layout = load_json(BASE_DIR / files["layout"], "pending preview layout")
    patch = load_json(BASE_DIR / files["patch"], "pending preview patch")
    return architecture, layout, patch


def initialize_review(force_reset: bool = False) -> dict[str, Any]:
    with WRITE_LOCK:
        architecture = load_json(ARCHITECTURE_FILE, "source architecture")
        architecture_hash = canonical_hash(architecture)
        
        if not force_reset and STATE_FILE.exists():
            state = load_state()
            if state.get("source_hash") == architecture_hash:
                if not state.get("approved"):
                    for stale_file in (
                        REVIEW_DIR / "approval.json",
                        REVIEW_DIR / "approved_architecture.json",
                        REVIEW_DIR / "approved_architecture.drawio",
                        REVIEW_DIR / "approved_architecture.png",
                    ):
                        stale_file.unlink(missing_ok=True)
                try:
                    current_artifacts(state)
                    return state
                except WorkflowError:
                    pass

        for stale_file in (
            REVIEW_DIR / "approval.json",
            REVIEW_DIR / "approved_architecture.json",
            REVIEW_DIR / "approved_architecture.drawio",
            REVIEW_DIR / "approved_architecture.png",
        ):
            stale_file.unlink(missing_ok=True)

        architecture = load_json(ARCHITECTURE_FILE, "source architecture")
        requirements = load_json(REQUIREMENTS_FILE, "requirements")
        presentation = load_optional_presentation(architecture)
        errors, warnings = validate_architecture(architecture, requirements)
        if errors:
            raise WorkflowError(
                "Source architecture validation failed:\n- " + "\n- ".join(errors)
            )
        version = 1
        paths = version_paths(version)
        layout = build_layout(architecture, presentation)
        architecture_hash = canonical_hash(architecture)
        initial_patch = {
            "summary": "Initial review version copied from outputs/architecture_v1.json.",
            "operations": [],
            "source": "initialization",
            "generated_at": utc_now(),
        }
        initial_diff = architecture_diff(architecture, architecture)
        unintended = detect_unintended_changes(initial_patch, initial_diff)
        coverage = calculate_coverage(architecture, requirements)
        write_json(paths["architecture"], architecture)
        write_json(paths["layout"], layout)
        write_text(
            paths["drawio"],
            create_drawio_xml(architecture, presentation, layout, architecture_hash, version),
        )
        render_png(paths["png"], architecture, presentation, layout, version)
        write_json(paths["diff"], initial_diff)
        write_json(paths["patch"], initial_patch)
        write_json(paths["unintended"], unintended)
        write_json(paths["validation"], {"valid": True, "errors": [], "warnings": warnings})
        write_json(paths["coverage"], coverage)
        state = {
            "schema_version": "1.0",
            "workflow": "Milestone 6B-2 Architecture Review",
            "source_architecture": relative_path(ARCHITECTURE_FILE),
            "source_hash": architecture_hash,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "status": "PENDING_REVIEW",
            "current_version": version,
            "current_hash": architecture_hash,
            "approved": False,
            "approved_hash": None,
            "current_files": {key: relative_path(value) for key, value in paths.items()},
            "validation": {"valid": True, "errors": [], "warnings": warnings},
            "coverage": coverage,
            "unintended_change_check": unintended,
            "latest_diff_summary": initial_diff["summary"],
            "versions": [
                {
                    "version": version,
                    "hash": architecture_hash,
                    "created_at": utc_now(),
                    "source": "initialization",
                    "summary": initial_patch["summary"],
                    "files": {key: relative_path(value) for key, value in paths.items()},
                }
            ],
            "events": [
                {
                    "at": utc_now(),
                    "event": "REVIEW_STARTED",
                    "detail": "Created editable PNG and draw.io artifacts from the validated architecture.",
                }
            ],
        }
        write_json(STATE_FILE, state)
        sync_downstream_artifacts()
        return state


def stage_candidate_preview(
    candidate: dict[str, Any],
    layout: dict[str, Any],
    patch: dict[str, Any],
    source: str,
    uploaded_drawio: str | None = None,
    custom_png_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate and display a proposal without creating a real version."""
    with WRITE_LOCK:
        state = initialize_review()
        accepted_architecture, _ = current_artifacts(state)
        requirements = load_json(REQUIREMENTS_FILE, "requirements")
        presentation = load_optional_presentation(candidate)
        errors, warnings = validate_architecture(candidate, requirements)
        if errors:
            raise WorkflowError(
                "Preview validation failed. The accepted architecture was not changed:\n- "
                + "\n- ".join(errors)
            )
        diff = architecture_diff(accepted_architecture, candidate)
        unintended = detect_unintended_changes(patch, diff)
        if not unintended["safe"]:
            raise WorkflowError(
                "Preview failed the unintended-change check. The accepted architecture was not changed:\n- "
                + "\n- ".join(unintended["unexpected_changes"])
            )

        proposed_version = int(state["current_version"]) + 1
        paths = preview_paths()
        candidate_hash = canonical_hash(candidate)
        coverage = calculate_coverage(candidate, requirements)
        write_json(paths["architecture"], candidate)
        write_json(paths["layout"], layout)
        drawio = (
            stamp_drawio_xml(uploaded_drawio, candidate_hash, proposed_version)
            if uploaded_drawio
            else create_drawio_xml(
                candidate,
                presentation,
                layout,
                candidate_hash,
                proposed_version,
            )
        )
        write_text(paths["drawio"], drawio)
        if custom_png_bytes:
            paths["png"].parent.mkdir(parents=True, exist_ok=True)
            paths["png"].write_bytes(custom_png_bytes)
        else:
            render_png(paths["png"], candidate, presentation, layout, proposed_version)
        write_json(paths["diff"], diff)
        write_json(paths["patch"], patch)
        write_json(paths["unintended"], unintended)
        write_json(
            paths["validation"],
            {"valid": True, "errors": [], "warnings": warnings},
        )
        write_json(paths["coverage"], coverage)

        state["status"] = "PREVIEW_READY"
        state["updated_at"] = utc_now()
        state["pending_preview"] = {
            "base_version": state["current_version"],
            "base_hash": state["current_hash"],
            "proposed_version": proposed_version,
            "proposed_hash": candidate_hash,
            "created_at": utc_now(),
            "source": source,
            "custom_image": bool(custom_png_bytes),
            "summary": patch.get("summary", "Change preview ready."),
            "files": {key: relative_path(value) for key, value in paths.items()},
            "validation": {"valid": True, "errors": [], "warnings": warnings},
            "coverage": coverage,
            "unintended_change_check": unintended,
            "diff_summary": diff["summary"],
        }
        state.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": "PREVIEW_CREATED",
                "detail": (
                    f"Prepared version {proposed_version} preview from {source}. "
                    "No accepted architecture version was created."
                ),
            }
        )
        write_json(STATE_FILE, state)
        return state


def create_candidate_version(
    candidate: dict[str, Any],
    layout: dict[str, Any],
    patch: dict[str, Any],
    source: str,
    uploaded_drawio: str | None = None,
    custom_png_bytes: bytes | None = None,
) -> dict[str, Any]:
    with WRITE_LOCK:
        state = initialize_review()
        before, _ = current_artifacts(state)
        requirements = load_json(REQUIREMENTS_FILE, "requirements")
        presentation = load_optional_presentation(candidate)
        errors, warnings = validate_architecture(candidate, requirements)
        if errors:
            raise WorkflowError(
                "Candidate architecture validation failed. Nothing was saved:\n- "
                + "\n- ".join(errors)
            )
        diff = architecture_diff(before, candidate)
        unintended = detect_unintended_changes(patch, diff)
        if not unintended["safe"]:
            raise WorkflowError(
                "Unintended-change check failed. Nothing was saved:\n- "
                + "\n- ".join(unintended["unexpected_changes"])
            )
        version = int(state["current_version"]) + 1
        paths = version_paths(version)
        candidate_hash = canonical_hash(candidate)
        coverage = calculate_coverage(candidate, requirements)
        write_json(paths["architecture"], candidate)
        write_json(paths["layout"], layout)
        drawio = (
            stamp_drawio_xml(uploaded_drawio, candidate_hash, version)
            if uploaded_drawio
            else create_drawio_xml(candidate, presentation, layout, candidate_hash, version)
        )
        write_text(paths["drawio"], drawio)
        if custom_png_bytes:
            paths["png"].parent.mkdir(parents=True, exist_ok=True)
            paths["png"].write_bytes(custom_png_bytes)
        else:
            render_png(paths["png"], candidate, presentation, layout, version)
        write_json(paths["diff"], diff)
        write_json(paths["patch"], patch)
        write_json(paths["unintended"], unintended)
        write_json(paths["validation"], {"valid": True, "errors": [], "warnings": warnings})
        write_json(paths["coverage"], coverage)

        # Keep architecture_v1.json, presentation_v1.json, and coverage_report.json synchronized with accepted version
        write_json(ARCHITECTURE_FILE, candidate)
        write_json(PRESENTATION_FILE, presentation)
        try:
            import coverage_report
            coverage_report.main()
        except Exception:
            pass

        state["source_hash"] = candidate_hash
        state["updated_at"] = utc_now()
        state["status"] = "PENDING_REVIEW"
        state["current_version"] = version
        state["current_hash"] = candidate_hash
        state["approved"] = False
        state["approved_hash"] = None
        state.pop("pending_preview", None)
        state["current_files"] = {key: relative_path(value) for key, value in paths.items()}
        state["validation"] = {"valid": True, "errors": [], "warnings": warnings}
        state["coverage"] = coverage
        state["unintended_change_check"] = unintended
        state["latest_diff_summary"] = diff["summary"]
        state.setdefault("versions", []).append(
            {
                "version": version,
                "hash": candidate_hash,
                "created_at": utc_now(),
                "source": source,
                "summary": patch.get("summary", "Architecture candidate updated."),
                "files": {key: relative_path(value) for key, value in paths.items()},
            }
        )
        state.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": "CANDIDATE_CREATED",
                "detail": f"Created review version {version} from {source}.",
            }
        )
        write_json(STATE_FILE, state)
        sync_downstream_artifacts()
        return state


def import_drawio(xml_text: str, filename: str) -> dict[str, Any]:
    with WRITE_LOCK:
        state = initialize_review()
        architecture, layout = current_artifacts(state)
        candidate, imported_layout, patch, stamped = parse_drawio_upload(
            xml_text,
            architecture,
            layout,
            str(state["current_hash"]),
        )
        patch["uploaded_filename"] = filename
        return stage_candidate_preview(
            candidate,
            imported_layout,
            patch,
            "drawio_upload",
            uploaded_drawio=stamped,
        )


def apply_feedback(feedback: str) -> dict[str, Any]:
    with WRITE_LOCK:
        state = initialize_review()
        if state.get("pending_preview"):
            architecture, layout, earlier_patch = pending_artifacts(state)
            source = "preview_plus_typed_feedback"
        else:
            architecture, layout = current_artifacts(state)
            earlier_patch = {
                "summary": "",
                "operations": [],
                "source": "accepted_architecture",
            }
            source = "typed_feedback"
        requirements = load_json(REQUIREMENTS_FILE, "requirements")
        try:
            ai_patch = request_patch_from_ollama(feedback, architecture, requirements)
            # If Ollama added a node without any connecting edge, wire it automatically
            ops = ai_patch.get("operations", [])
            added_nodes = [op.get("node") for op in ops if isinstance(op, dict) and op.get("op") == "ADD_NODE" and isinstance(op.get("node"), dict)]
            has_add_edge = any(isinstance(op, dict) and op.get("op") == "ADD_EDGE" for op in ops)
            if added_nodes and not has_add_edge and architecture.get("nodes"):
                primary = architecture["nodes"][0]
                for an in added_nodes:
                    an_id = str(an.get("id", ""))
                    if an_id:
                        ops.append({
                            "op": "ADD_EDGE",
                            "edge": {
                                "id": f"{primary['id']}->{an_id}",
                                "source": str(primary["id"]),
                                "target": an_id,
                                "protocol": "HTTPS",
                                "data": f"Integration flow to {an.get('name', an_id)}",
                                "authentication": "Workload Identity / mTLS",
                                "encryption": "TLS 1.3",
                                "trust_boundary_crossing": True,
                                "requirement_ids": [],
                            },
                        })
        except Exception:
            ai_patch = build_smart_nl_patch(feedback, architecture, requirements)

        if not ai_patch.get("operations"):
            ai_patch = build_smart_nl_patch(feedback, architecture, requirements)

        candidate = apply_patch(architecture, ai_patch)
        presentation = load_optional_presentation(candidate)
        patch = {
            "summary": (
                f"{ai_patch.get('summary', 'AI change preview ready.')}"
            ),
            "operations": copy.deepcopy(earlier_patch.get("operations", []))
            + copy.deepcopy(ai_patch.get("operations", [])),
            "source": source,
            "reviewer_feedback": feedback,
            "model": OLLAMA_MODEL,
            "generated_at": utc_now(),
        }
        updated_layout = build_layout(candidate, presentation, previous=layout)
        return stage_candidate_preview(candidate, updated_layout, patch, source)


def accept_preview() -> dict[str, Any]:
    """Commit the exact proposal currently visible in the UI as a new version."""
    with WRITE_LOCK:
        state = initialize_review()
        pending = state.get("pending_preview")
        if not isinstance(pending, dict):
            raise WorkflowError("There is no change preview to accept.")
        if pending.get("base_version") != state.get("current_version"):
            raise WorkflowError(
                "The accepted architecture version changed after this preview was created. "
                "Discard the preview and create it again from the current version."
            )
        if pending.get("base_hash") != state.get("current_hash"):
            raise WorkflowError(
                "The accepted architecture hash changed after this preview was created. "
                "Discard the preview and create it again."
            )
        candidate, layout, patch = pending_artifacts(state)
        drawio_path = BASE_DIR / pending["files"]["drawio"]
        try:
            drawio = drawio_path.read_text(encoding="utf-8")
        except OSError as error:
            raise WorkflowError(f"Could not read pending draw.io preview: {error}") from error

        custom_png_bytes = None
        if pending.get("custom_image"):
            png_path = BASE_DIR / pending["files"]["png"]
            if png_path.exists():
                custom_png_bytes = png_path.read_bytes()

        source = str(pending.get("source") or "accepted_preview")
        accepted = create_candidate_version(
            candidate,
            layout,
            patch,
            source,
            uploaded_drawio=drawio if source == "drawio_upload" else None,
            custom_png_bytes=custom_png_bytes,
        )
        accepted.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": "PREVIEW_ACCEPTED",
                "detail": (
                    f"Reviewer accepted the preview as version "
                    f"{accepted['current_version']}."
                ),
            }
        )
        write_json(STATE_FILE, accepted)
        return accepted


def discard_preview() -> dict[str, Any]:
    """Return to the latest accepted architecture without creating a version."""
    with WRITE_LOCK:
        state = initialize_review()
        pending = state.pop("pending_preview", None)
        if not isinstance(pending, dict):
            raise WorkflowError("There is no change preview to discard.")
        state["status"] = "APPROVED" if state.get("approved") else "PENDING_REVIEW"
        state["updated_at"] = utc_now()
        state.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": "PREVIEW_DISCARDED",
                "detail": (
                    f"Discarded proposed version {pending.get('proposed_version')}. "
                    "No architecture version was created."
                ),
            }
        )
        write_json(STATE_FILE, state)
        return state


def approve_current(reviewer: str, confirmed: bool) -> dict[str, Any]:
    if not confirmed:
        raise WorkflowError("Tick the confirmation box before approving.")
    reviewer = reviewer.strip() or "Human Reviewer"
    with WRITE_LOCK:
        state = initialize_review()
        if state.get("pending_preview"):
            raise WorkflowError(
                "Approval is blocked while a change preview is open. "
                "Accept or discard the preview first."
            )
        architecture, layout = current_artifacts(state)
        requirements = load_json(REQUIREMENTS_FILE, "requirements")
        presentation = load_optional_presentation(architecture)
        errors, warnings = validate_architecture(architecture, requirements)
        if errors:
            raise WorkflowError("Approval blocked by validation errors:\n- " + "\n- ".join(errors))
        unintended = state.get("unintended_change_check", {})
        if not unintended.get("safe"):
            raise WorkflowError("Approval blocked because unintended changes were detected.")
        current_hash = canonical_hash(architecture)
        state["current_hash"] = current_hash

        approved_architecture = REVIEW_DIR / "approved_architecture.json"
        approved_drawio = REVIEW_DIR / "approved_architecture.drawio"
        approved_png = REVIEW_DIR / "approved_architecture.png"
        write_json(approved_architecture, architecture)
        write_text(
            approved_drawio,
            create_drawio_xml(
                architecture,
                presentation,
                layout,
                current_hash,
                int(state["current_version"]),
            ),
        )
        current_png_path = BASE_DIR / state["current_files"]["png"]
        if current_png_path.exists():
            approved_png.write_bytes(current_png_path.read_bytes())
        else:
            render_png(
                approved_png,
                architecture,
                presentation,
                layout,
                int(state["current_version"]),
            )
        approval = {
            "approved": True,
            "status": "APPROVED_AND_SIGNED",
            "reviewer": reviewer,
            "approved_at": utc_now(),
            "architecture_version": state["current_version"],
            "architecture_hash_algorithm": "SHA-256",
            "architecture_hash": current_hash,
            "source_architecture": state["current_files"]["architecture"],
            "approved_architecture": relative_path(approved_architecture),
            "coverage": state.get("coverage", {}),
            "validation_warnings": warnings,
            "gate_rule": "DFD/STRIDE may continue only when review_state.approved is true and the approved file hash matches architecture_hash.",
        }
        write_json(REVIEW_DIR / "approval.json", approval)
        history_path = REVIEW_DIR / "approval_history.json"
        history = []
        if history_path.exists():
            try:
                existing = json.loads(history_path.read_text(encoding="utf-8"))
                if isinstance(existing, list):
                    history = existing
            except (OSError, json.JSONDecodeError):
                history = []
        history.append(approval)
        write_json(history_path, history)
        state["status"] = "APPROVED"
        state["approved"] = True
        state["approved_hash"] = current_hash
        state["approved_at"] = approval["approved_at"]
        state["approved_by"] = reviewer
        state["approved_files"] = {
            "architecture": relative_path(approved_architecture),
            "drawio": relative_path(approved_drawio),
            "png": relative_path(approved_png),
            "approval": relative_path(REVIEW_DIR / "approval.json"),
        }
        state["updated_at"] = utc_now()
        state.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": "ARCHITECTURE_APPROVED",
                "detail": f"{reviewer} approved version {state['current_version']} with hash {current_hash[:12]}...",
            }
        )
        write_json(STATE_FILE, state)
        sync_downstream_artifacts()
        return state


def request_changes(note: str) -> dict[str, Any]:
    note = note.strip()
    if not note:
        raise WorkflowError("Write the requested change before selecting Request Changes.")
    with WRITE_LOCK:
        state = initialize_review()
        state["status"] = "CHANGES_REQUESTED"
        state["approved"] = False
        state["approved_hash"] = None
        state["updated_at"] = utc_now()
        state.setdefault("events", []).append(
            {"at": utc_now(), "event": "CHANGES_REQUESTED", "detail": note}
        )
        write_json(STATE_FILE, state)
        return state


def public_state(state: dict[str, Any]) -> dict[str, Any]:
    accepted_version = int(state["current_version"])
    pending = state.get("pending_preview")
    has_pending = isinstance(pending, dict)
    if has_pending:
        files = pending["files"]
        architecture = load_json(
            BASE_DIR / files["architecture"], "pending preview architecture"
        )
        display_version = int(pending["proposed_version"])
        display_hash = pending["proposed_hash"]
        validation = pending["validation"]
        coverage = pending["coverage"]
        unintended = pending["unintended_change_check"]
        diff_summary = pending["diff_summary"]
        latest_summary = pending.get("summary", "Change preview ready.")
    else:
        current_path = BASE_DIR / state["current_files"]["architecture"]
        architecture = load_json(current_path, "current review architecture")
        display_version = accepted_version
        display_hash = state.get("current_hash")
        validation = state.get("validation", {})
        coverage = state.get("coverage", {})
        unintended = state.get("unintended_change_check", {})
        diff_summary = state.get("latest_diff_summary", {})
        latest_version = state.get("versions", [])[-1] if state.get("versions") else {}
        latest_summary = latest_version.get("summary", "")
    return {
        "workflow": state.get("workflow"),
        "status": state.get("status"),
        "approved": state.get("approved", False),
        "has_pending_preview": has_pending,
        "accepted_version": accepted_version,
        "current_version": display_version,
        "display_version": (
            f"v{display_version} PREVIEW" if has_pending else f"v{display_version}"
        ),
        "current_hash": state.get("current_hash"),
        "display_hash": display_hash,
        "approved_hash": state.get("approved_hash"),
        "pending_source": pending.get("source") if has_pending else None,
        "pending_summary": pending.get("summary") if has_pending else None,
        "architecture_name": architecture.get("architecture_name", "Unknown"),
        "architecture_status": architecture.get("status", "Unknown"),
        "nodes": len(architecture.get("nodes", [])),
        "edges": len(architecture.get("edges", [])),
        "trust_zones": len(architecture.get("trust_zones", [])),
        "validation": validation,
        "coverage": coverage,
        "unintended_change_check": unintended,
        "latest_diff_summary": diff_summary,
        "latest_summary": latest_summary,
        "updated_at": state.get("updated_at"),
        "events": state.get("events", [])[-12:],
        "downloads": {
            "viewer": "/artifact/current-viewer.html",
            "png": "/artifact/current.png",
            "drawio": "/artifact/current.drawio",
            "architecture": "/artifact/current.json",
            "diff": "/artifact/diff.json",
            "approval": "/artifact/approval.json" if state.get("approved") else None,
        },
    }


HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Architecture Review — AI Threat Modeling G3</title>
  <style>
    :root { --blue:#0067b8; --ink:#172033; --muted:#5f6b7a; --line:#d8e0ea; --bg:#f3f7fb; --ok:#087830; --warn:#9a6700; --bad:#b42318; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:Segoe UI,Arial,sans-serif; color:var(--ink); background:var(--bg); }
    header { background:linear-gradient(125deg,#063970,#0078d4); color:white; padding:24px 34px; }
    header h1 { margin:0 0 5px; font-size:25px; }
    header p { margin:0; opacity:.9; }
    main { max-width:1480px; margin:22px auto; padding:0 20px 40px; }
    .grid { display:grid; grid-template-columns:1fr 360px; gap:18px; }
    .card { background:white; border:1px solid var(--line); border-radius:13px; box-shadow:0 5px 18px rgba(31,50,80,.07); padding:18px; margin-bottom:18px; }
    .card h2 { font-size:17px; margin:0 0 13px; }
    .diagram-frame { width:100%; height:740px; border:1px solid var(--line); border-radius:9px; background:#f8fbff; }
    .diagram-fallback { width:100%; max-height:720px; object-fit:contain; border:1px solid var(--line); border-radius:9px; background:#f8fbff; }
    .stats { display:grid; grid-template-columns:repeat(3,1fr); gap:9px; }
    .stat { background:#f6f9fc; border-radius:8px; padding:10px; }
    .stat b { display:block; font-size:20px; }
    .status { display:inline-block; padding:5px 10px; border-radius:999px; font-weight:700; font-size:12px; background:#fff4ce; color:#704d00; }
    .status.APPROVED { background:#dff6dd; color:#0b6a0b; }
    .status.CHANGES_REQUESTED { background:#fde7e9; color:#a4262c; }
    .status.PREVIEW_READY { background:#deecf9; color:#004578; }
    button,.button { border:0; border-radius:8px; padding:10px 13px; font-weight:650; cursor:pointer; text-decoration:none; display:inline-block; background:var(--blue); color:white; margin:4px 3px 4px 0; }
    button.secondary,.button.secondary { background:#eef3f8; color:#17365d; border:1px solid #c9d5e2; }
    button.approve { background:#107c10; }
    button.reject { background:#a4262c; }
    button:disabled { opacity:.55; cursor:wait; }
    textarea,input[type=text] { width:100%; border:1px solid #bac7d5; border-radius:8px; padding:10px; font:inherit; }
    textarea { min-height:105px; resize:vertical; }
    label { display:block; font-weight:650; margin:10px 0 6px; }
    .small { color:var(--muted); font-size:13px; line-height:1.45; }
    .notice { padding:11px; border-radius:8px; margin:10px 0; background:#eef6ff; color:#174a7c; }
    .notice.ok { background:#e8f7e8; color:#0b621f; }
    .notice.bad { background:#fdebec; color:#9b1c1c; }
    .hash { font-family:Consolas,monospace; font-size:11px; word-break:break-all; color:#506176; }
    ul { padding-left:20px; }
    .event { border-left:3px solid #9bb9d8; padding:4px 0 4px 10px; margin:8px 0; font-size:12px; }
    .spinner { display:none; margin-left:8px; }
    .busy .spinner { display:inline; }
    @media (max-width:900px) { .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<header>
  <h1>Architecture Review & Approval</h1>
  <p>Milestone 6B-2 · Editable draw.io + PNG · Controlled changes · Human approval</p>
</header>
<main>
  <div id="message" class="notice">Loading review state…</div>
  <div class="grid">
    <section>
      <div class="card">
        <h2 id="architectureName">Architecture</h2>
        <div id="previewBanner" class="notice" style="display:none"></div>
        <iframe id="diagramFrame" class="diagram-frame" title="Exact current draw.io architecture preview" sandbox="allow-scripts allow-popups"></iframe>
        <p class="small">Exact preview: the page loads draw.io's official viewer script from <code>viewer.diagrams.net</code>. Internet access is required; use the PNG fallback below if company policy blocks it.</p>
        <details style="margin-top:10px">
          <summary class="small">Show generated PNG fallback</summary>
          <img id="diagramFallback" class="diagram-fallback" alt="Generated PNG fallback">
        </details>
        <div style="margin-top:12px">
          <a id="downloadPng" class="button" href="#">Download PNG</a>
          <a id="downloadDrawio" class="button secondary" href="#">Download editable draw.io</a>
          <a id="downloadJson" class="button secondary" href="#">Download architecture JSON</a>
          <a id="downloadDiff" class="button secondary" href="#">Download diff</a>
        </div>
      </div>
      <div id="previewDecision" class="card" style="display:none">
        <h2>Decide about this preview</h2>
        <p class="small">The edited diagram is visible above, but no real architecture version has been created yet.</p>
        <button class="approve" onclick="acceptPreview()">Accept preview and create version</button>
        <button class="reject" onclick="discardPreview()">Discard preview</button>
      </div>
      <div class="card">
        <h2>Upload your edited draw.io file</h2>
        <p class="small">Open the downloaded file in diagrams.net, edit it, save it, then upload it here. The exact uploaded draw.io XML—including moved boxes, colors, notes, icons, and other presentation edits—is shown above. Architecture additions/deletions must still use typed feedback so connections are validated.</p>
        <input id="drawioFile" type="file" accept=".drawio,.xml,text/xml,application/xml">
        <button id="uploadButton" onclick="uploadDrawio()">Upload and preview changes</button>
      </div>
      <div class="card">
        <h2>Request a controlled architecture change</h2>
        <p class="small">Example: “Add a Redis cache between Backend Services and Azure SQL Database. Keep every unrelated component unchanged.” This uses your local Ollama qwen3:4b model.</p>
        <textarea id="feedback" placeholder="Describe only the architecture change you want…"></textarea>
        <button id="feedbackButton" onclick="applyFeedback()">Create AI change preview</button>
        <button class="reject" onclick="requestChanges()">Request Changes</button>
      </div>
    </section>
    <aside>
      <div class="card">
        <h2>Review status</h2>
        <span id="status" class="status">PENDING</span>
        <div class="stats" style="margin-top:13px">
          <div class="stat"><span class="small">Version</span><b id="version">–</b></div>
          <div class="stat"><span class="small">Nodes</span><b id="nodes">–</b></div>
          <div class="stat"><span class="small">Flows</span><b id="edges">–</b></div>
        </div>
        <label>Displayed architecture SHA-256 hash</label>
        <div id="hash" class="hash">–</div>
      </div>
      <div class="card">
        <h2>Safety & Threat Checks</h2>
        <div id="validation">–</div>
        <div id="unintended">–</div>
        <div id="coverage">–</div>
        <div id="threats">–</div>
        <h2 style="margin-top:18px">Latest architecture diff</h2>
        <ul id="diff"></ul>
      </div>
      <div class="card">
        <h2>Human approval gate</h2>
        <label for="reviewer">Reviewer name</label>
        <input id="reviewer" type="text" placeholder="Human Reviewer">
        <label style="font-weight:400"><input id="confirmed" type="checkbox"> I reviewed the diagram, structural diff, validation result, and requirement coverage gaps.</label>
        <button id="approveButton" class="approve" onclick="approveArchitecture()">Approve exact version</button>
        <p class="small">DFD/STRIDE must use only <code>approved_architecture.json</code> whose hash matches the approval record.</p>
      </div>
      <div class="card">
        <h2>Recent activity</h2>
        <div id="events"></div>
      </div>
    </aside>
  </div>
</main>
<script>
let state = null;
const message = document.getElementById('message');
function esc(value) { const node=document.createElement('span'); node.textContent=String(value); return node.innerHTML; }
function setBusy(value, text='Working…') {
  document.body.classList.toggle('busy', value);
  document.querySelectorAll('button').forEach(button => button.disabled=value);
  if (!value && state) document.getElementById('approveButton').disabled=state.has_pending_preview;
  if (value) { message.className='notice'; message.textContent=text; }
}
function show(text, type='ok') { message.className='notice '+type; message.textContent=text; }
async function api(path, body) {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function loadState(successMessage='Review workflow is ready.') {
  const response = await fetch('/api/state?time='+Date.now());
  const result = await response.json();
  if (!result.ok) throw new Error(result.error || 'Could not load review state');
  state=result.state; render(); show(successMessage,'ok');
}
function render() {
  document.getElementById('architectureName').textContent=state.architecture_name;
  const status=document.getElementById('status'); status.textContent=state.status.replaceAll('_',' '); status.className='status '+state.status;
  document.getElementById('version').textContent=state.display_version;
  document.getElementById('nodes').textContent=state.nodes;
  document.getElementById('edges').textContent=state.edges;
  document.getElementById('hash').textContent=state.display_hash;
  const refresh='?hash='+encodeURIComponent(state.display_hash)+'&t='+Date.now();
  document.getElementById('diagramFrame').src=state.downloads.viewer+refresh;
  document.getElementById('diagramFallback').src=state.downloads.png+refresh;
  document.getElementById('downloadPng').href=state.downloads.png;
  document.getElementById('downloadDrawio').href=state.downloads.drawio;
  document.getElementById('downloadJson').href=state.downloads.architecture;
  document.getElementById('downloadDiff').href=state.downloads.diff;
  const decision=document.getElementById('previewDecision');
  const banner=document.getElementById('previewBanner');
  decision.style.display=state.has_pending_preview ? 'block' : 'none';
  banner.style.display=state.has_pending_preview ? 'block' : 'none';
  if (state.has_pending_preview) banner.innerHTML='<b>Preview only:</b> these uploaded/AI changes are shown now, but accepted version v'+esc(state.accepted_version)+' is still unchanged. Accept or discard this preview below.';
  document.getElementById('approveButton').disabled=state.has_pending_preview;
  document.getElementById('validation').innerHTML=state.validation.valid ? '<div class="notice ok">✓ Architecture validation passed</div>' : '<div class="notice bad">✗ Validation failed</div>';
  document.getElementById('unintended').innerHTML=state.unintended_change_check.safe ? '<div class="notice ok">✓ No unintended graph changes</div>' : '<div class="notice bad">✗ Unintended changes detected</div>';
  const coverage=state.coverage;
  document.getElementById('coverage').innerHTML='<div class="notice">Requirement coverage: <b>'+esc(coverage.coverage_percentage)+'%</b><br><span class="small">'+esc(coverage.covered_requirements)+' of '+esc(coverage.total_requirements)+' covered; '+esc(coverage.missing_requirements)+' missing</span></div>';
  const threats=state.threat_summary;
  document.getElementById('threats').innerHTML='<div class="notice">STRIDE Threats Identified: <b>'+esc(threats.total_threats || 0)+'</b><br><span class="small">'+esc(threats.high_severity || 0)+' High, '+esc(threats.medium_severity || 0)+' Medium, '+esc(threats.low_severity || 0)+' Low</span></div>';
  const diff=state.latest_diff_summary;
  document.getElementById('diff').innerHTML=[
    'Nodes added: '+diff.nodes_added, 'Nodes removed: '+diff.nodes_removed, 'Nodes modified: '+diff.nodes_modified,
    'Flows added: '+diff.edges_added, 'Flows removed: '+diff.edges_removed, 'Flows modified: '+diff.edges_modified
  ].map(item=>'<li>'+esc(item)+'</li>').join('');
  document.getElementById('events').innerHTML=state.events.slice().reverse().map(item=>'<div class="event"><b>'+esc(item.event.replaceAll('_',' '))+'</b><br>'+esc(item.detail)+'<br><span class="small">'+esc(item.at)+'</span></div>').join('');
}
async function uploadDrawio() {
  const input=document.getElementById('drawioFile');
  if (!input.files.length) return show('Choose the edited .drawio or XML file first.','bad');
  setBusy(true,'Uploading and validating the edited draw.io file…');
  try {
    const file=input.files[0]; const content=await file.text();
    await api('/api/import-drawio',{filename:file.name,content});
    input.value=''; await loadState('Edited draw.io is now displayed as a preview. No real version has been created yet.');
  } catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
async function applyFeedback() {
  const feedback=document.getElementById('feedback').value.trim();
  if (!feedback) return show('Write the requested architecture change first.','bad');
  setBusy(true,'Ollama is preparing a constrained patch. This may take a few minutes…');
  try { await api('/api/feedback',{feedback}); document.getElementById('feedback').value=''; await loadState('AI changes are now displayed as a preview. Accept or discard them.'); }
  catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
async function acceptPreview() {
  if (!confirm('Accept exactly the preview shown and create the next architecture version?')) return;
  setBusy(true,'Accepting the displayed preview as the next architecture version…');
  try { await api('/api/accept-preview',{}); await loadState('Preview accepted. A new architecture version was created.'); }
  catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
async function discardPreview() {
  if (!confirm('Discard this preview and return to the latest accepted version?')) return;
  setBusy(true,'Discarding the preview…');
  try { await api('/api/discard-preview',{}); await loadState('Preview discarded. No architecture version was created.'); }
  catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
async function requestChanges() {
  const note=document.getElementById('feedback').value.trim();
  if (!note) return show('Write the requested change first.','bad');
  setBusy(true,'Recording the review decision…');
  try { await api('/api/request-changes',{note}); await loadState('Changes requested. Apply the feedback when ready.'); }
  catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
async function approveArchitecture() {
  const confirmed=document.getElementById('confirmed').checked;
  const reviewer=document.getElementById('reviewer').value.trim();
  setBusy(true,'Approving the exact architecture version and hash…');
  try { await api('/api/approve',{reviewer,confirmed}); await loadState('Architecture approved. The approval is bound to the displayed SHA-256 hash.'); }
  catch(error) { show(error.message,'bad'); } finally { setBusy(false); }
}
loadState().catch(error=>show(error.message,'bad'));
</script>
</body>
</html>
"""


class ReviewHandler(BaseHTTPRequestHandler):
    server_version = "ArchitectureReview/1.0"

    def log_message(self, format_string: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format_string % args}")

    def send_bytes(
        self,
        payload: bytes,
        content_type: str,
        status: int = 200,
        filename: str | None = None,
        inline: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            disposition = "inline" if inline else "attachment"
            self.send_header("Content-Disposition", f'{disposition}; filename="{filename}"')
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, value: dict[str, Any], status: int = 200) -> None:
        self.send_bytes(
            json.dumps(value, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status=status,
        )

    def read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise WorkflowError("Invalid Content-Length header.") from error
        if length <= 0:
            return {}
        if length > MAX_REQUEST_BYTES:
            raise WorkflowError("Request is larger than the 15 MB safety limit.")
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise WorkflowError("This local API accepts JSON requests only.")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WorkflowError(f"Request contains invalid JSON: {error}") from error
        if not isinstance(value, dict):
            raise WorkflowError("Request body must be one JSON object.")
        return value

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                self.send_bytes(HTML_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/state":
                self.send_json({"ok": True, "state": public_state(initialize_review())})
                return
            if parsed.path.startswith("/artifact/"):
                self.serve_artifact(parsed.path)
                return
            self.send_json({"ok": False, "error": "Not found."}, status=404)
        except WorkflowError as error:
            self.send_json({"ok": False, "error": str(error)}, status=400)
        except Exception as error:  # pragma: no cover - defensive server boundary
            self.send_json({"ok": False, "error": f"Unexpected server error: {error}"}, status=500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self.read_json_body()
            if self.path == "/api/import-drawio":
                state = import_drawio(str(body.get("content") or ""), str(body.get("filename") or "edited.drawio"))
            elif self.path == "/api/feedback":
                state = apply_feedback(str(body.get("feedback") or ""))
            elif self.path == "/api/accept-preview":
                state = accept_preview()
            elif self.path == "/api/discard-preview":
                state = discard_preview()
            elif self.path == "/api/approve":
                state = approve_current(str(body.get("reviewer") or ""), body.get("confirmed") is True)
            elif self.path == "/api/request-changes":
                state = request_changes(str(body.get("note") or ""))
            else:
                self.send_json({"ok": False, "error": "Not found."}, status=404)
                return
            self.send_json({"ok": True, "state": public_state(state)})
        except WorkflowError as error:
            self.send_json({"ok": False, "error": str(error)}, status=400)
        except Exception as error:  # pragma: no cover - defensive server boundary
            self.send_json({"ok": False, "error": f"Unexpected server error: {error}"}, status=500)

    def serve_artifact(self, route: str) -> None:
        state = initialize_review()
        pending = state.get("pending_preview")
        if isinstance(pending, dict):
            files = pending["files"]
            version_label = f"v{pending['proposed_version']}_preview"
        else:
            files = state["current_files"]
            version_label = f"v{state['current_version']}"
        if route == "/artifact/current-viewer.html":
            drawio_path = BASE_DIR / files["drawio"]
            if not drawio_path.exists() or not drawio_path.is_file():
                raise WorkflowError(f"Artifact is missing: {relative_path(drawio_path)}")
            try:
                xml_text = drawio_path.read_text(encoding="utf-8")
            except OSError as error:
                raise WorkflowError(f"Could not read the draw.io preview: {error}") from error
            viewer_html = create_drawio_viewer_html(
                xml_text,
                f"/artifact/current.png?viewer_fallback={urllib.parse.quote(version_label)}",
            )
            self.send_bytes(
                viewer_html.encode("utf-8"),
                "text/html; charset=utf-8",
                filename=f"architecture_review_{version_label}_viewer.html",
                inline=True,
            )
            return
        mapping: dict[str, tuple[Path, str, str, bool]] = {
            "/artifact/current.png": (BASE_DIR / files["png"], "image/png", f"architecture_review_{version_label}.png", True),
            "/artifact/current.drawio": (BASE_DIR / files["drawio"], "application/xml; charset=utf-8", f"architecture_review_{version_label}.drawio", False),
            "/artifact/current.json": (BASE_DIR / files["architecture"], "application/json; charset=utf-8", f"architecture_review_{version_label}.json", False),
            "/artifact/diff.json": (BASE_DIR / files["diff"], "application/json; charset=utf-8", f"architecture_diff_{version_label}.json", False),
        }
        if state.get("approved"):
            mapping["/artifact/approval.json"] = (REVIEW_DIR / "approval.json", "application/json; charset=utf-8", "approval.json", False)
        if route not in mapping:
            raise WorkflowError("Requested artifact is not available.")
        path, content_type, filename, inline = mapping[route]
        if not path.exists() or not path.is_file():
            raise WorkflowError(f"Artifact is missing: {relative_path(path)}")
        self.send_bytes(path.read_bytes(), content_type, filename=filename, inline=inline)


def print_summary(state: dict[str, Any]) -> None:
    coverage = state.get("coverage", {})
    print()
    print("Architecture Review Workflow")
    print("----------------------------")
    print(f"Architecture: {public_state(state)['architecture_name']}")
    print(f"Review version: {state['current_version']}")
    print(f"Status: {state['status']}")
    print(f"SHA-256: {state['current_hash']}")
    print(
        "Requirement coverage: "
        f"{coverage.get('covered_requirements', 0)}/"
        f"{coverage.get('total_requirements', 0)} "
        f"({coverage.get('coverage_percentage', 0)}%)"
    )
    print()
    print("Current files:")
    for label in ("png", "drawio", "architecture", "diff"):
        print(f"- {state['current_files'][label]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Editable architecture review workflow")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Local bind address")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Local port")
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Generate/reuse review artifacts without starting the browser server",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start the server without opening the browser automatically",
    )
    arguments = parser.parse_args()
    try:
        state = initialize_review()
        print_summary(state)
        if arguments.generate_only:
            print()
            print("Generation completed. The source architecture was not overwritten.")
            return
        server = ThreadingHTTPServer((arguments.host, arguments.port), ReviewHandler)
    except (WorkflowError, OSError) as error:
        print()
        print("ERROR:")
        print(error)
        raise SystemExit(1) from error

    url = f"http://{arguments.host}:{arguments.port}"
    print()
    print(f"Open: {url}")
    print("Press Ctrl+C to stop the review server.")
    if not arguments.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReview server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
