"""Render a controlled, reviewer-friendly architecture diagram.

The validated architecture JSON remains the source of truth.  The presentation
JSON supplies visualization-only grouping, category, position and style hints.
No architecture component or visible flow is invented by this renderer.
"""

import json
import html
import math
import os
import shutil
import subprocess
import textwrap
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
PRESENTATION_FILE = BASE_DIR / "outputs" / "presentation" / "presentation_v1.json"
OUTPUT_FOLDER = BASE_DIR / "outputs" / "diagrams"
OUTPUT_STEM = OUTPUT_FOLDER / "architecture_professional_v1"
DOT_FILE = OUTPUT_FOLDER / ".architecture_professional_v1.gv"

GRAPHVIZ_BIN = Path(r"C:\Program Files\Graphviz\bin")
EXPECTED_STATUSES = {"DRAFT", "APPROVED"}


class DiagramError(RuntimeError):
    """Raised when a truthful professional diagram cannot be generated."""


def load_json(path, description):
    if not path.exists():
        raise DiagramError(f"missing {description}: {path.relative_to(BASE_DIR)}")

    try:
        with path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except json.JSONDecodeError as error:
        raise DiagramError(f"malformed {description}: {error}") from error
    except OSError as error:
        raise DiagramError(f"could not read {description}: {error}") from error

    if not isinstance(value, dict):
        raise DiagramError(f"{description} must contain a JSON object")

    return value


def validate_models(architecture, presentation):
    errors = []

    status = str(architecture.get("status") or "").upper()
    if status not in EXPECTED_STATUSES:
        errors.append(
            "architecture status must be DRAFT or APPROVED; "
            f"received '{architecture.get('status')}'"
        )

    nodes = architecture.get("nodes")
    edges = architecture.get("edges")
    groups = presentation.get("visual_groups")
    node_presentations = presentation.get("node_presentations")
    edge_presentations = presentation.get("edge_presentations")

    if not isinstance(nodes, list) or not nodes:
        errors.append("architecture contains no nodes")
        nodes = []
    if not isinstance(edges, list):
        errors.append("architecture edges must be a list")
        edges = []
    if not isinstance(groups, list) or not groups:
        errors.append("presentation model contains no visual groups")
        groups = []
    if not isinstance(node_presentations, list):
        errors.append("presentation node_presentations must be a list")
        node_presentations = []
    if not isinstance(edge_presentations, list):
        errors.append("presentation edge_presentations must be a list")
        edge_presentations = []

    architecture_name = architecture.get("architecture_name")
    presentation_name = presentation.get("architecture_name")
    if architecture_name and presentation_name and architecture_name != presentation_name:
        errors.append(
            "presentation model belongs to a different architecture: "
            f"'{presentation_name}'"
        )

    node_ids = []
    for node in nodes:
        node_id = node.get("id") if isinstance(node, dict) else None
        if not node_id:
            errors.append("an architecture node is missing an ID")
        else:
            node_ids.append(node_id)

    duplicate_node_ids = sorted(
        {node_id for node_id in node_ids if node_ids.count(node_id) > 1}
    )
    for node_id in duplicate_node_ids:
        errors.append(f"duplicate architecture node ID: {node_id}")

    valid_node_ids = set(node_ids)
    edge_ids = []
    for edge in edges:
        edge_id = edge.get("id") if isinstance(edge, dict) else None
        source = edge.get("source") if isinstance(edge, dict) else None
        target = edge.get("target") if isinstance(edge, dict) else None

        if not edge_id:
            errors.append("an architecture edge is missing an ID")
        else:
            edge_ids.append(edge_id)
        if source not in valid_node_ids:
            errors.append(f"{edge_id or 'unknown edge'}: source node '{source}' does not exist")
        if target not in valid_node_ids:
            errors.append(f"{edge_id or 'unknown edge'}: target node '{target}' does not exist")

    duplicate_edge_ids = sorted(
        {edge_id for edge_id in edge_ids if edge_ids.count(edge_id) > 1}
    )
    for edge_id in duplicate_edge_ids:
        errors.append(f"duplicate architecture edge ID: {edge_id}")

    valid_edge_ids = set(edge_ids)
    group_ids = []
    for group in groups:
        group_id = group.get("id") if isinstance(group, dict) else None
        if not group_id:
            errors.append("a presentation group is missing an ID")
        else:
            group_ids.append(group_id)

    duplicate_group_ids = sorted(
        {group_id for group_id in group_ids if group_ids.count(group_id) > 1}
    )
    for group_id in duplicate_group_ids:
        errors.append(f"duplicate presentation group ID: {group_id}")

    valid_group_ids = set(group_ids)
    for group in groups:
        if not isinstance(group, dict):
            continue
        parent_id = group.get("parent_id")
        if parent_id and parent_id not in valid_group_ids:
            errors.append(f"group '{group.get('id')}' has unknown parent '{parent_id}'")

    seen_presented_nodes = set()
    for item in node_presentations:
        node_id = item.get("node_id") if isinstance(item, dict) else None
        group_id = item.get("group_id") if isinstance(item, dict) else None
        if node_id not in valid_node_ids:
            errors.append(f"presentation references unknown node '{node_id}'")
        elif node_id in seen_presented_nodes:
            errors.append(f"duplicate node presentation for '{node_id}'")
        else:
            seen_presented_nodes.add(node_id)
        if group_id not in valid_group_ids:
            errors.append(f"node '{node_id}' references unknown visual group '{group_id}'")

    missing_presentations = sorted(valid_node_ids - seen_presented_nodes)
    if missing_presentations:
        errors.append(
            "presentation metadata is missing architecture nodes: "
            + ", ".join(missing_presentations)
        )

    seen_presented_edges = set()
    for item in edge_presentations:
        edge_id = item.get("edge_id") if isinstance(item, dict) else None
        if edge_id not in valid_edge_ids:
            errors.append(f"presentation references unknown edge '{edge_id}'")
        elif edge_id in seen_presented_edges:
            errors.append(f"duplicate edge presentation for '{edge_id}'")
        else:
            seen_presented_edges.add(edge_id)

    missing_edge_presentations = sorted(valid_edge_ids - seen_presented_edges)
    if missing_edge_presentations:
        errors.append(
            "presentation metadata is missing architecture edges: "
            + ", ".join(missing_edge_presentations)
        )

    if errors:
        raise DiagramError("validation failed:\n- " + "\n- ".join(errors))


def find_graphviz():
    if GRAPHVIZ_BIN.exists():
        os.environ["PATH"] = str(GRAPHVIZ_BIN) + os.pathsep + os.environ.get("PATH", "")

    executable = shutil.which("dot") or shutil.which("dot.exe")
    if not executable:
        for candidate_dir in [
            Path(r"C:\Program Files\Graphviz\bin"),
            Path(r"C:\Program Files (x86)\Graphviz\bin"),
            Path(r"C:\Graphviz\bin"),
        ]:
            cand_exe = candidate_dir / "dot.exe"
            if cand_exe.exists():
                return str(cand_exe)
        return None
    return executable


def dot_quote(value):
    return json.dumps(str(value), ensure_ascii=False)


def dot_id(prefix, value):
    safe = "".join(character if character.isalnum() else "_" for character in str(value))
    return f"{prefix}_{safe}"


def wrapped_label(label, subtitle):
    lines = textwrap.wrap(str(label), width=22, break_long_words=False) or [str(label)]
    if subtitle:
        lines.append(str(subtitle).upper())
    return "\n".join(lines)


def group_has_content(group_id, group_children, group_nodes):
    if group_nodes.get(group_id):
        return True
    return any(
        group_has_content(child_id, group_children, group_nodes)
        for child_id in group_children.get(group_id, [])
    )


def build_group_dot(group_id, groups, group_children, group_nodes, node_lines, depth=1):
    if not group_has_content(group_id, group_children, group_nodes):
        return []

    group = groups[group_id]
    indent = "    " * depth
    cluster_name = dot_id("cluster", group_id)
    style = "rounded,filled"
    if group.get("line_style") == "dashed":
        style = "rounded,dashed,filled"

    lines = [f"{indent}subgraph {cluster_name} {{"]
    lines.extend(
        [
            f"{indent}    label={dot_quote(group.get('label', group_id))};",
            f"{indent}    color={dot_quote(group.get('border_color', '#A0A0A0'))};",
            f"{indent}    fillcolor={dot_quote(group.get('fill_color', '#FFFFFF'))};",
            f"{indent}    style={dot_quote(style)};",
            f"{indent}    penwidth={2.2 if group.get('group_type') == 'platform' else 1.3};",
            f"{indent}    fontsize={16 if group.get('group_type') == 'platform' else 12};",
            f"{indent}    fontname=\"Arial Bold\";",
            f"{indent}    fontcolor=\"#334155\";",
            f"{indent}    margin=22;",
        ]
    )

    for node_id in group_nodes.get(group_id, []):
        lines.append(f"{indent}    {node_lines[node_id]}")

    child_ids = sorted(
        group_children.get(group_id, []),
        key=lambda child_id: groups[child_id].get("order", 999),
    )
    for child_id in child_ids:
        lines.extend(
            build_group_dot(
                child_id,
                groups,
                group_children,
                group_nodes,
                node_lines,
                depth + 1,
            )
        )

    lines.append(f"{indent}}}")
    return lines


def build_dot(architecture, presentation):
    theme = presentation.get("theme", {})
    category_styles = theme.get("category_styles", {})
    flow_styles = theme.get("flow_styles", {})
    groups = {group["id"]: group for group in presentation["visual_groups"]}
    group_children = defaultdict(list)
    root_groups = []
    for group in presentation["visual_groups"]:
        parent_id = group.get("parent_id")
        if parent_id:
            group_children[parent_id].append(group["id"])
        else:
            root_groups.append(group["id"])

    node_metadata = {item["node_id"]: item for item in presentation["node_presentations"]}
    group_nodes = defaultdict(list)
    node_lines = {}

    for node in architecture["nodes"]:
        node_id = node["id"]
        metadata = node_metadata[node_id]
        category = metadata.get("category", "other")
        style = category_styles.get(category, category_styles.get("other", {}))
        label = wrapped_label(metadata.get("label") or node.get("name") or node_id, metadata.get("subtitle"))

        attributes = {
            "label": label,
            "shape": "box",
            "style": "rounded,filled",
            "fixedsize": "true",
            "width": "2.55",
            "height": "0.82",
            "fillcolor": style.get("fill", "#F3F4F6"),
            "color": style.get("border", "#687078"),
            "fontcolor": theme.get("text", "#243447"),
            "fontname": theme.get("font_family", "Arial"),
            "fontsize": "11",
            "penwidth": "1.8",
            "margin": "0.12,0.08",
        }
        attrs = ", ".join(f"{key}={dot_quote(value)}" for key, value in attributes.items())
        node_lines[node_id] = f"{dot_quote(node_id)} [{attrs}];"
        group_nodes[metadata["group_id"]].append(node_id)

    title = html.escape(architecture.get("architecture_name") or "Software Architecture")
    presentation_note = html.escape(presentation.get("presentation_note", ""))
    data_label = html.escape(
        flow_styles.get("data_request", {}).get("label", "Data / request flow")
    )
    management_label = html.escape(
        flow_styles.get("management", {}).get("label", "Management / control flow")
    )
    deployment_label = html.escape(
        flow_styles.get("deployment", {}).get("label", "Deployment flow")
    )
    graph_label = (
        "<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLPADDING=\"2\">"
        f"<TR><TD><FONT POINT-SIZE=\"24\"><B>{title}</B></FONT></TD></TR>"
        "<TR><TD><FONT POINT-SIZE=\"18\">Professional Architecture View</FONT></TD></TR>"
        "<TR><TD><FONT POINT-SIZE=\"9\" COLOR=\"#5B6673\">"
        f"Solid blue: {data_label}  |  "
        f"Dashed violet: {management_label}  |  "
        f"Dashed orange: {deployment_label}"
        "</FONT></TD></TR>"
        f"<TR><TD><FONT POINT-SIZE=\"8\" COLOR=\"#6B7280\">{presentation_note}</FONT></TD></TR>"
        "</TABLE>"
    )

    lines = [
        "digraph ProfessionalArchitecture {",
        "    graph [",
        "        layout=dot,",
        "        rankdir=LR,",
        "        newrank=true,",
        "        ranksep=0.75,",
        "        nodesep=0.40,",
        "        outputorder=edgesfirst,",
        "        overlap=false,",
        "        splines=ortho,",
        f"        bgcolor={dot_quote(theme.get('background', '#F5F8FC'))},",
        "        pad=0.45,",
        "        margin=0.12,",
        f"        fontname={dot_quote(theme.get('font_family', 'Arial'))},",
        "        fontcolor=\"#1F2937\",",
        f"        label=<{graph_label}>,",
        "        labelloc=t,",
        "        labeljust=c,",
        "        compound=true",
        "    ];",
        "    node [fontname=\"Arial\"];",
        "    edge [fontname=\"Arial\", fontsize=9, arrowsize=0.8];",
    ]

    for root_group_id in sorted(root_groups, key=lambda item: groups[item].get("order", 999)):
        lines.extend(
            build_group_dot(
                root_group_id,
                groups,
                group_children,
                group_nodes,
                node_lines,
            )
        )

    edge_metadata = {item["edge_id"]: item for item in presentation["edge_presentations"]}
    for edge in architecture["edges"]:
        metadata = edge_metadata[edge["id"]]
        flow_type = metadata.get("flow_type", "data_request")
        style = flow_styles.get(flow_type, flow_styles.get("data_request", {}))
        label = metadata.get("visible_label", "") if metadata.get("show_label", True) else ""
        attributes = {
            "color": style.get("color", "#0078D4"),
            "fontcolor": style.get("color", "#0078D4"),
            "style": style.get("line_style", "solid"),
            "penwidth": str(style.get("pen_width", 2.0)),
            "xlabel": label,
            "tooltip": f"{edge['source']} -> {edge['target']}",
        }
        attrs = ", ".join(f"{key}={dot_quote(value)}" for key, value in attributes.items())
        lines.append(
            f"    {dot_quote(edge['source'])} -> {dot_quote(edge['target'])} [{attrs}];"
        )

    lines.append("}")

    return "\n".join(lines) + "\n"


def render(graphviz_executable, dot_source):
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    DOT_FILE.write_text(dot_source, encoding="utf-8")

    outputs = {}
    temporary_outputs = {}
    try:
        for output_format in ("png", "svg"):
            output_path = OUTPUT_STEM.with_suffix(f".{output_format}")
            temporary_path = OUTPUT_FOLDER / f"{OUTPUT_STEM.name}.tmp.{output_format}"
            temporary_outputs[output_format] = temporary_path
            command = [
                graphviz_executable,
                f"-T{output_format}",
                str(DOT_FILE),
                "-o",
                str(temporary_path),
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip() or "unknown Graphviz error"
                raise DiagramError(f"Graphviz {output_format.upper()} rendering failed: {detail}")
            if not temporary_path.exists() or temporary_path.stat().st_size == 0:
                raise DiagramError(f"Graphviz did not create a valid {output_format.upper()} file")
            outputs[output_format] = output_path

        for output_format in ("png", "svg"):
            os.replace(temporary_outputs[output_format], outputs[output_format])
    finally:
        try:
            DOT_FILE.unlink()
        except FileNotFoundError:
            pass
        for temporary_path in temporary_outputs.values():
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    return outputs


def render_fallback_diagrams(architecture, presentation):
    """Render both PNG and SVG deterministically when Graphviz 'dot' is not installed."""
    import architecture_review_workflow as workflow

    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    png_path = OUTPUT_STEM.with_suffix(".png")
    svg_path = OUTPUT_STEM.with_suffix(".svg")

    layout = workflow.build_layout(architecture, presentation)
    workflow.render_png(png_path, architecture, presentation, layout, version=1)

    # Also build clean standalone SVG matching layout
    canvas = layout["canvas"]
    width = int(canvas["width"])
    header_height = 92
    footer_height = 42
    total_height = int(canvas["height"]) + header_height + footer_height
    title = html.escape(str(architecture.get("architecture_name") or "Software Architecture"))
    subtitle = html.escape(f"Professional Architecture View — Status: {architecture.get('status', 'DRAFT')}")

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" viewBox="0 0 {width} {total_height}">',
        f'  <rect width="100%" height="100%" fill="#F5F8FC"/>',
        f'  <text x="{width / 2}" y="38" text-anchor="middle" font-family="Arial, sans-serif" font-size="24" font-weight="bold" fill="#1F2937">{title}</text>',
        f'  <text x="{width / 2}" y="66" text-anchor="middle" font-family="Arial, sans-serif" font-size="14" fill="#5B6673">{subtitle}</text>',
    ]

    for group in workflow.group_bounds(architecture, presentation, layout):
        gx = group["x"]
        gy = group["y"] + header_height
        gw = group["width"]
        gh = group["height"]
        dash_attr = ' stroke-dasharray="8,5"' if group.get("dashed") else ""
        glabel = html.escape(str(group.get("label", group["id"])))
        svg_parts.append(
            f'  <rect x="{gx}" y="{gy}" width="{gw}" height="{gh}" rx="12" fill="{group["fill"]}" stroke="{group["border"]}" stroke-width="2"{dash_attr}/>'
        )
        svg_parts.append(
            f'  <text x="{gx + 14}" y="{gy + 22}" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#334155">{glabel}</text>'
        )

    for edge in architecture.get("edges", []):
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        if source_id not in layout["nodes"] or target_id not in layout["nodes"]:
            continue
        sbox = layout["nodes"][source_id]
        tbox = layout["nodes"][target_id]
        sx = sbox["x"] + sbox["width"] / 2
        sy = sbox["y"] + sbox["height"] / 2 + header_height
        tx = tbox["x"] + tbox["width"] / 2
        ty = tbox["y"] + tbox["height"] / 2 + header_height
        edge_id = str(edge.get("id", ""))
        color, dashed = workflow.flow_style(edge_id, presentation)
        dash_attr = ' stroke-dasharray="8,5"' if dashed else ""
        svg_parts.append(
            f'  <line x1="{sx:.1f}" y1="{sy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" stroke="{color}" stroke-width="2.5"{dash_attr}/>'
        )
        label = html.escape(str(layout.get("edge_labels", {}).get(edge_id, "")))
        if label:
            mx = (sx + tx) / 2
            my = (sy + ty) / 2
            svg_parts.append(
                f'  <text x="{mx:.1f}" y="{my - 4:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" fill="{color}">{label}</text>'
            )

    styles = workflow.theme_styles(presentation)
    node_meta, _, _ = workflow.presentation_indexes(presentation)
    for node in architecture.get("nodes", []):
        nid = str(node.get("id", ""))
        if nid not in layout["nodes"]:
            continue
        box = layout["nodes"][nid]
        nx = box["x"]
        ny = box["y"] + header_height
        nw = box["width"]
        nh = box["height"]
        cat = str(node_meta.get(nid, {}).get("category") or workflow.category_for_node(node))
        style = styles.get(cat, styles["other"])
        nlabel = html.escape(str(node.get("name") or nid))
        ntype = html.escape(str(node.get("type") or "COMPONENT").upper())
        svg_parts.append(
            f'  <rect x="{nx}" y="{ny}" width="{nw}" height="{nh}" rx="10" fill="{style.get("fill", "#F3F4F6")}" stroke="{style.get("border", "#687078")}" stroke-width="2.5"/>'
        )
        svg_parts.append(
            f'  <text x="{nx + nw / 2:.1f}" y="{ny + nh / 2 - 4:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="#243447">{nlabel}</text>'
        )
        svg_parts.append(
            f'  <text x="{nx + nw / 2:.1f}" y="{ny + nh / 2 + 14:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="#5B6673">{ntype}</text>'
        )

    svg_parts.append("</svg>\n")
    svg_path.write_text("\n".join(svg_parts), encoding="utf-8")
    return {"png": png_path, "svg": svg_path}


def relative_display(path):
    return str(path.relative_to(BASE_DIR)).replace("/", os.sep)


def main():
    print()
    print("Professional Architecture Diagram")
    print("---------------------------------")
    print()

    try:
        print("Loading architecture...")
        architecture = load_json(ARCHITECTURE_FILE, "architecture JSON")
        print("Loading presentation model...")
        presentation = load_json(PRESENTATION_FILE, "presentation JSON")

        print()
        print("Architecture:")
        print(architecture.get("architecture_name", "Unknown"))
        print()
        print("Validating graph...")
        validate_models(architecture, presentation)
        graphviz_executable = find_graphviz()
        if not graphviz_executable:
            print("Graphviz 'dot' executable not found; rendering professional PNG and SVG via built-in layout renderer...")
            outputs = render_fallback_diagrams(architecture, presentation)
        else:
            print("Building visual groups...")
            dot_source = build_dot(architecture, presentation)
            print("Rendering professional architecture...")
            outputs = render(graphviz_executable, dot_source)

        print()
        print("Professional architecture diagram generated successfully!")
        print()
        print("PNG:")
        print(relative_display(outputs["png"]))
        print()
        print("SVG:")
        print(relative_display(outputs["svg"]))
    except (DiagramError, OSError) as error:
        print()
        print("ERROR:")
        print(error)
        print()
        print("Diagram generation stopped. No diagram output was updated by this run.")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
