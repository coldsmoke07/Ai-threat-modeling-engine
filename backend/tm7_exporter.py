"""Microsoft Threat Modeling Tool (.tm7) XML Exporter & Visual TM7/DFD Diagram Renderer.

Exports architecture models, DFD elements, trust boundaries, and STRIDE threats into:
1. Valid Microsoft Threat Modeling Tool XML documents (outputs/architecture_model.tm7)
2. High-resolution visual TM7 Threat Model & DFD diagrams (outputs/diagrams/tm7_threat_model_v1.png & .svg)
"""

from __future__ import annotations

import html
import json
import math
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw

import dfd_generator

BASE_DIR = Path(__file__).resolve().parent
REVIEW_DIR = BASE_DIR / "outputs" / "review"
DFD_FILE = BASE_DIR / "outputs" / "dfd.json"
STRIDE_FILE = BASE_DIR / "outputs" / "stride_threats.json"
OUTPUT_TM7_FILE = BASE_DIR / "outputs" / "architecture_model.tm7"
DIAGRAMS_DIR = BASE_DIR / "outputs" / "diagrams"
OUTPUT_TM7_PNG = DIAGRAMS_DIR / "tm7_threat_model_v1.png"
OUTPUT_TM7_SVG = DIAGRAMS_DIR / "tm7_threat_model_v1.svg"


class Tm7ExportError(RuntimeError):
    """Raised when .tm7 export fails."""


def safe_guid(name: str) -> str:
    """Generate deterministic GUID string from item identifier."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"ai.threat.modeling.{name}"))


def generate_tm7_xml(architecture: dict[str, Any], dfd: dict[str, Any], stride: dict[str, Any], approval: dict[str, Any]) -> str:
    nodes = architecture.get("nodes", [])
    edges = architecture.get("edges", [])
    trust_zones = architecture.get("trust_zones", [])
    threats = stride.get("threats", [])

    model_id = safe_guid(architecture.get("architecture_name", "TM7Model"))

    root = ET.Element("ThreatModel", {
        "Id": model_id,
        "Name": str(architecture.get("architecture_name", "Architecture Threat Model")),
        "Owner": str(approval.get("reviewer", "Security Reviewer")),
        "HighLevelSystemDescription": str(architecture.get("description", "")),
        "Version": str(approval.get("architecture_version", 1)),
        "Status": str(approval.get("status", "CANDIDATE_ACTIVE")),
        "AppVersion": "4.0.0",
        "SchemaVersion": "1.0",
        "Hash": str(approval.get("architecture_hash", "")),
    })

    meta = ET.SubElement(root, "MetaData")
    ET.SubElement(meta, "Created").text = datetime.now(timezone.utc).isoformat()
    ET.SubElement(meta, "ApprovedHash").text = str(approval.get("architecture_hash", ""))
    ET.SubElement(meta, "ApprovalStatus").text = str(approval.get("status", "CANDIDATE_ACTIVE"))

    kb = ET.SubElement(root, "KnowledgeBase")
    ET.SubElement(kb, "Name").text = "Azure Threat Modeling Stencil Set (STRIDE-per-Element)"

    boundaries_elem = ET.SubElement(root, "Boundaries")
    for zone in trust_zones:
        zid = str(zone.get("id") or zone.get("name") or "")
        z_guid = safe_guid(f"boundary_{zid}")
        ET.SubElement(boundaries_elem, "Boundary", {
            "Id": z_guid,
            "Name": str(zone.get("name", zid)),
            "Description": str(zone.get("description", "")),
        })

    dfd_kind_by_id = {}
    for sec, kind_label in (("external_entities", "StencilExternalInteractor"), ("processes", "StencilProcess"), ("data_stores", "StencilDataStore")):
        for item in dfd.get(sec, []):
            dfd_kind_by_id[str(item.get("id", ""))] = kind_label

    elements_elem = ET.SubElement(root, "Elements")
    node_guid_map = {}

    for node in nodes:
        node_id = str(node.get("id", ""))
        guid = safe_guid(f"node_{node_id}")
        node_guid_map[node_id] = guid
        stencil = dfd_kind_by_id.get(node_id, "StencilProcess")

        el = ET.SubElement(elements_elem, "Element", {
            "Id": guid,
            "Name": str(node.get("name", node_id)),
            "TypeId": str(node.get("type", "Component")),
            "StencilType": stencil,
            "TrustZone": str(node.get("trust_zone", "")),
        })
        props = ET.SubElement(el, "Properties")
        ET.SubElement(props, "Property", {"Name": "RequirementIDs"}).text = ",".join(node.get("requirement_ids", []))
        ET.SubElement(props, "Property", {"Name": "Description"}).text = str(node.get("description", ""))

    lines_elem = ET.SubElement(root, "Lines")
    edge_guid_map = {}
    for edge in edges:
        edge_id = str(edge.get("id", ""))
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        e_guid = safe_guid(f"edge_{edge_id}")
        edge_guid_map[edge_id] = e_guid

        line = ET.SubElement(lines_elem, "Line", {
            "Id": e_guid,
            "Name": str(edge.get("data", edge_id)),
            "SourceId": node_guid_map.get(source_id, safe_guid(source_id)),
            "TargetId": node_guid_map.get(target_id, safe_guid(target_id)),
            "Protocol": str(edge.get("protocol", "HTTPS")),
            "CrossesBoundary": "true" if edge.get("trust_boundary_crossing") else "false",
        })
        props = ET.SubElement(line, "Properties")
        ET.SubElement(props, "Property", {"Name": "Encryption"}).text = str(edge.get("encryption", "TLS"))
        ET.SubElement(props, "Property", {"Name": "Authentication"}).text = str(edge.get("authentication", "None"))

    threats_elem = ET.SubElement(root, "Threats")
    for threat in threats:
        tid = str(threat.get("threat_id", ""))
        t_guid = safe_guid(f"threat_{tid}")
        target_key = str(threat.get("target_id", ""))
        target_guid = node_guid_map.get(target_key) or edge_guid_map.get(target_key) or safe_guid(target_key)
        t_elem = ET.SubElement(threats_elem, "Threat", {
            "Id": t_guid,
            "ThreatId": tid,
            "Category": str(threat.get("category", "")),
            "StrideCode": str(threat.get("stride_code", "")),
            "DfdElementType": str(threat.get("dfd_element_type", "")),
            "Title": str(threat.get("title", "")),
            "Severity": str(threat.get("severity", "MEDIUM")),
            "RiskScore": str(threat.get("risk_score", 4)),
            "TargetId": target_guid,
            "TargetElementId": target_key,
        })
        ET.SubElement(t_elem, "Description").text = str(threat.get("description", ""))
        ET.SubElement(t_elem, "Mitigation").text = str(threat.get("mitigation", ""))
        ET.SubElement(t_elem, "RequirementId").text = str(threat.get("requirement_id", "N/A"))

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def render_tm7_visual_diagrams(architecture: dict[str, Any], dfd: dict[str, Any], stride: dict[str, Any], approval: dict[str, Any]) -> tuple[Path, Path]:
    """Render visual Microsoft Threat Modeling Tool (.TM7) & DFD Threat Diagram as PNG and SVG."""
    import architecture_review_workflow as workflow

    DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    presentation = workflow.load_optional_presentation()

    # Load current review layout if available, else build fresh layout
    layout = None
    if workflow.STATE_FILE.exists():
        try:
            st = workflow.load_state()
            _, layout = workflow.current_artifacts(st)
        except Exception:
            layout = None
    if not layout or set(layout.get("nodes", {}).keys()) != {str(n.get("id")) for n in architecture.get("nodes", [])}:
        layout = workflow.build_layout(architecture, presentation)

    canvas = layout["canvas"]
    width = int(canvas["width"])
    diagram_height = int(canvas["height"])
    header_height = 104
    footer_height = 56
    total_height = diagram_height + header_height + footer_height

    # Map DFD kinds and STRIDE threat badges per element
    dfd_by_id: dict[str, dict[str, Any]] = {}
    for sec in ("external_entities", "processes", "data_stores"):
        for item in dfd.get(sec, []):
            dfd_by_id[str(item.get("id", ""))] = item
    flow_by_id: dict[str, dict[str, Any]] = {
        str(f.get("id", "")): f for f in dfd.get("data_flows", [])
    }

    image = Image.new("RGB", (width, total_height), "#F8FAFC")
    draw = ImageDraw.Draw(image)
    title_font = workflow.load_font(23, bold=True)
    subtitle_font = workflow.load_font(12, bold=True)
    group_font = workflow.load_font(12, bold=True)
    node_font = workflow.load_font(11, bold=True)
    badge_font = workflow.load_font(9, bold=True)
    edge_font = workflow.load_font(9, bold=True)
    footer_font = workflow.load_font(11, bold=True)

    # Header banner
    draw.rectangle((0, 0, width, header_height - 10), fill="#0F172A")
    title = f"{architecture.get('architecture_name', 'System')} — .TM7 Threat Model & DFD Diagram"
    tbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(((width - (tbox[2] - tbox[0])) / 2, 16), title, fill="#F8FAFC", font=title_font)

    s_sum = stride.get("summary", {})
    d_sum = dfd.get("summary", {})
    sub = (
        f"DFD Elements: {d_sum.get('total_external_entities', 0)} External Entities  |  "
        f"{d_sum.get('total_processes', 0)} Processes  |  "
        f"{d_sum.get('total_data_stores', 0)} Data Stores  |  "
        f"{d_sum.get('total_data_flows', 0)} Data Flows   •   "
        f"STRIDE Threats: {s_sum.get('total_threats', 0)} Total "
        f"({s_sum.get('high_severity', 0)} HIGH, {s_sum.get('medium_severity', 0)} MEDIUM, {s_sum.get('low_severity', 0)} LOW)"
    )
    sbox = draw.textbbox((0, 0), sub, font=subtitle_font)
    draw.text(((width - (sbox[2] - sbox[0])) / 2, 54), sub, fill="#93C5FD", font=subtitle_font)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" viewBox="0 0 {width} {total_height}">',
        f'  <rect width="100%" height="100%" fill="#F8FAFC"/>',
        f'  <rect width="{width}" height="{header_height - 10}" fill="#0F172A"/>',
        f'  <text x="{width / 2}" y="38" text-anchor="middle" font-family="Arial, sans-serif" font-size="22" font-weight="bold" fill="#F8FAFC">{html.escape(title)}</text>',
        f'  <text x="{width / 2}" y="68" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#93C5FD">{html.escape(sub)}</text>',
    ]

    # Draw Trust Boundary containers with red dashed borders (TM7 Trust Boundary style)
    for group in workflow.group_bounds(architecture, presentation, layout):
        gx1 = group["x"]
        gy1 = group["y"] + header_height
        gx2 = gx1 + group["width"]
        gy2 = gy1 + group["height"]
        border_col = "#DC2626" if group.get("dashed") else "#2563EB"
        fill_col = "#FFF5F5" if group.get("dashed") else group["fill"]
        draw.rounded_rectangle((gx1, gy1, gx2, gy2), radius=10, fill=fill_col, outline=border_col, width=2)
        b_label = f"TRUST BOUNDARY: {str(group['label']).upper()}"
        draw.text((gx1 + 12, gy1 + 7), b_label, fill=border_col, font=group_font)

        svg_parts.append(
            f'  <rect x="{gx1}" y="{gy1}" width="{group["width"]}" height="{group["height"]}" rx="10" fill="{fill_col}" stroke="{border_col}" stroke-width="2" stroke-dasharray="8,4"/>'
        )
        svg_parts.append(
            f'  <text x="{gx1 + 12}" y="{gy1 + 20}" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="{border_col}">{html.escape(b_label)}</text>'
        )

    # Draw DFD Data Flows with boundary crossing & threat indicators
    for edge in architecture.get("edges", []):
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        if source_id not in layout["nodes"] or target_id not in layout["nodes"]:
            continue
        source = layout["nodes"][source_id]
        target = layout["nodes"][target_id]
        sx = source["x"] + source["width"] / 2
        sy = source["y"] + source["height"] / 2 + header_height
        tx = target["x"] + target["width"] / 2
        ty = target["y"] + target["height"] / 2 + header_height
        angle = math.atan2(ty - sy, tx - sx)
        start = (sx + math.cos(angle) * 52, sy + math.sin(angle) * 32)
        end = (tx - math.cos(angle) * 55, ty - math.sin(angle) * 34)

        edge_id = str(edge.get("id", ""))
        f_info = flow_by_id.get(edge_id, {})
        crosses = bool(edge.get("trust_boundary_crossing", False))
        t_count = f_info.get("threat_count", 0)
        line_color = "#DC2626" if crosses else "#0284C7"

        workflow.draw_arrow(draw, start, end, line_color, dashed=crosses)
        dash_part = ' stroke-dasharray="6,4"' if crosses else ""
        svg_parts.append(
            f'  <line x1="{start[0]:.1f}" y1="{start[1]:.1f}" x2="{end[0]:.1f}" y2="{end[1]:.1f}" stroke="{line_color}" stroke-width="2.5"{dash_part}/>'
        )

        proto = str(edge.get("protocol", "HTTPS"))
        flow_tag = f"{proto} [{'I,T' if crosses else 'I'}:{t_count}]"
        mx = (start[0] + end[0]) / 2
        my = (start[1] + end[1]) / 2
        lbox = draw.textbbox((0, 0), flow_tag, font=edge_font)
        lw = lbox[2] - lbox[0]
        lh = lbox[3] - lbox[1]
        draw.rounded_rectangle(
            (mx - lw / 2 - 5, my - lh / 2 - 3, mx + lw / 2 + 5, my + lh / 2 + 3),
            radius=4,
            fill="#FEF2F2" if crosses else "#EFF6FF",
            outline=line_color,
            width=1,
        )
        draw.text((mx - lw / 2, my - lh / 2 - 1), flow_tag, fill=line_color, font=edge_font)
        svg_parts.append(
            f'  <text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" font-weight="bold" fill="{line_color}">{html.escape(flow_tag)}</text>'
        )

    # Draw DFD Nodes (External Entity = rectangle, Process = rounded pill, Data Store = parallel bars) + STRIDE badges
    for node in architecture.get("nodes", []):
        node_id = str(node.get("id", ""))
        if node_id not in layout["nodes"]:
            continue
        box = layout["nodes"][node_id]
        nx1 = box["x"]
        ny1 = box["y"] + header_height
        nw = box["width"]
        nh = box["height"]
        nx2 = nx1 + nw
        ny2 = ny1 + nh

        dfd_info = dfd_by_id.get(node_id, {})
        dfd_kind = dfd_info.get("dfd_kind", "process")
        dfd_label = dfd_info.get("dfd_label", "Process").upper()
        t_count = dfd_info.get("threat_count", 2)
        max_sev = dfd_info.get("max_severity", "HIGH")
        codes = ",".join(dfd_info.get("stride_codes", ["S", "T", "E"]))

        if dfd_kind == "external_entity":
            fill_c, border_c = "#EFF6FF", "#1D4ED8"
            draw.rectangle((nx1, ny1, nx2, ny2), fill=fill_c, outline=border_c, width=3)
            draw.rectangle((nx1 + 4, ny1 + 4, nx2 - 4, ny2 - 4), outline=border_c, width=1)
            svg_parts.append(f'  <rect x="{nx1}" y="{ny1}" width="{nw}" height="{nh}" fill="{fill_c}" stroke="{border_c}" stroke-width="3"/>')
        elif dfd_kind == "data_store":
            fill_c, border_c = "#FFF7ED", "#C2410C"
            draw.rectangle((nx1, ny1, nx2, ny2), fill=fill_c, outline=None)
            draw.line((nx1, ny1, nx2, ny1), fill=border_c, width=4)
            draw.line((nx1, ny2, nx2, ny2), fill=border_c, width=4)
            draw.line((nx1, ny1, nx1, ny2), fill=border_c, width=2)
            svg_parts.append(f'  <rect x="{nx1}" y="{ny1}" width="{nw}" height="{nh}" fill="{fill_c}" stroke="{border_c}" stroke-width="2.5"/>')
        else:
            fill_c, border_c = "#F0FDF4", "#15803D"
            draw.rounded_rectangle((nx1, ny1, nx2, ny2), radius=28, fill=fill_c, outline=border_c, width=3)
            svg_parts.append(f'  <rect x="{nx1}" y="{ny1}" width="{nw}" height="{nh}" rx="28" fill="{fill_c}" stroke="{border_c}" stroke-width="3"/>')

        # Node Name & DFD Kind Subtitle
        lines = workflow.wrap_lines(str(node.get("name") or node_id), 22)
        cy = ny1 + 12
        for line in lines[:2]:
            tb = draw.textbbox((0, 0), line, font=node_font)
            draw.text((nx1 + (nw - (tb[2] - tb[0])) / 2, cy), line, fill="#0F172A", font=node_font)
            cy += 14
        sub_tag = f"[{dfd_label}]"
        stb = draw.textbbox((0, 0), sub_tag, font=badge_font)
        draw.text((nx1 + (nw - (stb[2] - stb[0])) / 2, ny2 - 16), sub_tag, fill=border_c, font=badge_font)

        svg_parts.append(
            f'  <text x="{nx1 + nw / 2:.1f}" y="{ny1 + nh / 2 - 2:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="#0F172A">{html.escape(str(node.get("name") or node_id))}</text>'
        )
        svg_parts.append(
            f'  <text x="{nx1 + nw / 2:.1f}" y="{ny2 - 8:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" font-weight="bold" fill="{border_c}">{html.escape(sub_tag)}</text>'
        )

        # Red/Amber STRIDE Threat Pill Badge on top-right of node
        badge_text = f"STRIDE [{codes}] • {t_count}"
        btb = draw.textbbox((0, 0), badge_text, font=badge_font)
        bw = (btb[2] - btb[0]) + 12
        bh = 18
        bx1 = nx2 - bw + 6
        by1 = ny1 - 10
        b_fill = "#DC2626" if max_sev == "HIGH" else "#D97706"
        draw.rounded_rectangle((bx1, by1, bx1 + bw, by1 + bh), radius=8, fill=b_fill, outline="#FFFFFF", width=1)
        draw.text((bx1 + 6, by1 + 3), badge_text, fill="#FFFFFF", font=badge_font)
        svg_parts.append(
            f'  <rect x="{bx1}" y="{by1}" width="{bw}" height="{bh}" rx="8" fill="{b_fill}" stroke="#FFFFFF" stroke-width="1"/>'
        )
        svg_parts.append(
            f'  <text x="{bx1 + bw / 2:.1f}" y="{by1 + 12:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" font-weight="bold" fill="#FFFFFF">{html.escape(badge_text)}</text>'
        )

    # Footer Legend
    fy = diagram_height + header_height + 14
    legend = (
        "TM7 / DFD Legend:  [Double Box] = External Entity (S, R)   |   (Rounded Pill) = Process (E, D)   |   "
        "[Parallel Bars] = Data Store (T, I)   |   Red Dashed Arrow = Boundary-Crossing Flow (I, T)"
    )
    ftb = draw.textbbox((0, 0), legend, font=footer_font)
    draw.text(((width - (ftb[2] - ftb[0])) / 2, fy), legend, fill="#1E293B", font=footer_font)
    svg_parts.append(
        f'  <text x="{width / 2}" y="{fy + 10}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="#1E293B">{html.escape(legend)}</text>'
    )
    svg_parts.append("</svg>\n")

    image.save(OUTPUT_TM7_PNG, format="PNG")
    OUTPUT_TM7_SVG.write_text("\n".join(svg_parts), encoding="utf-8")
    return OUTPUT_TM7_PNG, OUTPUT_TM7_SVG


def export_tm7() -> Path:
    approval, architecture = dfd_generator.resolve_active_architecture()

    if not DFD_FILE.exists():
        dfd_generator.main()
    if not STRIDE_FILE.exists():
        import stride_engine
        stride_engine.main()

    dfd = json.loads(DFD_FILE.read_text(encoding="utf-8")) if DFD_FILE.exists() else {}
    stride = json.loads(STRIDE_FILE.read_text(encoding="utf-8")) if STRIDE_FILE.exists() else {}

    xml_text = generate_tm7_xml(architecture, dfd, stride, approval)

    OUTPUT_TM7_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_TM7_FILE.write_text(xml_text, encoding="utf-8")

    version = approval.get("architecture_version", 1)
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    version_file = REVIEW_DIR / f"threat_model_v{version}.tm7"
    version_file.write_text(xml_text, encoding="utf-8")

    # Also render visual TM7 / DFD Threat Model Diagrams (.png and .svg)
    render_tm7_visual_diagrams(architecture, dfd, stride, approval)

    return OUTPUT_TM7_FILE


def main() -> None:
    print()
    print("Microsoft Threat Modeling Tool (.tm7) Exporter & Diagram Renderer")
    print("-----------------------------------------------------------------")
    try:
        path = export_tm7()
        print(f"[SUCCESS] Microsoft Threat Modeling Tool (.tm7) XML & visual diagrams generated!")
        print(f"Saved .tm7 XML to: {path.relative_to(BASE_DIR)}")
        print(f"Saved .tm7 PNG to: {OUTPUT_TM7_PNG.relative_to(BASE_DIR)}")
        print(f"Saved .tm7 SVG to: {OUTPUT_TM7_SVG.relative_to(BASE_DIR)}")
    except Exception as err:
        print(f"[FAILED] .tm7 Export Error: {err}")
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
