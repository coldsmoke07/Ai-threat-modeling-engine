import json
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
GRAPHVIZ_BIN = r"C:\Program Files\Graphviz\bin"
os.environ["PATH"] = GRAPHVIZ_BIN + os.pathsep + os.environ.get("PATH", "")

ARCHITECTURE_FILE = BASE_DIR / "outputs" / "architecture_v1.json"
OUTPUT_FOLDER = BASE_DIR / "outputs" / "diagrams"


def load_architecture():
    if not ARCHITECTURE_FILE.exists():
        print("ERROR: architecture_v1.json not found.")
        raise SystemExit(1)

    with ARCHITECTURE_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def generate_diagram(architecture):
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_FOLDER / "architecture_v1"

    if shutil.which("dot") or shutil.which("dot.exe"):
        from graphviz import Digraph

        graph = Digraph("Architecture", format="png")
        graph.attr(
            rankdir="LR",
            label=architecture.get("architecture_name", "Software Architecture"),
            labelloc="t",
            fontsize="20",
        )
        graph.attr("node", shape="box", style="rounded")

        nodes = architecture.get("nodes", [])
        edges = architecture.get("edges", [])
        trust_zones = architecture.get("trust_zones", [])
        defined_zone_names = set()

        for zone in trust_zones:
            zone_id = zone.get("id", "UNKNOWN")
            zone_name = zone.get("name", "Unknown Zone")
            defined_zone_names.add(zone_name)

            with graph.subgraph(name=f"cluster_{zone_id}") as cluster:
                cluster.attr(label=f"Trust Zone: {zone_name}")
                for node in nodes:
                    if node.get("trust_zone") == zone_name:
                        label = f"{node.get('name', 'Unknown')}\n[{node.get('type', 'unknown')}]"
                        cluster.node(node.get("id"), label)

        for node in nodes:
            if node.get("trust_zone") not in defined_zone_names:
                label = f"{node.get('name', 'Unknown')}\n[{node.get('type', 'unknown')}]"
                graph.node(node.get("id"), label)

        for edge in edges:
            labels = []
            if edge.get("protocol"):
                labels.append(edge.get("protocol"))
            if edge.get("data"):
                labels.append(edge.get("data"))
            if edge.get("trust_boundary_crossing"):
                labels.append("Trust Boundary Crossing")
            edge_label = "\n".join(labels)
            graph.edge(edge.get("source"), edge.get("target"), label=edge_label)

        return graph.render(filename=str(output_file), cleanup=True)

    # Built-in Pillow fallback when Graphviz 'dot' binary is not installed
    import architecture_review_workflow as workflow
    presentation = workflow.load_optional_presentation()
    layout = workflow.build_layout(architecture, presentation)
    png_path = output_file.with_suffix(".png")
    workflow.render_png(png_path, architecture, presentation, layout, version=1)
    return str(png_path.relative_to(BASE_DIR))


def main():
    print()
    print("Architecture Diagram Generation")
    print("-------------------------------")
    print()

    try:
        architecture = load_architecture()
        print("Architecture:", architecture.get("architecture_name", "Unknown"))
        print("Nodes:", len(architecture.get("nodes", [])))
        print("Data flows:", len(architecture.get("edges", [])))
        print("Trust zones:", len(architecture.get("trust_zones", [])))
        print()
        print("Generating diagram...")
        result = generate_diagram(architecture)
        print()
        print("Architecture diagram generated successfully!")
        print()
        print("Saved to:")
        print(result)
    except Exception as error:
        print()
        print("ERROR:")
        print(error)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()