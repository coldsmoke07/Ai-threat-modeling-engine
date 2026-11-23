"""Unified AI Threat Modeling & Architecture Review Pipeline Orchestrator.

Executes all pipeline stages sequentially:
1. PDF Text Extraction
2. AI Requirements Analysis
3. Requirements Validation
4. AI Candidate Architecture Synthesis
5. Architecture Graph Validation
6. Requirement Coverage Reporting
7. STRIDE Threat Modeling Analysis
8. Visual Presentation Metadata Generation
9. Diagram Rendering (PNG / SVG)
10. Initializes Review State & Launches Workbench Web Application (http://127.0.0.1:8081)
"""

from __future__ import annotations

import argparse
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

STEPS = [
    ("pdf_test.py", "1. Extracting text from SRS PDF document"),
    ("requirements_ai.py", "2. Parsing requirements with local AI"),
    ("validate_requirements.py", "3. Validating requirement structure & IDs"),
    ("architecture_ai.py", "4. Synthesizing candidate architecture graph"),
    ("validate_architecture.py", "5. Validating architecture graph & constraints"),
    ("coverage_report.py", "6. Calculating requirement coverage metrics"),
    ("threat_model_ai.py", "7. Performing STRIDE threat modeling analysis"),
    ("presentation_model.py", "8. Generating visual presentation metadata"),
    ("professional_architecture_diagram.py", "9. Rendering SVG/PNG architecture diagrams"),
]


def run_script(script_name: str, description: str) -> bool:
    print(f"\n==================================================")
    print(f"   {description}")
    print(f"   Running: {script_name}")
    print(f"==================================================")
    script_path = BASE_DIR / script_name
    if not script_path.exists():
        print(f"Error: Script {script_name} not found.")
        return False

    cmd = [sys.executable, str(script_path)]
    result = subprocess.run(cmd, cwd=str(BASE_DIR))
    if result.returncode != 0:
        print(f"\n[FAILED] Step '{script_name}' failed with exit code {result.returncode}.")
        return False

    print(f"[SUCCESS] Step '{script_name}' completed successfully.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Threat Modeling Pipeline Orchestrator")
    parser.add_argument("--skip-server", action="store_true", help="Do not launch the web server after processing")
    parser.add_argument("--from-step", type=int, default=1, help="Start pipeline from step number (1-9)")
    args = parser.parse_args()

    print("\n==================================================")
    print("   STARTING AI THREAT MODELING & REVIEW PIPELINE ")
    print("==================================================")

    start_idx = max(1, min(args.from_step, len(STEPS))) - 1
    for script_name, description in STEPS[start_idx:]:
        success = run_script(script_name, description)
        if not success:
            print("\nPipeline execution halted due to errors.")
            sys.exit(1)

    # Always synchronize the Stage 4/5 review artifacts with the newly generated architecture
    try:
        import architecture_review_workflow as workflow
        state = workflow.initialize_review(force_reset=True)
        workflow.print_summary(state)
    except Exception as err:
        print(f"\n[FAILED] Review state initialization failed: {err}")
        sys.exit(1)

    print("\n==================================================")
    print("   ALL PIPELINE GENERATION STAGES COMPLETED ")
    print("==================================================")

    if not args.skip_server:
        print("\nStarting Interactive Review Workflow Server...")
        server_script = BASE_DIR / "app.py"
        subprocess.run([sys.executable, str(server_script)], cwd=str(BASE_DIR))


if __name__ == "__main__":
    main()
