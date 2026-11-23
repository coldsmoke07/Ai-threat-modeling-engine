"""Security Controls Traceability & Mapping Engine.

Establishes end-to-end security traceability:
Requirement → DFD / Architecture Element → STRIDE Threat → Mitigation → NIST SP 800-53 Security Control.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dfd_generator

BASE_DIR = Path(__file__).resolve().parent
REVIEW_DIR = BASE_DIR / "outputs" / "review"
STRIDE_FILE = BASE_DIR / "outputs" / "stride_threats.json"
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"
OUTPUT_CONTROLS_FILE = BASE_DIR / "outputs" / "security_controls.json"


class SecurityControlsError(RuntimeError):
    """Raised when control mapping fails."""


def map_controls() -> dict[str, Any]:
    approval, _ = dfd_generator.resolve_active_architecture()

    if not STRIDE_FILE.exists():
        import stride_engine
        stride_engine.main()

    if not STRIDE_FILE.exists():
        raise SecurityControlsError("Security control mapping requires STRIDE threat analysis output.")

    with STRIDE_FILE.open("r", encoding="utf-8") as f:
        stride = json.load(f)

    req_catalog = {}
    if REQUIREMENTS_FILE.exists():
        with REQUIREMENTS_FILE.open("r", encoding="utf-8") as f:
            reqs = json.load(f)
            all_req_lists = (
                reqs.get("functional_requirements", [])
                + reqs.get("non_functional_requirements", [])
                + reqs.get("security_requirements", [])
                + reqs.get("compliance_requirements", [])
            )
            for r in all_req_lists:
                if isinstance(r, dict):
                    rid = r.get("requirement_id")
                    if rid:
                        req_catalog[rid] = r

    control_mappings = []
    threats = stride.get("threats", [])

    for count, threat in enumerate(threats, start=1):
        tid = threat.get("threat_id", f"THR-{count}")
        category = threat.get("category", "General")
        target_id = threat.get("target_id", "Unknown")
        target_name = threat.get("target_name", target_id)
        dfd_element_type = threat.get("dfd_element_type", "Element")
        mitigation = threat.get("mitigation", "Implement standard security control")
        req_id = threat.get("requirement_id", "N/A")
        req_info = req_catalog.get(req_id, {})
        req_title = (
            req_info.get("title")
            or req_info.get("category")
            or (req_info.get("description", "")[:50] if req_info.get("description") else "System Security Requirement")
        )

        # Control standard mapping heuristic
        if "encryption" in mitigation.lower() or category == "Information Disclosure":
            control_code = "SC-8 / SC-28"
            control_title = "Transmission & At-Rest Cryptographic Protection (TLS 1.3 / CMK)"
            framework = "NIST SP 800-53 R5"
        elif "authentication" in mitigation.lower() or category == "Spoofing":
            control_code = "IA-2 / IA-8"
            control_title = "Identification & Multi-Factor Authentication (OIDC / MFA / mTLS)"
            framework = "NIST SP 800-53 R5"
        elif "tampering" in category.lower() or "tde" in mitigation.lower():
            control_code = "SI-7"
            control_title = "Software, Firmware, and Information Integrity Verification"
            framework = "NIST SP 800-53 R5"
        elif category == "Denial of Service":
            control_code = "SC-5"
            control_title = "Denial-of-Service Protection, WAF & Rate Limiting"
            framework = "NIST SP 800-53 R5"
        elif category == "Elevation of Privilege":
            control_code = "AC-6"
            control_title = "Least Privilege & Role-Based Access Control (RBAC)"
            framework = "NIST SP 800-53 R5"
        else:
            control_code = "AU-2 / AU-9"
            control_title = "Audit Event Logging & Protection of Audit Information"
            framework = "NIST SP 800-53 R5"

        mapping = {
            "mapping_id": f"MAP-{count:03d}",
            "requirement": {
                "requirement_id": req_id,
                "title": req_title,
            },
            "target_element": target_id,
            "target_name": target_name,
            "dfd_element_type": dfd_element_type,
            "stride_threat": {
                "threat_id": tid,
                "category": category,
                "severity": threat.get("severity", "MEDIUM"),
                "risk_score": threat.get("risk_score", 4),
            },
            "mitigation": mitigation,
            "security_control": {
                "control_id": control_code,
                "control_name": control_title,
                "framework": framework,
                "status": "RECOMMENDED",
            },
        }
        control_mappings.append(mapping)

    report = {
        "controls_schema": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_approval": {
            "status": approval.get("status", "CANDIDATE_ACTIVE"),
            "approved": bool(approval.get("approved")),
            "approved_version": approval.get("architecture_version"),
            "approved_hash": approval.get("architecture_hash"),
        },
        "summary": {
            "total_mapped_controls": len(control_mappings),
            "threats_covered": len(threats),
        },
        "control_traceability_matrix": control_mappings,
    }

    OUTPUT_CONTROLS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CONTROLS_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    version = approval.get("architecture_version", 1)
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    version_file = REVIEW_DIR / f"security_controls_v{version}.json"
    with version_file.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    return report


def main() -> None:
    print()
    print("Security Controls Traceability & Mapping Engine")
    print("-----------------------------------------------")
    try:
        report = map_controls()
        print(f"[SUCCESS] Security Controls Mapping complete!")
        print(f"Total Controls Mapped: {report['summary']['total_mapped_controls']}")
        print(f"Saved to: {OUTPUT_CONTROLS_FILE.relative_to(BASE_DIR)}")
    except Exception as err:
        print(f"[FAILED] Security Controls Error: {err}")
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
