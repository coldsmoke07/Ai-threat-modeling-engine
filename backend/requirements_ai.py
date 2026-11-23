import json
import re
from pathlib import Path
import requests

try:
    from ollama_utils import check_ollama_status, select_model
except ImportError:
    def check_ollama_status():
        return False, "ollama_utils unavailable"

    def select_model():
        return "qwen3:4b"

BASE_DIR = Path(__file__).resolve().parent
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = select_model()

INPUT_FILE = BASE_DIR / "outputs" / "extracted_text.txt"
OUTPUT_FILE = BASE_DIR / "outputs" / "requirements.json"


def load_extracted_text():
    if not INPUT_FILE.exists():
        print("ERROR: extracted_text.txt was not found.")
        print("Run pdf_test.py first.")
        raise SystemExit(1)

    return INPUT_FILE.read_text(encoding="utf-8")


def infer_actor(description: str) -> str:
    desc_lower = description.lower()
    actors = []
    if "guest" in desc_lower:
        actors.append("Guest")
    if "front-desk" in desc_lower or "front desk" in desc_lower:
        actors.append("Front-desk staff")
    if "housekeeping" in desc_lower:
        actors.append("Housekeeping staff")
    if "property manager" in desc_lower or "manager" in desc_lower:
        actors.append("Property manager")
    if "security auditor" in desc_lower or "auditor" in desc_lower:
        actors.append("Security auditor")
    if "customer" in desc_lower or "client application" in desc_lower:
        actors.append("Customer / Client")
    if "administrator" in desc_lower or "admin" in desc_lower:
        actors.append("Administrator")
    if "devops" in desc_lower or "ci/cd" in desc_lower or "pipeline" in desc_lower:
        actors.append("DevOps engineer")
    if "security analyst" in desc_lower:
        actors.append("Security analyst")
    if "staff" in desc_lower and not any("staff" in a.lower() for a in actors):
        actors.append("Staff")
    return ", ".join(actors) if actors else "System"


def infer_security_relevance(title: str, description: str) -> bool:
    combined = f"{title} {description}".lower()
    keywords = (
        "auth", "security", "audit", "payment", "card", "encrypt", "tls",
        "token", "secret", "key vault", "role", "access", "authorized",
        "mfa", "firewall", "waf", "vulnerability", "privacy", "consent",
        "identity", "active directory", "entra", "credential", "certificate",
    )
    return any(k in combined for k in keywords)


def short_title_from_text(title: str, description: str) -> str:
    t = str(title or "").strip()
    d = str(description or "").strip()
    if t and len(t) <= 48 and t.lower() != d.lower():
        return t
    source = t or d
    words = re.sub(r"[^a-zA-Z0-9 /&-]", "", source).split()
    return " ".join(words[:5]).title() if words else "System Requirement"


def extract_requirements_deterministic(document_text: str) -> dict:
    """Deterministically parse formal requirements (FR, NFR, SEC, COM, REQ, SR, SF) from extracted PDF text."""
    lines = [line.strip() for line in document_text.splitlines()]

    # 1. Detect project name
    project_name = "Software System"
    for line in lines:
        if not line or line.startswith("--- PAGE") or line.upper().startswith("SYSTEM REQUIREMENTS"):
            continue
        if "|" in line:
            candidate = line.split("|")[0].strip()
            if candidate and candidate.lower() != "ai threat modeling g3":
                project_name = candidate
                break
        if any(
            phrase in line
            for phrase in (
                "HarborStay Motel",
                "Secure Azure Kubernetes Commerce Platform",
                "Azure Kubernetes-Based Application Platform",
            )
        ):
            project_name = line.strip()
            break

    # 2. Extract actors
    actors = []
    known_actors = [
        ("Guest", "Guest"),
        ("Front-desk staff", "Front-desk staff"),
        ("Housekeeping staff", "Housekeeping staff"),
        ("Property manager", "Property manager"),
        ("Security auditor", "Security auditor"),
        ("Customer", "Customer"),
        ("Administrator", "Administrator"),
        ("DevOps engineer", "DevOps engineer"),
        ("Security analyst", "Security analyst"),
        ("Client Applications", "Client Applications"),
    ]
    for token, label in known_actors:
        if re.search(rf"\b{re.escape(token)}\b", document_text, re.IGNORECASE):
            if label not in actors:
                actors.append(label)
    if not actors:
        actors = ["User", "Administrator", "DevOps Engineer"]

    # 3. Parse formal requirement lines (FR-xxx, NFR-xxx, SEC-xxx, COM-xxx, REQ-xxx, SR-xxx, SF-xxx)
    req_pattern = re.compile(
        r"^((?:FR|NFR|SEC|COM|REQ|SR|SF)-\d{2,3})\s+(.+)$"
    )
    stop_prefixes = (
        "--- PAGE",
        "SYNTHETIC TEST DATA",
        "TEST DATA - NOT FOR PRODUCTION",
        "HarborStay Motel Platform |",
        "AI Threat Modeling G3 |",
        "5.1 Expected",
        "5. Expected",
        "6. Security",
        "6. Required",
        "6. CI/CD",
        "7. Compliance",
        "7. Expected",
        "7. Security",
        "8. Expected",
        "8. Test",
        "8. Non-Functional",
        "9. Explicit",
        "9. Architecture",
        "10. Expected",
        "11. Assumptions",
        "4. Non-functional",
        "4. Functional",
        "3. Functional",
        "Document purpose:",
    )

    raw_items = []
    current_section = "functional"
    i = 0
    while i < len(lines):
        line = lines[i]
        lower_line = line.lower()
        if re.match(r"^\d+\.\s*functional requirements", lower_line):
            current_section = "functional"
        elif re.match(r"^\d+\.\s*non-functional requirements", lower_line):
            current_section = "non_functional"
        elif re.match(r"^\d+\.\s*security requirements", lower_line):
            current_section = "security"
        elif re.match(r"^\d+\.\s*compliance", lower_line):
            current_section = "compliance"
        elif line.startswith("5.1 ") or line.startswith("8. Expected") or line.startswith("9. "):
            current_section = "other"

        match = req_pattern.match(line)
        if match and current_section != "other":
            req_id = match.group(1).strip()
            rest = match.group(2).strip()
            # Fix PDF extraction merged words like "managemeCnIt/CD" -> "management CI/CD"
            rest = rest.replace("managemeCnIt/CD", "management CI/CD")
            i += 1
            while i < len(lines):
                next_line = lines[i]
                if not next_line:
                    i += 1
                    continue
                if req_pattern.match(next_line) or any(next_line.startswith(p) for p in stop_prefixes):
                    break
                if re.match(r"^\d+(\.\d+)?\s+[A-Z]", next_line) or next_line.startswith("ID "):
                    break
                rest += " " + next_line
                i += 1

            title = ""
            description = rest
            sentence_split = re.split(
                r"\s+(?=(?:Guests|Front-desk|The platform|Housekeeping|Authorized|The guest|The 95th|The system|Production|Every production|Guest-facing|Guest profile|All internet-facing|Guest data|API credentials|Public access|Security-relevant|Internet traffic|The company|Final invoices|Customers|The order service|DevOps engineers|The production service|The application tier|Database backups|Central application|Application releases|Application services|All external|Customer data|Users, workloads|Secrets, certificates|Public, application|Container images|Administrative access|The Azure Load Balancer|The Kubernetes Ingress|Backend services|Services requiring|CI/CD shall|AKS shall|Helm charts|Azure Pipelines|Prometheus shall|Elasticsearch shall|Azure Active Directory|Sensitive credentials)\b)",
                rest,
                maxsplit=1,
            )
            if len(sentence_split) == 2:
                title = sentence_split[0].strip()
                description = sentence_split[1].strip()
            else:
                words = rest.split()
                title = " ".join(words[:3])
                description = rest

            raw_items.append((req_id, title, description, current_section))
            continue
        i += 1

    functional_requirements = []
    non_functional_requirements = []
    security_requirements = []
    seen_ids = set()

    for req_id, title, description, section in raw_items:
        if req_id in seen_ids:
            continue
        seen_ids.add(req_id)

        prefix = req_id.split("-")[0]
        sec_rel = infer_security_relevance(title, description)
        clean_title = short_title_from_text(title, description)

        if prefix == "FR" or (prefix == "REQ" and section == "functional"):
            functional_requirements.append({
                "requirement_id": req_id,
                "title": clean_title,
                "description": description,
                "actor": infer_actor(description),
                "security_relevance": sec_rel,
            })
        elif prefix in {"NFR", "SF"} or (prefix == "REQ" and section == "non_functional"):
            non_functional_requirements.append({
                "requirement_id": req_id,
                "title": clean_title,
                "description": description,
                "category": clean_title or "Operational",
                "security_relevance": sec_rel,
            })
        elif prefix in {"SEC", "COM", "SR"} or (prefix == "REQ" and section in {"security", "compliance"}):
            security_requirements.append({
                "requirement_id": req_id,
                "title": clean_title,
                "description": description,
                "category": "Compliance" if prefix == "COM" else "Security",
                "security_relevance": True,
            })

    # Support bullet/table-based Non-Functional and Security requirements (e.g. Azure AKS doc)
    if functional_requirements and not non_functional_requirements and "8. Non-Functional Requirements" in document_text:
        nfr_block = document_text.split("8. Non-Functional Requirements", 1)[1].split("9. Architecture", 1)[0]
        nfr_categories = [
            "Scalability", "Availability", "Performance", "Security",
            "Maintainability", "Observability", "Deployability", "Reliability", "Extensibility"
        ]
        idx = 1
        for cat in nfr_categories:
            m = re.search(rf"\b{cat}\s+([^\n]+(?:\n(?!(?:{'|'.join(nfr_categories)}|\d+\.))[^\n]+)*)", nfr_block)
            if m:
                desc = " ".join(m.group(1).split())
                non_functional_requirements.append({
                    "requirement_id": f"NFR-{idx:02d}",
                    "title": cat,
                    "description": desc,
                    "category": cat,
                    "security_relevance": infer_security_relevance(cat, desc),
                })
                idx += 1

    if functional_requirements and not security_requirements and "7. Security Requirements" in document_text:
        sec_block = document_text.split("7. Security Requirements", 1)[1].split("8. Non-Functional", 1)[0]
        sec_block = re.sub(r"--- PAGE \d+ ---", "", sec_block)
        bullets = [
            " ".join(b.strip().split())
            for b in re.split(r"\(cid:127\)|•", sec_block)
            if b.strip()
        ]
        sec_titles = [
            "RBAC Access Control",
            "No Hardcoded Secrets",
            "Key Vault Secret Storage",
            "VNet Network Isolation",
            "Minimal Port Exposure",
            "Trusted Container Registry",
            "Authorized Audit Visibility",
        ]
        for idx, b in enumerate(bullets, start=1):
            clean_b = re.sub(r"--- PAGE \d+ ---", "", b).strip()
            if clean_b:
                stitle = sec_titles[idx - 1] if idx - 1 < len(sec_titles) else f"Security Control {idx}"
                security_requirements.append({
                    "requirement_id": f"SEC-{idx:02d}",
                    "title": stitle,
                    "description": clean_b,
                    "category": "Security",
                    "security_relevance": True,
                })

    return {
        "project_name": project_name,
        "functional_requirements": functional_requirements,
        "non_functional_requirements": non_functional_requirements,
        "actors": actors,
        "security_requirements": security_requirements,
    }


def merge_and_normalize_requirements(ai_data: dict, deterministic_data: dict) -> dict:
    """Ensure every requirement has clean fields and no formal ID from the document is lost or renumbered."""
    if not isinstance(ai_data, dict):
        return deterministic_data

    det_total = (
        len(deterministic_data.get("functional_requirements", []))
        + len(deterministic_data.get("non_functional_requirements", []))
        + len(deterministic_data.get("security_requirements", []))
    )
    if det_total > 0:
        det_ids = {
            item["requirement_id"]
            for sec in ("functional_requirements", "non_functional_requirements", "security_requirements")
            for item in deterministic_data.get(sec, [])
        }
        ai_ids = {
            str(item.get("requirement_id", "")).strip()
            for sec in ("functional_requirements", "non_functional_requirements", "security_requirements")
            for item in ai_data.get(sec, [])
            if isinstance(item, dict) and item.get("requirement_id")
        }
        if det_ids != ai_ids:
            return deterministic_data

    for sec in ("functional_requirements", "non_functional_requirements", "security_requirements"):
        for item in ai_data.get(sec, []):
            if isinstance(item, dict):
                desc = str(item.get("description") or item.get("title") or "").strip()
                item["description"] = desc
                item["title"] = short_title_from_text(item.get("title", ""), desc)
                if sec == "security_requirements":
                    item["security_relevance"] = True
                    item.setdefault("category", "Compliance" if str(item.get("requirement_id", "")).startswith("COM-") else "Security")
                elif sec == "functional_requirements":
                    item.setdefault("actor", infer_actor(desc))
                    item["security_relevance"] = bool(item.get("security_relevance") or infer_security_relevance(item["title"], desc))
                else:
                    item.setdefault("category", item["title"])
                    item["security_relevance"] = bool(item.get("security_relevance") or infer_security_relevance(item["title"], desc))

    return ai_data


def extract_requirements_with_ai(document_text: str) -> dict:
    deterministic_result = extract_requirements_deterministic(document_text)

    online, status_msg = check_ollama_status()
    if not online:
        print(f"Notice: Ollama unavailable ({status_msg}). Using deterministic requirements parser.")
        return deterministic_result

    system_prompt = """
You are a software requirements analysis assistant.

Your job is to extract requirements ONLY from the provided document.

IMPORTANT RULES:

1. Do not invent requirements.
2. Preserve requirement IDs7 exactly as written in the text (e.g. FR-001, NFR-001, SEC-001, COM-001, REQ-001, FR-01). Extract all statements with requirement IDs.
3. Separate functional, non-functional, and security/compliance requirements. Store COM-xxx compliance requirements inside security_requirements while keeping their exact COM-xxx requirement_id.
4. Extract actors mentioned in the document.
5. Keep descriptions clear and concise, and always provide a short title (2-5 words) separate from description.
6. Return valid JSON only.

Return JSON using exactly this structure:

{
  "project_name": "",
  "functional_requirements": [
    {
      "requirement_id": "",
      "title": "",
      "description": "",
      "actor": "",
      "security_relevance": false
    }
  ],
  "non_functional_requirements": [
    {
      "requirement_id": "",
      "title": "",
      "description": "",
      "category": "",
      "security_relevance": false
    }
  ],
  "actors": [],
  "security_requirements": [
    {
      "requirement_id": "",
      "title": "",
      "description": "",
      "category": "Security",
      "security_relevance": true
    }
  ]
}
"""

    user_prompt = f"""
Analyze the following software requirements document.

DOCUMENT:

{document_text}
"""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "think": False,
        "options": {"temperature": 0.1},
    }

    print("Sending extracted requirements to Ollama...")
    print("Model:", MODEL_NAME)
    print()

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=90)
        response.raise_for_status()
        response_data = response.json()
        ai_content = response_data["message"]["content"]
        ai_parsed = json.loads(ai_content)
        return merge_and_normalize_requirements(ai_parsed, deterministic_result)
    except Exception as err:
        print(f"Notice: Ollama extraction fallback triggered ({err}). Using deterministic requirements parser.")
        return deterministic_result


def save_requirements(data):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def main():
    try:
        print("AI Requirements Extraction")
        print("--------------------------")

        document_text = load_extracted_text()
        print("Characters loaded:", len(document_text))

        requirements = extract_requirements_with_ai(document_text)
        save_requirements(requirements)

        functional_count = len(requirements.get("functional_requirements", []))
        non_functional_count = len(requirements.get("non_functional_requirements", []))
        actor_count = len(requirements.get("actors", []))
        security_count = len(requirements.get("security_requirements", []))

        print("Requirements extraction successful!")
        print()
        print("Project:", requirements.get("project_name", "Unknown"))
        print("Functional requirements:", functional_count)
        print("Non-functional requirements:", non_functional_count)
        print("Security & Compliance requirements:", security_count)
        print("Total formal requirements:", functional_count + non_functional_count + security_count)
        print("Actors:", actor_count)
        print()
        print("Structured requirements saved to:")
        print(OUTPUT_FILE.relative_to(BASE_DIR))

    except Exception as error:
        print()
        print("ERROR:")
        print(error)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()