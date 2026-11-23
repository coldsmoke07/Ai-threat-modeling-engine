import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / "outputs" / "requirements.json"


def load_requirements():
    if not REQUIREMENTS_FILE.exists():
        print("ERROR: requirements.json was not found.")
        raise SystemExit(1)

    with REQUIREMENTS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_requirement_list(requirements, category):
    errors = []
    ids = []

    if not isinstance(requirements, list):
        return [f"{category} section must be a list."], []

    for index, requirement in enumerate(requirements, start=1):
        if not isinstance(requirement, dict):
            errors.append(f"{category} #{index}: Entry must be a JSON object")
            continue

        requirement_id = str(requirement.get("requirement_id") or "").strip()
        description = str(requirement.get("description") or "").strip()

        if not requirement_id:
            errors.append(f"{category} #{index}: Missing requirement_id")
        else:
            ids.append(requirement_id)

        if not description:
            errors.append(f"{requirement_id or index}: Missing description")

    duplicates = sorted({
        requirement_id
        for requirement_id in ids
        if ids.count(requirement_id) > 1
    })

    for duplicate in duplicates:
        errors.append(f"Duplicate requirement ID in {category}: {duplicate}")

    return errors, ids


def main():
    print("Requirements Validation")
    print("-----------------------")

    try:
        data = load_requirements()
    except json.JSONDecodeError as err:
        print(f"INVALID: requirements.json contains bad JSON ({err}).")
        raise SystemExit(1) from err

    required_sections = [
        "project_name",
        "functional_requirements",
        "non_functional_requirements",
        "actors",
        "security_requirements",
    ]

    errors = []

    for section in required_sections:
        if section not in data:
            errors.append(f"Missing section: {section}")

    functional = data.get("functional_requirements", [])
    non_functional = data.get("non_functional_requirements", [])
    security = data.get("security_requirements", [])

    functional_errors, functional_ids = validate_requirement_list(
        functional, "Functional requirement"
    )
    non_functional_errors, non_functional_ids = validate_requirement_list(
        non_functional, "Non-functional requirement"
    )
    security_errors, security_ids = validate_requirement_list(
        security, "Security requirement"
    )

    errors.extend(functional_errors)
    errors.extend(non_functional_errors)
    errors.extend(security_errors)

    all_ids = functional_ids + non_functional_ids + security_ids

    duplicate_all = sorted({
        requirement_id
        for requirement_id in all_ids
        if all_ids.count(requirement_id) > 1
    })

    for duplicate in duplicate_all:
        message = f"Requirement ID appears more than once: {duplicate}"
        if message not in errors:
            errors.append(message)

    actors = data.get("actors", [])
    if not isinstance(actors, list):
        errors.append("Actors must be stored as a list.")

    print()
    print("Project:", data.get("project_name", "Unknown"))
    print("Functional requirements:", len(functional) if isinstance(functional, list) else 0)
    print("Non-functional requirements:", len(non_functional) if isinstance(non_functional, list) else 0)
    print("Security & Compliance requirements:", len(security) if isinstance(security, list) else 0)
    print("Total formal requirements:", len(all_ids))
    print("Actors:", len(actors) if isinstance(actors, list) else 0)
    print()

    if errors:
        print("VALIDATION FAILED")
        print()
        for error in errors:
            print("ERROR:", error)
        raise SystemExit(1)
    else:
        print("VALIDATION PASSED")
        print()
        print("All requirement IDs and required fields are valid.")


if __name__ == "__main__":
    main()