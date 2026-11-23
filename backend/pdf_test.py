import pdfplumber
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUT_PATH = BASE_DIR / "outputs" / "extracted_text.txt"
ACTIVE_PDF_MARKER = BASE_DIR / "outputs" / "active_pdf.txt"

pdf_files = list(UPLOADS_DIR.glob("*.pdf")) if UPLOADS_DIR.exists() else []
if not pdf_files:
    print("ERROR: No PDF file found in uploads/ folder.")
    raise SystemExit(1)

selected_pdf = None
if ACTIVE_PDF_MARKER.exists():
    marker_name = ACTIVE_PDF_MARKER.read_text(encoding="utf-8").strip()
    if marker_name and (UPLOADS_DIR / marker_name).exists():
        selected_pdf = UPLOADS_DIR / marker_name

if selected_pdf is None:
    pdf_files.sort(key=lambda p: (p.stat().st_mtime, p.name != "z_latest.pdf"), reverse=True)
    selected_pdf = pdf_files[0]

PDF_PATH = selected_pdf
print(f"Reading PDF: {PDF_PATH.name}...")

all_text = []

with pdfplumber.open(PDF_PATH) as pdf:
    print(f"Total pages: {len(pdf.pages)}")

    for page_number, page in enumerate(pdf.pages, start=1):
        text = page.extract_text()
        if text:
            all_text.append(f"\n--- PAGE {page_number} ---\n{text}")

final_text = "\n".join(all_text)

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as file:
    file.write(final_text)

print()
print("PDF extraction successful!")
print(f"Text saved to: {OUTPUT_PATH.relative_to(BASE_DIR)}")
print("Characters extracted:", len(final_text))