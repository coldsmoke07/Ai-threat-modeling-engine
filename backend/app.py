"""AI Threat Modeling G3 - Master Server & Single-Page Application (SPA) Workbench.

Combines the complete local REST API backend and interactive SPA workbench frontend into a single
executable web application running at http://127.0.0.1:8081.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# Import internal pipeline modules
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

try:
    from ollama_utils import check_ollama_status, select_model, get_available_models
except ImportError:
    def check_ollama_status() -> tuple[bool, str]:
        return True, "OK"

    def select_model() -> str:
        return "qwen3:4b"

    def get_available_models() -> list[str]:
        return ["qwen3:4b"]

import architecture_review_workflow as workflow
import run_pipeline

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
MAX_REQUEST_BYTES = 15 * 1024 * 1024

PIPELINE_LOCK = threading.Lock()
PIPELINE_STATUS: dict[str, Any] = {
    "running": False,
    "current_step": "Idle",
    "step_index": 0,
    "total_steps": len(run_pipeline.STEPS),
    "steps": [
        {"index": idx, "script": script, "description": desc, "status": "completed"}
        for idx, (script, desc) in enumerate(run_pipeline.STEPS, start=1)
    ],
    "logs": ["Ready to run pipeline steps..."],
    "error": None,
    "finished": False,
}


def run_single_pipeline_step(step_index: int, reset_logs: bool = False) -> tuple[bool, str]:
    """Execute a single pipeline step (1..9) synchronously and update PIPELINE_STATUS."""
    global PIPELINE_STATUS
    steps = run_pipeline.STEPS
    if step_index < 1 or step_index > len(steps):
        return False, f"Invalid step index: {step_index}"

    script, desc = steps[step_index - 1]
    with PIPELINE_LOCK:
        PIPELINE_STATUS["running"] = True
        PIPELINE_STATUS["finished"] = False
        PIPELINE_STATUS["error"] = None
        PIPELINE_STATUS["step_index"] = step_index
        PIPELINE_STATUS["current_step"] = desc
        if reset_logs:
            PIPELINE_STATUS["logs"] = []
            for s in PIPELINE_STATUS["steps"]:
                s["status"] = "pending"
        PIPELINE_STATUS["steps"][step_index - 1]["status"] = "running"
        PIPELINE_STATUS["logs"].append(f"▶ Step {step_index}/{len(steps)}: {desc} ({script})...")

    cmd = [sys.executable, str(BASE_DIR / script)]
    res = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True, errors="replace")
    output_text = (res.stdout or "").strip()
    err_text = (res.stderr or "").strip()

    if res.returncode != 0:
        err_msg = f"Step {step_index} ('{script}') failed with exit code {res.returncode}:\n{err_text or output_text}"
        with PIPELINE_LOCK:
            PIPELINE_STATUS["running"] = False
            PIPELINE_STATUS["error"] = err_msg
            PIPELINE_STATUS["steps"][step_index - 1]["status"] = "failed"
            PIPELINE_STATUS["logs"].append(f"[FAILED] {err_msg}")
        return False, err_msg

    # If Step 9 finished (or architecture_v1.json was updated), initialize/sync review & downstream artifacts
    if step_index == len(steps):
        try:
            workflow.initialize_review(force_reset=True)
        except Exception as reset_err:
            output_text += f"\nReview sync note: {reset_err}"

    with PIPELINE_LOCK:
        PIPELINE_STATUS["steps"][step_index - 1]["status"] = "completed"
        if output_text:
            PIPELINE_STATUS["logs"].append(output_text)
        PIPELINE_STATUS["logs"].append(f"[SUCCESS] Step {step_index}/{len(steps)} ({script}) completed.\n")
        if step_index == len(steps):
            PIPELINE_STATUS["running"] = False
            PIPELINE_STATUS["finished"] = True
            PIPELINE_STATUS["current_step"] = "All 9 Steps Complete! Proceed to Stage 2 (Requirements) or Stage 4 (Human Review)."
            PIPELINE_STATUS["logs"].append("🎉 [COMPLETE] All 9 pipeline stages and downstream DFD/STRIDE/TM7 models are ready!")
        else:
            PIPELINE_STATUS["running"] = False

    return True, output_text


def execute_pipeline_worker() -> None:
    for idx in range(1, len(run_pipeline.STEPS) + 1):
        ok, _ = run_single_pipeline_step(idx, reset_logs=(idx == 1))
        if not ok:
            return


SPA_HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Threat Modeling G3 — Workbench</title>
  <style>
    :root {
      --primary: #0078D4; --primary-dark: #005A9E; --bg: #F3F6F9; --surface: #FFFFFF;
      --border: #E1E6EB; --text: #1F2937; --muted: #6B7280; --ok: #107C10; --warn: #D97706; --bad: #D13438;
      --sidebar-width: 245px;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: var(--text); background: var(--bg); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
    header { background: #06284B; color: white; height: 50px; display: flex; align-items: center; justify-content: space-between; padding: 0 18px; border-bottom: 1px solid #1E3A5F; flex-shrink: 0; }
    header h1 { font-size: 16px; margin: 0; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    header .status-badge { background: #1E3A5F; padding: 4px 10px; border-radius: 999px; font-size: 11px; color: #E2E8F0; }
    
    .app-shell { display: flex; flex: 1; overflow: hidden; }
    
    /* Stage Rail Navigation */
    .stage-rail { width: var(--sidebar-width); background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; overflow-y: auto; }
    .stage-rail-header { padding: 14px 16px 8px; font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .stage-item { display: flex; align-items: center; gap: 10px; padding: 10px 16px; font-size: 13px; font-weight: 500; color: var(--text); cursor: pointer; border-left: 3px solid transparent; text-decoration: none; transition: all 0.15s; }
    .stage-item:hover { background: #F8FAFC; }
    .stage-item.active { background: #EFF6FF; border-left-color: var(--primary); color: var(--primary); font-weight: 600; }
    .stage-item .num { width: 22px; height: 22px; border-radius: 50%; background: #E2E8F0; color: #475569; font-size: 11px; display: flex; align-items: center; justify-content: center; font-weight: 600; flex-shrink: 0; }
    .stage-item.active .num { background: var(--primary); color: white; }
    .stage-item.completed .num { background: var(--ok); color: white; }

    /* Main Workspace */
    .workspace { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg); }
    .stage-view { display: none; flex: 1; flex-direction: column; padding: 20px; overflow-y: auto; }
    .stage-view.active { display: flex; }
    
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .card h2 { margin: 0 0 12px; font-size: 16px; font-weight: 600; }
    .card h3 { margin: 12px 0 8px; font-size: 14px; font-weight: 600; color: #334155; }

    /* Buttons & Form Controls */
    button, .btn { background: var(--primary); color: white; border: none; border-radius: 6px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
    button.secondary, .btn.secondary { background: #E2E8F0; color: #1E293B; }
    button.approve, .btn.approve { background: var(--ok); }
    button.danger, .btn.danger { background: var(--bad); }
    button.small, .btn.small { padding: 5px 10px; font-size: 11px; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    input[type=text], textarea, select { width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; font-family: inherit; margin-top: 4px; }
    
    /* Status Badges & Notices */
    .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; background: #E2E8F0; color: #334155; white-space: nowrap; }
    .badge.functional { background: #E0F2FE; color: #0369A1; }
    .badge.non_functional { background: #F3E8FF; color: #6B21A8; }
    .badge.security, .badge.compliance { background: #FEE2E2; color: #991B1B; }
    .badge.HIGH, .badge.failed { background: #FEE2E2; color: #991B1B; }
    .badge.MEDIUM, .badge.running { background: #FEF3C7; color: #92400E; }
    .badge.LOW, .badge.completed { background: #D1FAE5; color: #065F46; }
    .badge.dfd-type { background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; }
    .notice { padding: 10px 14px; border-radius: 6px; background: #EFF6FF; color: #1E40AF; border: 1px solid #BFDBFE; font-size: 13px; margin-bottom: 12px; }
    .notice.ok { background: #ECFDF5; color: #065F46; border-color: #A7F3D0; }
    .notice.bad { background: #FEF2F2; color: #991B1B; border-color: #FCA5A5; }
    
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 10px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { background: #F8FAFC; color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.3px; }
    .diagram-img { width: 100%; max-height: 560px; object-fit: contain; border: 1px solid var(--border); border-radius: 8px; background: #FFFFFF; padding: 6px; }
    .stage-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
    .kpi-box { background: #F8FAFC; border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; }
    .kpi-box .label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; }
    .kpi-box .val { font-size: 20px; font-weight: 700; margin-top: 4px; color: var(--text); }
  </style>
</head>
<body>

<header>
  <h1><span>🛡️</span> AI Threat Modeling G3 Workbench</h1>
  <div style="display:flex; align-items:center; gap:12px;">
    <span class="status-badge" id="activeProjectBadge">Project: Loading...</span>
    <span class="status-badge" id="ollamaStatus">Ollama: Checking...</span>
    <span class="status-badge" id="appVersion">Version 1.0</span>
  </div>
</header>

<div class="app-shell">
  <!-- Stage Rail Left Sidebar -->
  <nav class="stage-rail">
    <div class="stage-rail-header">Pipeline Stages</div>
    <a class="stage-item active" data-stage="1" onclick="switchStage(1)"><span class="num">1</span> Upload & Pipeline</a>
    <a class="stage-item" data-stage="2" onclick="switchStage(2)"><span class="num">2</span> Requirements</a>
    <a class="stage-item" data-stage="3" onclick="switchStage(3)"><span class="num">3</span> Architecture</a>
    <a class="stage-item" data-stage="4" onclick="switchStage(4)"><span class="num">4</span> Human Review</a>
    <a class="stage-item" data-stage="5" onclick="switchStage(5)"><span class="num">5</span> Approval Gate</a>
    <a class="stage-item" data-stage="6" onclick="switchStage(6)"><span class="num">6</span> DFD Engine</a>
    <a class="stage-item" data-stage="7" onclick="switchStage(7)"><span class="num">7</span> STRIDE Threats</a>
    <a class="stage-item" data-stage="8" onclick="switchStage(8)"><span class="num">8</span> Risk Matrix</a>
    <a class="stage-item" data-stage="9" onclick="switchStage(9)"><span class="num">9</span> Controls</a>
    <a class="stage-item" data-stage="10" onclick="switchStage(10)"><span class="num">10</span> Final Output & TM7</a>
  </nav>

  <!-- Main Stage Workspace -->
  <div class="workspace">
    
    <!-- Stage 1: PDF Upload & Step-by-Step Pipeline -->
    <div class="stage-view active" id="stage-1">
      <div class="card">
        <h2>1. Upload System Requirements PDF & Execute Pipeline One-by-One</h2>
        <p style="color:var(--muted); font-size:13px;">Select your SRS requirements PDF and run all 9 pipeline stages sequentially one-by-one (or trigger any individual step below).</p>
        <div style="border: 2px dashed var(--border); border-radius: 8px; padding: 24px; text-align: center; background: #F8FAFC; margin: 12px 0;">
          <input type="file" id="pdfFile" accept=".pdf" style="display:none" onchange="handleFileSelect()">
          <button onclick="document.getElementById('pdfFile').click()">📄 Choose Requirements PDF</button>
          <div id="pdfFileName" style="margin-top:8px; font-weight:600; font-size:13px; color:var(--primary);">Using active PDF in uploads/ (or select a new PDF above)</div>
        </div>
        <div style="display:flex; gap:10px; align-items:center;">
          <button class="approve" id="startPipelineBtn" onclick="runFullPipeline()">▶ Start Automated Pipeline (Run Steps 1–9 One-by-One)</button>
          <span id="pipelineProgressText" style="font-size:13px; font-weight:600; color:var(--muted);">Ready</span>
        </div>
      </div>

      <div class="card">
        <h2>Step-by-Step Pipeline Execution Tracker (Steps 1 to 9)</h2>
        <table id="stepsTable">
          <thead>
            <tr><th style="width:60px;">Step</th><th>Pipeline Stage Description</th><th>Module Script</th><th style="width:120px;">Status</th><th style="width:120px;">Action</th></tr>
          </thead>
          <tbody id="stepsTableBody"></tbody>
        </table>
      </div>

      <div class="card">
        <h2>Live Pipeline Console Output</h2>
        <pre id="pipelineLog" style="background:#0F172A; color:#E2E8F0; padding:12px; border-radius:6px; font-size:12px; height:180px; overflow-y:auto; white-space:pre-wrap;">Ready to start pipeline...</pre>
        <div class="stage-footer">
          <span></span>
          <button class="approve" onclick="switchStage(2)">Proceed to Stage 2: Requirements &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 2: Requirements Workspace & Add Form -->
    <div class="stage-view" id="stage-2">
      <div class="card">
        <h2>2. System Requirements & Architecture Traceability Matrix</h2>
        <div id="reqSummary" class="notice ok">Loading requirements...</div>
        <div style="overflow-x:auto;">
          <table id="reqTable">
            <thead>
              <tr>
                <th style="width:90px;">ID</th>
                <th style="width:160px;">Title</th>
                <th>Full Requirement Description</th>
                <th style="width:110px;">Category</th>
                <th style="width:130px;">Actor / Scope</th>
                <th style="width:90px;">Security</th>
                <th style="width:200px;">Mapped Architecture Elements</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h2>➕ Add Custom Requirement (Auto-Mapped to Architecture)</h2>
        <div style="display:grid; grid-template-columns: 1fr 2fr 1fr; gap:12px; margin-top:10px;">
          <div>
            <label>Requirement ID</label>
            <input type="text" id="addReqId" placeholder="e.g. SEC-009 or REQ-026">
          </div>
          <div>
            <label>Short Title</label>
            <input type="text" id="addReqTitle" placeholder="e.g. Multi-Tenant Data Isolation">
          </div>
          <div>
            <label>Category</label>
            <select id="addReqCategory">
              <option value="functional">Functional</option>
              <option value="non_functional">Non-Functional</option>
              <option value="security">Security / Compliance</option>
            </select>
          </div>
        </div>
        <div style="margin-top:10px;">
          <label>Description</label>
          <textarea id="addReqDesc" rows="2" placeholder="Detailed description of the requirement..."></textarea>
        </div>
        <div style="margin-top:10px; display:flex; align-items:center; justify-content:space-between;">
          <label><input type="checkbox" id="addReqSec"> Security Relevant</label>
          <button class="approve" onclick="addCustomRequirement()">Add & Map Requirement to System</button>
        </div>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(1)">&larr; Back to Stage 1</button>
          <button class="approve" onclick="switchStage(3)">Proceed to Stage 3: Architecture &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 3: Architecture & Coverage -->
    <div class="stage-view" id="stage-3">
      <div class="card">
        <h2>3. Candidate Architecture & Requirement Coverage Analysis</h2>
        <div id="coverageNotice" class="notice ok">Loading coverage...</div>
      </div>
      <div class="card">
        <h2>Architecture Components (Nodes)</h2>
        <table id="nodesTable">
          <thead><tr><th>Node ID</th><th>Component Name</th><th>Type</th><th>Trust Zone</th><th>Mapped Requirement IDs</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="card">
        <h2>Architecture Data Flows (Edges)</h2>
        <table id="flowsTable">
          <thead><tr><th>Flow ID</th><th>Source &rarr; Target</th><th>Protocol</th><th>Data Payload</th><th>Encryption</th><th>Authentication</th><th>Mapped Req IDs</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(2)">&larr; Back to Stage 2</button>
          <button class="approve" onclick="switchStage(4)">Proceed to Stage 4: Human Review &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 4: Human Review Workbench -->
    <div class="stage-view" id="stage-4">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <h2 style="margin:0;">4. Interactive Architecture Diagram Review & AI Editor</h2>
          <div>
            <span class="badge completed" id="stage4VersionBadge">v1</span>
            <button class="secondary small" onclick="refreshDiagramsNow()">🔄 Refresh Diagram</button>
          </div>
        </div>
        <div id="previewBanner" class="notice bad" style="display:none;"></div>
        <img id="reviewDiagram" class="diagram-img" alt="Architecture Diagram">
        <div style="margin-top:12px; display:flex; flex-wrap:wrap; gap:8px;">
          <a id="downloadPngBtn" class="btn secondary" href="/artifact/current.png" download="architecture_review.png">⬇ Download PNG</a>
          <a id="downloadDrawioBtn" class="btn secondary" href="/artifact/current.drawio" download="architecture_review.drawio">⬇ Download .drawio XML (Edit in diagrams.net)</a>
          <button id="acceptPreviewBtn" class="approve" style="display:none;" onclick="acceptPreview()">✅ Accept Preview & Save New Version</button>
          <button id="discardPreviewBtn" class="danger" style="display:none;" onclick="discardPreview()">✖ Discard Preview</button>
        </div>
      </div>
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
        <div class="card">
          <h2>📤 Upload Edited Diagram (.drawio, .xml, .svg, .png, .jpg)</h2>
          <p style="color:var(--muted); font-size:12px;">Download the <code>.drawio</code> file above, add/remove/move/rename components in draw.io (or select any custom diagram image/XML), and upload it below to preview & apply.</p>
          <input type="file" id="drawioUpload" accept=".drawio,.xml,.svg,.png,.jpg,.jpeg">
          <button style="margin-top:10px;" onclick="uploadDrawio()">Upload & Show New Diagram Preview</button>
        </div>
        <div class="card">
          <h2>🤖 Make Changes in Diagram Using AI</h2>
          <p style="color:var(--muted); font-size:12px;">Examples: <i>"Add a Redis Cache between ReservationService and PrimaryDatabase"</i>, <i>"Add a Fraud Detection Service connected to PaymentService"</i>, <i>"Remove EmailSmsProvider"</i>, or <i>"Rename EdgeGateway to Cloudflare WAF"</i>.</p>
          <textarea id="aiPrompt" rows="3" placeholder="Describe the component or flow to add, remove, rename, or connect..."></textarea>
          <button style="margin-top:10px;" id="aiPromptBtn" onclick="sendAiPrompt()">✨ Apply AI Change to Diagram</button>
        </div>
      </div>
      <div class="card">
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(3)">&larr; Back to Stage 3</button>
          <button class="approve" onclick="switchStage(5)">Proceed to Stage 5: Approval Gate &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 5: Approval Gate & Audit History -->
    <div class="stage-view" id="stage-5">
      <div class="card">
        <h2>5. SHA-256 Architecture Approval Gate (Cryptographic Sign-Off)</h2>
        <div class="notice ok">
          Active Architecture Version: <b id="appVersionText">v1</b> &nbsp;|&nbsp;
          Approval Status: <b id="appGateStatusText">PENDING_REVIEW</b><br>
          Canonical SHA-256 Hash: <code id="appHashText">-</code>
        </div>
        <p style="color:var(--muted); font-size:13px;">Enter your Reviewer Name and check the confirmation box below to cryptographically sign this architecture version and lock Phase 2 outputs (DFD, STRIDE Threats, Risk Matrix, Security Controls, and .TM7 Export + Visual Diagrams).</p>
        <label>Reviewer Name</label>
        <input type="text" id="reviewerName" placeholder="e.g. Shantanu (Security Architect)" value="Shantanu (Security Architect)">
        <label style="margin-top:10px; display:block;">
          <input type="checkbox" id="confirmCheckbox" checked> I confirm that I have reviewed the architecture diagram, diff, and 100% requirement coverage metrics.
        </label>
        <button class="approve" style="margin-top:12px;" onclick="approveArchitecture()">🔏 Approve Exact Version & SHA-256 Hash (Lock & Sign Phase 2)</button>
      </div>
      <div class="card">
        <h2>Approval Audit History Log</h2>
        <div id="approvalHistoryLog" style="font-size:13px; color:var(--muted)">No prior approvals recorded.</div>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(4)">&larr; Back to Stage 4</button>
          <button class="approve" onclick="switchStage(6)">Proceed to Stage 6: DFD Engine &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 6: DFD Engine Breakdown -->
    <div class="stage-view" id="stage-6">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h2 style="margin:0;">6. Data Flow Diagram (DFD) Element Breakdown (1-to-1 Matched with Risk Matrix)</h2>
            <p style="color:var(--muted); font-size:12.5px; margin:4px 0 0;">Every DFD Process, Data Store, External Entity, and Data Flow below maps directly to the STRIDE Threats & Risk Matrix on Stages 7 & 8.</p>
          </div>
          <button class="secondary" onclick="generateDownstream()">🔄 Re-Sync DFD, STRIDE & .TM7</button>
        </div>
      </div>
      <div class="card">
        <h3>Processes (Compute / Application / Gateway Services)</h3>
        <table id="dfdProcessesTable">
          <thead><tr><th>DFD ID</th><th>Process Name</th><th>Component Type</th><th>Trust Zone</th><th>Requirements</th><th>Matched STRIDE Threats & Max Risk</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="card">
        <h3>Data Stores (Databases / Caches / Vaults / Audit Logs)</h3>
        <table id="dfdStoresTable">
          <thead><tr><th>DFD ID</th><th>Data Store Name</th><th>Component Type</th><th>Trust Zone</th><th>Requirements</th><th>Matched STRIDE Threats & Max Risk</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="card">
        <h3>External Entities (Clients / Human Portals / Third-Party Providers)</h3>
        <table id="dfdEntitiesTable">
          <thead><tr><th>DFD ID</th><th>External Entity Name</th><th>Component Type</th><th>Trust Zone</th><th>Requirements</th><th>Matched STRIDE Threats & Max Risk</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="card">
        <h3>Data Flows (Edges & Trust Boundary Crossings)</h3>
        <table id="dfdFlowsTable">
          <thead><tr><th>Flow ID</th><th>Source &rarr; Target</th><th>Protocol & Encryption</th><th>Data Payload</th><th>Boundary Crossing</th><th>Matched STRIDE Threats & Max Risk</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(5)">&larr; Back to Stage 5</button>
          <button class="approve" onclick="switchStage(7)">Proceed to Stage 7: STRIDE Threats &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 7: STRIDE Threat Workbench -->
    <div class="stage-view" id="stage-7">
      <div class="card">
        <h2>7. STRIDE Security Threat Workbench (Mapped to DFD Elements)</h2>
        <div id="strideDfdSummary" class="notice ok">Loading STRIDE-to-DFD alignment...</div>
        <table id="strideTable">
          <thead><tr><th>Threat ID</th><th>STRIDE Category</th><th>Severity</th><th>DFD Element Type</th><th>Target DFD Element</th><th>Threat Title & Description</th><th>Recommended Mitigation Control</th><th>Req ID</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(6)">&larr; Back to Stage 6</button>
          <button class="approve" onclick="switchStage(8)">Proceed to Stage 8: Risk Matrix &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 8: Risk Ranking Matrix -->
    <div class="stage-view" id="stage-8">
      <div class="card">
        <h2>8. DFD-Aligned Risk Ranking Matrix (Likelihood &times; Impact)</h2>
        <div id="riskSummaryCards" class="kpi-grid">
          <div class="kpi-box">
            <div class="label">TOTAL DFD THREATS</div>
            <div id="riskTotalCount" class="val">0</div>
          </div>
          <div class="kpi-box" style="background:#FEE2E2; border-color:#FCA5A5;">
            <div class="label" style="color:#991B1B">HIGH RISK (SCORE 6–9)</div>
            <div id="riskHighCount" class="val" style="color:#991B1B">0</div>
          </div>
          <div class="kpi-box" style="background:#FEF3C7; border-color:#FCD34D;">
            <div class="label" style="color:#92400E">MEDIUM RISK (SCORE 3–5)</div>
            <div id="riskMedCount" class="val" style="color:#92400E">0</div>
          </div>
          <div class="kpi-box" style="background:#D1FAE5; border-color:#6EE7B7;">
            <div class="label" style="color:#065F46">LOW RISK (SCORE 1–2)</div>
            <div id="riskLowCount" class="val" style="color:#065F46">0</div>
          </div>
        </div>
        
        <h3>3&times;3 Risk Matrix Grid (Likelihood vs Impact)</h3>
        <div style="display:grid; grid-template-columns: 110px repeat(3, 1fr); gap:6px; margin:16px 0; font-size:12px; text-align:center;">
          <div></div><div><b>Impact 1 (Low)</b></div><div><b>Impact 2 (Medium)</b></div><div><b>Impact 3 (High)</b></div>
          <div style="font-weight:600; display:flex; align-items:center; justify-content:center;">Likelihood 3 (High)</div>
          <div style="background:#FEF3C7; padding:14px; border-radius:6px;">Score 3 (MEDIUM)<br><b id="cell_3_1">0 threats</b></div>
          <div style="background:#FEE2E2; padding:14px; border-radius:6px;">Score 6 (HIGH)<br><b id="cell_3_2">0 threats</b></div>
          <div style="background:#FEE2E2; padding:14px; border-radius:6px;">Score 9 (HIGH)<br><b id="cell_3_3">0 threats</b></div>
          <div style="font-weight:600; display:flex; align-items:center; justify-content:center;">Likelihood 2 (Med)</div>
          <div style="background:#D1FAE5; padding:14px; border-radius:6px;">Score 2 (LOW)<br><b id="cell_2_1">0 threats</b></div>
          <div style="background:#FEF3C7; padding:14px; border-radius:6px;">Score 4 (MEDIUM)<br><b id="cell_2_2">0 threats</b></div>
          <div style="background:#FEE2E2; padding:14px; border-radius:6px;">Score 6 (HIGH)<br><b id="cell_2_3">0 threats</b></div>
          <div style="font-weight:600; display:flex; align-items:center; justify-content:center;">Likelihood 1 (Low)</div>
          <div style="background:#D1FAE5; padding:14px; border-radius:6px;">Score 1 (LOW)<br><b id="cell_1_1">0 threats</b></div>
          <div style="background:#D1FAE5; padding:14px; border-radius:6px;">Score 2 (LOW)<br><b id="cell_1_2">0 threats</b></div>
          <div style="background:#FEF3C7; padding:14px; border-radius:6px;">Score 3 (MEDIUM)<br><b id="cell_1_3">0 threats</b></div>
        </div>
      </div>

      <div class="card">
        <h3>Categorized DFD Risk Ranking Table</h3>
        <table id="riskTable">
          <thead><tr><th>Threat ID</th><th>STRIDE Category</th><th>DFD Element Type</th><th>Target DFD Element</th><th>Likelihood</th><th>Impact</th><th>Risk Score</th><th>Severity</th><th>Title</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(7)">&larr; Back to Stage 7</button>
          <button class="approve" onclick="switchStage(9)">Proceed to Stage 9: Security Controls &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 9: Security Controls Matrix -->
    <div class="stage-view" id="stage-9">
      <div class="card">
        <h2>9. NIST SP 800-53 R5 Security Control Traceability Matrix</h2>
        <table id="controlsTable">
          <thead><tr><th>Mapping ID</th><th>System Requirement</th><th>DFD Element</th><th>STRIDE Threat</th><th>NIST SP 800-53 Control</th><th>Mitigation Implementation</th><th>Status</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(8)">&larr; Back to Stage 8</button>
          <button class="approve" onclick="switchStage(10)">Proceed to Stage 10: Final Output & Diagrams &rarr;</button>
        </div>
      </div>
    </div>

    <!-- Stage 10: Complete End Output, Final Architecture Diagram & Visual .TM7 Threat Model Diagram -->
    <div class="stage-view" id="stage-10">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <div>
            <h2 style="margin:0;">10. Final End-of-Pipeline Deliverable Report, Architecture Diagram &amp; .TM7 Threat Model Diagram</h2>
            <p style="color:var(--muted); font-size:13px; margin:4px 0 0;">Complete end-to-end threat modeling output package with visual Architecture Diagram, visual Microsoft Threat Modeling Tool (.TM7 / DFD) Diagram, and downloadable artifacts.</p>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="approve" onclick="window.print()">🖨️ Print / Save Full End Report as PDF</button>
            <button class="secondary" onclick="generateDownstream()">🔄 Regenerate All Final Outputs</button>
          </div>
        </div>

        <div class="kpi-grid" style="margin-top:14px;">
          <div class="kpi-box">
            <div class="label">ARCHITECTURE VERSION</div>
            <div class="val" id="endArchVersion">v1</div>
          </div>
          <div class="kpi-box">
            <div class="label">APPROVAL STATUS</div>
            <div class="val" id="endApprovalStatus" style="font-size:15px;">APPROVED</div>
          </div>
          <div class="kpi-box" style="background:#ECFDF5; border-color:#A7F3D0;">
            <div class="label" style="color:#065F46">REQ COVERAGE</div>
            <div class="val" id="endCoverageVal" style="color:#065F46">100%</div>
          </div>
          <div class="kpi-box">
            <div class="label">DFD ELEMENTS</div>
            <div class="val" id="endDfdCount">0</div>
          </div>
          <div class="kpi-box" style="background:#FEE2E2; border-color:#FCA5A5;">
            <div class="label" style="color:#991B1B">STRIDE THREATS</div>
            <div class="val" id="endThreatCount" style="color:#991B1B">0</div>
          </div>
          <div class="kpi-box" style="background:#EFF6FF; border-color:#BFDBFE;">
            <div class="label" style="color:#1D4ED8">NIST CONTROLS</div>
            <div class="val" id="endControlCount" style="color:#1D4ED8">0</div>
          </div>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; padding-top:8px; border-top:1px solid var(--border);">
          <a class="btn approve" href="/artifact/architecture_model.tm7" download="architecture_model.tm7">⬇ Download Microsoft .TM7 XML Model</a>
          <a class="btn secondary" href="/artifact/current.png" download="final_architecture_diagram.png">⬇ Download Architecture Diagram (.PNG)</a>
          <a class="btn secondary" href="/artifact/current.svg" download="final_architecture_diagram.svg">⬇ Download Architecture Diagram (.SVG)</a>
          <a class="btn secondary" href="/artifact/current.drawio" download="final_architecture.drawio">⬇ Download Editable .drawio XML</a>
          <a class="btn secondary" href="/artifact/tm7.png" download="tm7_threat_model_diagram.png">⬇ Download .TM7 Threat Diagram (.PNG)</a>
          <a class="btn secondary" href="/artifact/tm7.svg" download="tm7_threat_model_diagram.svg">⬇ Download .TM7 Threat Diagram (.SVG)</a>
          <a class="btn secondary" href="/artifact/coverage_report.json" download="coverage_report.json">⬇ Coverage JSON</a>
          <a class="btn secondary" href="/artifact/dfd.json" download="dfd.json">⬇ DFD JSON</a>
          <a class="btn secondary" href="/artifact/stride_threats.json" download="stride_threats.json">⬇ STRIDE Threats JSON</a>
          <a class="btn secondary" href="/artifact/security_controls.json" download="security_controls.json">⬇ NIST Controls JSON</a>
        </div>
      </div>

      <!-- Visual Deliverable 1: Final Architecture Diagram -->
      <div class="card">
        <h2>📐 Final Validated System Architecture Diagram</h2>
        <p style="color:var(--muted); font-size:12.5px;">Reflects all accepted human review & AI modifications across trust zones, components, and encrypted data flows.</p>
        <img id="finalArchDiagram" class="diagram-img" alt="Final Architecture Diagram">
      </div>

      <!-- Visual Deliverable 2: Visual .TM7 Threat Model & DFD Diagram -->
      <div class="card">
        <h2>🛡️ Visual Microsoft Threat Modeling Tool (.TM7) &amp; DFD Threat Diagram</h2>
        <p style="color:var(--muted); font-size:12.5px;">Shows DFD External Entities (Double Box), Processes (Rounded Pill), Data Stores (Parallel Bars), Trust Boundaries (Red Dashed), and overlaid STRIDE Threat Badges.</p>
        <img id="finalTm7Diagram" class="diagram-img" alt="TM7 Threat Model & DFD Diagram">
      </div>

      <!-- Complete End-Output Executive Summary Table -->
      <div class="card">
        <h2>📋 Final End-of-Pipeline Threat &amp; Control Executive Summary</h2>
        <table id="finalExecutiveTable">
          <thead>
            <tr>
              <th>Threat ID</th>
              <th>DFD Element</th>
              <th>Element Type</th>
              <th>STRIDE Category</th>
              <th>Risk Score &amp; Severity</th>
              <th>NIST SP 800-53 Control</th>
              <th>Mitigation Action</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
        <div class="stage-footer">
          <button class="secondary" onclick="switchStage(9)">&larr; Back to Stage 9</button>
          <button class="approve" onclick="switchStage(1)">↺ Return to Stage 1</button>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
let currentState = null;
let lastDiagramSignature = "";

function switchStage(stageNum) {
  document.querySelectorAll('.stage-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.stage-view').forEach(el => el.classList.remove('active'));
  
  const navItem = document.querySelector(`.stage-item[data-stage="${stageNum}"]`);
  const viewItem = document.getElementById(`stage-${stageNum}`);
  if (navItem) navItem.classList.add('active');
  if (viewItem) viewItem.classList.add('active');
}

function refreshDiagramsNow() {
  const ts = Date.now();
  const revImg = document.getElementById('reviewDiagram');
  const finArchImg = document.getElementById('finalArchDiagram');
  const finTm7Img = document.getElementById('finalTm7Diagram');
  if (revImg) revImg.src = '/artifact/current.png?t=' + ts;
  if (finArchImg) finArchImg.src = '/artifact/current.png?t=' + ts;
  if (finTm7Img) finTm7Img.src = '/artifact/tm7.png?t=' + ts;
}

async function fetchState(forceDiagramReload = false) {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();
    if (data.ok) {
      currentState = data.state;
      updateUI(forceDiagramReload);
    }
  } catch (err) {
    console.error('State fetch failed:', err);
  }
}

function updateUI(forceDiagramReload = false) {
  if (!currentState) return;

  // Header Badges
  const projName = (currentState.requirements && currentState.requirements.project_name) || currentState.architecture_name || 'System';
  document.getElementById('activeProjectBadge').textContent = 'Project: ' + projName;
  document.getElementById('ollamaStatus').textContent = 'Model: ' + (currentState.ollama_model || 'Deterministic + AI');
  document.getElementById('appVersion').textContent = currentState.display_version || 'v1';

  // Stage 1: Step-by-Step Table & Console Logs
  const pStatus = currentState.pipeline_status;
  if (pStatus) {
    if (pStatus.logs) {
      const logElem = document.getElementById('pipelineLog');
      logElem.textContent = pStatus.logs.join('\n');
      logElem.scrollTop = logElem.scrollHeight;
    }
    const stepsTb = document.getElementById('stepsTableBody');
    if (stepsTb && pStatus.steps) {
      stepsTb.innerHTML = '';
      pStatus.steps.forEach(s => {
        const tr = document.createElement('tr');
        let badgeHtml = '<span class="badge">PENDING</span>';
        if (s.status === 'completed') badgeHtml = '<span class="badge completed">✅ COMPLETED</span>';
        else if (s.status === 'running') badgeHtml = '<span class="badge running">⏳ RUNNING...</span>';
        else if (s.status === 'failed') badgeHtml = '<span class="badge failed">✖ FAILED</span>';
        tr.innerHTML = `
          <td><b>Step ${s.index}</b></td>
          <td>${s.description}</td>
          <td><code>${s.script}</code></td>
          <td>${badgeHtml}</td>
          <td><button class="secondary small" onclick="runSingleStep(${s.index})" ${pStatus.running ? 'disabled' : ''}>▶ Run Step ${s.index}</button></td>
        `;
        stepsTb.appendChild(tr);
      });
    }
  }

  // Reload diagram images only when version, hash, or preview state changes (or when forced)
  const diagSig = `${currentState.display_version}|${currentState.display_hash}|${currentState.has_pending_preview}|${currentState.updated_at}`;
  if (forceDiagramReload || diagSig !== lastDiagramSignature) {
    lastDiagramSignature = diagSig;
    refreshDiagramsNow();
  }

  // Stage 4 & 5: Version, Hash & Preview Controls
  document.getElementById('stage4VersionBadge').textContent = currentState.display_version || 'v1';
  document.getElementById('appVersionText').textContent = currentState.display_version || 'v1';
  document.getElementById('appGateStatusText').textContent = currentState.approved ? 'APPROVED & SIGNED' : (currentState.status || 'PENDING_REVIEW');
  document.getElementById('appHashText').textContent = currentState.display_hash || '-';
  
  const isPreview = currentState.has_pending_preview;
  const previewBanner = document.getElementById('previewBanner');
  previewBanner.style.display = isPreview ? 'block' : 'none';
  if (isPreview) {
    previewBanner.innerHTML = `<b>PREVIEW READY (${currentState.display_version}):</b> ${currentState.pending_summary || 'Review pending changes.'} — Click <b>Accept Preview</b> below to commit as a new version, or <b>Discard Preview</b>.`;
  }
  document.getElementById('acceptPreviewBtn').style.display = isPreview ? 'inline-flex' : 'none';
  document.getElementById('discardPreviewBtn').style.display = isPreview ? 'inline-flex' : 'none';

  // Stage 2: Requirements Workspace Table with Mapped Architecture Elements
  if (currentState.requirements) {
    const tbody = document.querySelector('#reqTable tbody');
    tbody.innerHTML = '';
    const funcs = currentState.requirements.functional_requirements || [];
    const nonFuncs = currentState.requirements.non_functional_requirements || [];
    const secs = currentState.requirements.security_requirements || [];
    const covMap = (currentState.coverage && currentState.coverage.mappings) || {};

    const allReqs = [];
    funcs.forEach(r => allReqs.push({...r, typeLabel: 'Functional', catClass: 'functional'}));
    nonFuncs.forEach(r => allReqs.push({...r, typeLabel: 'Non-Functional', catClass: 'non_functional'}));
    secs.forEach(r => {
      const isCom = String(r.requirement_id || '').startsWith('COM-') || String(r.category || '').toLowerCase() === 'compliance';
      allReqs.push({...r, typeLabel: isCom ? 'Compliance' : 'Security', catClass: isCom ? 'compliance' : 'security', security_relevance: true});
    });

    const covPct = (currentState.coverage && currentState.coverage.coverage_percentage) ?? 100;
    document.getElementById('reqSummary').innerHTML = `
      Project: <b>${currentState.requirements.project_name || 'System'}</b> &nbsp;|&nbsp;
      Total Formal Requirements: <b>${allReqs.length}</b> (${funcs.length} Functional, ${nonFuncs.length} Non-Functional, ${secs.length} Security/Compliance) &nbsp;|&nbsp;
      Architecture Alignment: <b>${covPct}% Matched</b>
    `;

    allReqs.forEach(r => {
      const tr = document.createElement('tr');
      const secBadge = r.security_relevance ? '<span class="badge security">YES</span>' : '<span class="badge">NO</span>';
      const catBadge = `<span class="badge ${r.catClass}">${r.typeLabel}</span>`;
      const detail = r.actor || r.category || 'System';
      const mappedList = covMap[r.requirement_id] || [];
      const mappedHtml = mappedList.length > 0
        ? `<span class="badge completed">COVERED</span> <span style="font-size:11px; color:#334155;">${mappedList.map(m => m.id).slice(0, 4).join(', ')}</span>`
        : `<span class="badge failed">UNMAPPED</span>`;
      tr.innerHTML = `
        <td><b>${r.requirement_id}</b></td>
        <td><b>${r.title || 'Requirement'}</b></td>
        <td>${r.description || r.title || '-'}</td>
        <td>${catBadge}</td>
        <td>${detail}</td>
        <td>${secBadge}</td>
        <td>${mappedHtml}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Stage 3: Nodes & Flows Tables
  const arch = currentState.candidate_architecture || {};
  const nodes = arch.nodes || [];
  const edges = arch.edges || [];
  
  const nodesTbody = document.querySelector('#nodesTable tbody');
  if (nodesTbody) {
    nodesTbody.innerHTML = '';
    nodes.forEach(n => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><b>${n.id}</b></td><td>${n.name}</td><td><span class="badge dfd-type">${n.type}</span></td><td>${n.trust_zone || '-'}</td><td>${(n.requirement_ids||[]).join(', ')||'N/A'}</td>`;
      nodesTbody.appendChild(tr);
    });
  }

  const flowsTbody = document.querySelector('#flowsTable tbody');
  if (flowsTbody) {
    flowsTbody.innerHTML = '';
    edges.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><b>${e.id}</b></td><td>${e.source} &rarr; ${e.target}</td><td>${e.protocol}</td><td>${e.data||'-'}</td><td>${e.encryption||'TLS'}</td><td>${e.authentication||'None'}</td><td>${(e.requirement_ids||[]).join(', ')||'N/A'}</td>`;
      flowsTbody.appendChild(tr);
    });
  }

  if (currentState.coverage_report) {
    const cov = currentState.coverage_report.summary || {};
    document.getElementById('coverageNotice').innerHTML = `
      Coverage Percentage: <b>${cov.coverage_percentage}%</b> &nbsp;|&nbsp;
      Total Requirements: <b>${cov.total_requirements}</b> &nbsp;|&nbsp;
      Covered: <b>${cov.covered_requirements}</b> &nbsp;|&nbsp;
      Missing: <b>${cov.missing_requirements}</b> &nbsp;|&nbsp;
      Nodes: <b>${nodes.length}</b> &nbsp;|&nbsp;
      Data Flows: <b>${edges.length}</b>
    `;
  }

  // Stage 5: Approval Audit Log
  const history = currentState.approval_history || [];
  const app = currentState.approval;
  let historyHTML = '';
  
  if (app && app.approved) {
    const appVer = app.architecture_version || app.version || 1;
    const appRev = app.reviewer || 'Security Architect';
    const appTs = app.approved_at || app.timestamp || 'Just now';
    const appHash = app.architecture_hash || app.hash || '-';
    historyHTML += `
      <div class="notice ok" style="margin-bottom:8px;">
        <b>✅ Signed & Approved Version v${appVer}</b><br>
        Reviewer: <b>${appRev}</b> &nbsp;|&nbsp; Timestamp: ${appTs}<br>
        SHA-256 Hash: <code>${appHash}</code>
      </div>
    `;
  }

  if (history.length > 0) {
    historyHTML += '<h3>Historical Approvals Audit Trail:</h3><ul>';
    history.forEach(h => {
      const ver = h.version || h.architecture_version || 1;
      const rev = h.reviewer || 'Security Architect';
      const ts = h.timestamp || h.approved_at || h.at || 'Just now';
      const hashStr = h.hash || h.architecture_hash || h.approved_hash || '-';
      const shortHash = (hashStr && hashStr !== '-') ? (hashStr.length > 16 ? hashStr.substring(0,16) + '...' : hashStr) : '-';
      historyHTML += `<li><b>v${ver}</b> — Approved by <b>${rev}</b> on ${ts} (SHA-256: <code>${shortHash}</code>)</li>`;
    });
    historyHTML += '</ul>';
  } else if (!app) {
    historyHTML = '<div style="color:var(--muted)">No prior approvals recorded for this session. Enter Reviewer Name above and click Approve to sign this version.</div>';
  }
  document.getElementById('approvalHistoryLog').innerHTML = historyHTML;

  // Stage 6: DFD Tables with 1-to-1 STRIDE Threat Counts & Severity Badges
  if (currentState.dfd) {
    const dfd = currentState.dfd;
    fillDfdTable('#dfdProcessesTable tbody', dfd.processes || []);
    fillDfdTable('#dfdStoresTable tbody', dfd.data_stores || []);
    fillDfdTable('#dfdEntitiesTable tbody', dfd.external_entities || []);

    const flowsTb = document.querySelector('#dfdFlowsTable tbody');
    if (flowsTb) {
      flowsTb.innerHTML = '';
      (dfd.data_flows || []).forEach(f => {
        const tr = document.createElement('tr');
        const boundaryBadge = f.crosses_trust_boundary ? '<span class="badge HIGH">YES (Boundary)</span>' : '<span class="badge">Internal</span>';
        const tCount = f.threat_count || 0;
        const mSev = f.max_severity || 'LOW';
        const codes = (f.stride_codes || []).join(', ') || 'I';
        const threatBadge = `<span class="badge ${mSev}">${tCount} Threats [${codes}] (${mSev})</span>`;
        tr.innerHTML = `<td><b>${f.id}</b></td><td>${f.source} &rarr; ${f.target}</td><td>${f.protocol} (${f.encryption || 'TLS'})</td><td>${f.data}</td><td>${boundaryBadge}</td><td>${threatBadge}</td>`;
        flowsTb.appendChild(tr);
      });
    }
  }

  // Stage 7 & 8: STRIDE Threats & Risk Matrix (1-to-1 DFD Aligned)
  const strideTb = document.querySelector('#strideTable tbody');
  const riskTb = document.querySelector('#riskTable tbody');
  
  if (currentState.stride_threats && currentState.stride_threats.threats) {
    const stride = currentState.stride_threats;
    const threats = stride.threats || [];
    const summary = stride.summary || {};
    const byDfd = summary.by_dfd_element_type || {};

    document.getElementById('strideDfdSummary').innerHTML = `
      <b>1-to-1 DFD-to-STRIDE Alignment:</b> Total Threats: <b>${threats.length}</b> &nbsp;|&nbsp;
      External Entity Threats: <b>${byDfd['External Entity'] || 0}</b> &nbsp;|&nbsp;
      Process Threats: <b>${byDfd['Process'] || 0}</b> &nbsp;|&nbsp;
      Data Store Threats: <b>${byDfd['Data Store'] || 0}</b> &nbsp;|&nbsp;
      Data Flow Threats: <b>${byDfd['Data Flow'] || 0}</b>
    `;

    if (strideTb) {
      strideTb.innerHTML = '';
      threats.forEach(t => {
        const tr = document.createElement('tr');
        const sevBadge = `<span class="badge ${t.severity}">${t.severity}</span>`;
        const dfdBadge = `<span class="badge dfd-type">${t.dfd_element_type || t.target_type}</span>`;
        tr.innerHTML = `
          <td><b>${t.threat_id}</b></td>
          <td><b>${t.category} (${t.stride_code || t.category[0]})</b></td>
          <td>${sevBadge}</td>
          <td>${dfdBadge}</td>
          <td><b>${t.target_id}</b><br><span style="color:var(--muted); font-size:11px;">${t.target_name || ''}</span></td>
          <td><b>${t.title}</b><br><span style="color:var(--muted); font-size:11.5px;">${t.description || ''}</span></td>
          <td>${t.mitigation}</td>
          <td><b>${t.requirement_id||'N/A'}</b></td>
        `;
        strideTb.appendChild(tr);
      });
    }

    document.getElementById('riskTotalCount').textContent = summary.total_threats || threats.length;
    document.getElementById('riskHighCount').textContent = summary.high_severity || 0;
    document.getElementById('riskMedCount').textContent = summary.medium_severity || 0;
    document.getElementById('riskLowCount').textContent = summary.low_severity || 0;

    for (let l=1; l<=3; l++) {
      for (let i=1; i<=3; i++) {
        const el = document.getElementById(`cell_${l}_${i}`);
        if (el) el.textContent = '0 threats';
      }
    }

    if (riskTb) {
      riskTb.innerHTML = '';
      threats.forEach(t => {
        const lh = t.likelihood || 2;
        const imp = t.impact || 2;
        const score = t.risk_score || (lh * imp);
        const cellEl = document.getElementById(`cell_${lh}_${imp}`);
        if (cellEl) {
          const curr = parseInt(cellEl.textContent) || 0;
          cellEl.textContent = `${curr + 1} threats`;
        }

        const tr = document.createElement('tr');
        const sevBadge = `<span class="badge ${t.severity}">${t.severity}</span>`;
        const dfdBadge = `<span class="badge dfd-type">${t.dfd_element_type || t.target_type}</span>`;
        tr.innerHTML = `
          <td><b>${t.threat_id}</b></td>
          <td>${t.category}</td>
          <td>${dfdBadge}</td>
          <td><b>${t.target_id}</b></td>
          <td>${lh}</td>
          <td>${imp}</td>
          <td><b>${score}</b></td>
          <td>${sevBadge}</td>
          <td>${t.title}</td>
        `;
        riskTb.appendChild(tr);
      });
    }
  }

  // Stage 9: Security Controls & Stage 10: Final Executive Summary Table
  const ctrlTb = document.querySelector('#controlsTable tbody');
  const execTb = document.querySelector('#finalExecutiveTable tbody');
  if (currentState.security_controls && currentState.security_controls.control_traceability_matrix) {
    const controls = currentState.security_controls.control_traceability_matrix || [];
    if (ctrlTb) {
      ctrlTb.innerHTML = '';
      controls.forEach(c => {
        const tr = document.createElement('tr');
        const req = c.requirement || {};
        const thr = c.stride_threat || {};
        const ctrl = c.security_control || {};
        tr.innerHTML = `
          <td><b>${c.mapping_id}</b></td>
          <td><b>${req.requirement_id}</b>: ${req.title}</td>
          <td><b>${c.target_element}</b> <span class="badge dfd-type">${c.dfd_element_type || ''}</span></td>
          <td><b>${thr.threat_id}</b> (${thr.category}) <span class="badge ${thr.severity}">${thr.severity}</span></td>
          <td><b>${ctrl.control_id}</b> — ${ctrl.control_name}</td>
          <td>${c.mitigation}</td>
          <td><span class="badge completed">${ctrl.status||'RECOMMENDED'}</span></td>
        `;
        ctrlTb.appendChild(tr);
      });
    }
    if (execTb) {
      execTb.innerHTML = '';
      controls.forEach(c => {
        const tr = document.createElement('tr');
        const thr = c.stride_threat || {};
        const ctrl = c.security_control || {};
        tr.innerHTML = `
          <td><b>${thr.threat_id}</b></td>
          <td><b>${c.target_element}</b></td>
          <td><span class="badge dfd-type">${c.dfd_element_type || 'Element'}</span></td>
          <td>${thr.category}</td>
          <td><span class="badge ${thr.severity}">Score ${thr.risk_score || 6} (${thr.severity})</span></td>
          <td><b>${ctrl.control_id}</b>: ${ctrl.control_name}</td>
          <td>${c.mitigation}</td>
        `;
        execTb.appendChild(tr);
      });
    }
  }

  // Stage 10 KPI Summary Cards
  document.getElementById('endArchVersion').textContent = currentState.display_version || 'v1';
  document.getElementById('endApprovalStatus').textContent = currentState.approved ? 'SIGNED & APPROVED' : 'CANDIDATE READY';
  const covPctVal = (currentState.coverage_report && currentState.coverage_report.summary && currentState.coverage_report.summary.coverage_percentage) ?? 100;
  document.getElementById('endCoverageVal').textContent = covPctVal + '%';
  const dfdSum = (currentState.dfd && currentState.dfd.summary) || {};
  document.getElementById('endDfdCount').textContent = (dfdSum.total_elements || ((dfdSum.total_processes||0) + (dfdSum.total_data_stores||0) + (dfdSum.total_external_entities||0) + (dfdSum.total_data_flows||0)));
  const strSum = (currentState.stride_threats && currentState.stride_threats.summary) || {};
  document.getElementById('endThreatCount').textContent = strSum.total_threats || 0;
  const ctrlSum = (currentState.security_controls && currentState.security_controls.summary) || {};
  document.getElementById('endControlCount').textContent = ctrlSum.total_mapped_controls || 0;
}

function fillDfdTable(selector, items) {
  const tbody = document.querySelector(selector);
  if (!tbody) return;
  tbody.innerHTML = '';
  items.forEach(item => {
    const tr = document.createElement('tr');
    const tCount = item.threat_count || 0;
    const mSev = item.max_severity || 'LOW';
    const codes = (item.stride_codes || []).join(', ') || 'S,T';
    const threatBadge = `<span class="badge ${mSev}">${tCount} Threats [${codes}] (${mSev})</span>`;
    tr.innerHTML = `<td><b>${item.id}</b></td><td><b>${item.name}</b></td><td><span class="badge dfd-type">${item.node_type}</span></td><td>${item.trust_zone||'-'}</td><td>${(item.requirement_ids||[]).join(', ')||'N/A'}</td><td>${threatBadge}</td>`;
    tbody.appendChild(tr);
  });
}

function handleFileSelect() {
  const input = document.getElementById('pdfFile');
  if (input.files.length > 0) {
    document.getElementById('pdfFileName').textContent = 'Selected PDF: ' + input.files[0].name;
  }
}

async function runSingleStep(stepNum) {
  const prog = document.getElementById('pipelineProgressText');
  prog.textContent = `Running Step ${stepNum}/9...`;
  const res = await fetch('/api/run-step', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ step: stepNum, reset_logs: false })
  });
  const data = await res.json();
  await fetchState(true);
  prog.textContent = data.ok ? `Step ${stepNum}/9 Completed!` : `Step ${stepNum} Failed`;
  return data.ok;
}

async function runFullPipeline() {
  const log = document.getElementById('pipelineLog');
  const fileInput = document.getElementById('pdfFile');
  const startBtn = document.getElementById('startPipelineBtn');
  const prog = document.getElementById('pipelineProgressText');
  startBtn.disabled = true;

  try {
    if (fileInput.files.length > 0) {
      const file = fileInput.files[0];
      log.textContent = `Uploading PDF: ${file.name}...\n`;
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);
      const uploadRes = await fetch('/api/upload-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, data_base64: base64 })
      });
      const uploadData = await uploadRes.json();
      if (!uploadData.ok) {
        log.textContent += "Upload failed: " + (uploadData.error || 'Unknown error') + "\n";
        startBtn.disabled = false;
        return;
      }
      log.textContent += uploadData.message + "\n\n";
    }

    // Execute Steps 1 through 9 sequentially ONE BY ONE so user sees every stage live!
    for (let step = 1; step <= 9; step++) {
      prog.textContent = `⏳ Executing Step ${step} of 9...`;
      // Mark current row as running visually right away
      const rows = document.querySelectorAll('#stepsTableBody tr');
      if (rows[step - 1]) {
        rows[step - 1].cells[3].innerHTML = '<span class="badge running">⏳ RUNNING...</span>';
      }
      const res = await fetch('/api/run-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ step: step, reset_logs: (step === 1) })
      });
      const data = await res.json();
      await fetchState(step === 9);
      if (!data.ok) {
        prog.textContent = `✖ Stopped at Step ${step}`;
        alert(`Step ${step} encountered an error:\n` + (data.error || 'Unknown error'));
        startBtn.disabled = false;
        return;
      }
    }

    prog.textContent = '✅ All 9 Steps Completed One-by-One!';
    refreshDiagramsNow();
    if (confirm("All 9 Pipeline Steps Completed One-by-One! Proceed to Stage 2 (Requirements Traceability Matrix)?")) {
      switchStage(2);
    }
  } catch (err) {
    log.textContent += "\nPipeline Error: " + err.message;
  } finally {
    startBtn.disabled = false;
  }
}

async function addCustomRequirement() {
  const req_id = document.getElementById('addReqId').value.trim();
  const title = document.getElementById('addReqTitle').value.trim();
  const category = document.getElementById('addReqCategory').value;
  const description = document.getElementById('addReqDesc').value.trim();
  const security_relevance = document.getElementById('addReqSec').checked;

  if (!req_id || !title) return alert('Requirement ID and Title are required.');

  const res = await fetch('/api/add-requirement', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requirement_id: req_id, title, category, description, security_relevance })
  });

  const data = await res.json();
  if (data.ok) {
    alert(data.message);
    document.getElementById('addReqId').value = '';
    document.getElementById('addReqTitle').value = '';
    document.getElementById('addReqDesc').value = '';
    await fetchState(true);
  } else {
    alert('Error: ' + data.error);
  }
}

async function uploadDrawio() {
  const fileInput = document.getElementById('drawioUpload');
  if (!fileInput.files.length) return alert('Select a diagram file first (.drawio, .xml, .svg, .png, .jpg)');
  const file = fileInput.files[0];
  const filename = file.name;
  
  if (filename.toLowerCase().endsWith('.png') || filename.toLowerCase().endsWith('.jpg') || filename.toLowerCase().endsWith('.jpeg')) {
    const reader = new FileReader();
    reader.onload = async function() {
      const res = await fetch('/api/import-drawio', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: filename, content: reader.result })
      });
      const data = await res.json();
      if (data.ok) {
        await fetchState(true);
        refreshDiagramsNow();
        alert(`Uploaded diagram '${filename}' is now displayed in the preview above! Click 'Accept Preview & Save New Version' to commit it.`);
      } else alert('Upload error: ' + data.error);
    };
    reader.readAsDataURL(file);
  } else {
    const text = await file.text();
    const res = await fetch('/api/import-drawio', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: filename, content: text })
    });
    const data = await res.json();
    if (data.ok) {
      await fetchState(true);
      refreshDiagramsNow();
      alert(`Imported diagram '${filename}'! The updated diagram preview is now shown above. Click 'Accept Preview & Save New Version' to commit it.`);
    } else alert('Upload error: ' + data.error);
  }
}

async function sendAiPrompt() {
  const promptInput = document.getElementById('aiPrompt');
  const prompt = promptInput.value.trim();
  if (!prompt) return alert('Enter a change description first (e.g. Add a Redis Cache between ReservationService and PrimaryDatabase)');
  
  const btn = document.getElementById('aiPromptBtn');
  const oldText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Applying AI Change to Diagram...';

  try {
    const res = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ feedback: prompt })
    });
    const data = await res.json();
    if (data.ok) {
      promptInput.value = '';
      await fetchState(true);
      refreshDiagramsNow();
      alert("AI diagram change applied! Review the updated diagram above and click 'Accept Preview & Save New Version' to commit.");
    } else alert('AI error: ' + data.error);
  } catch (err) {
    alert('AI call failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

async function acceptPreview() {
  const res = await fetch('/api/accept-preview', { method: 'POST' });
  const data = await res.json();
  if (data.ok) {
    await fetchState(true);
    refreshDiagramsNow();
    if (confirm("Preview accepted! New version created and DFD / STRIDE / .TM7 models synchronized. Proceed to Stage 5 (Approval Gate)?")) {
      switchStage(5);
    }
  } else {
    alert('Accept Preview error: ' + data.error);
  }
}

async function discardPreview() {
  const res = await fetch('/api/discard-preview', { method: 'POST' });
  const data = await res.json();
  if (data.ok) {
    await fetchState(true);
    refreshDiagramsNow();
  }
}

async function approveArchitecture() {
  const reviewerInput = document.getElementById('reviewerName');
  const reviewer = reviewerInput.value.trim();
  const confirmed = document.getElementById('confirmCheckbox').checked;

  if (!reviewer) {
    return alert('Please enter your Reviewer Name before approving.');
  }

  if (!confirmed) {
    return alert('Please check the confirmation box to verify you have reviewed the diagram.');
  }

  const res = await fetch('/api/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewer, confirmed })
  });
  const data = await res.json();
  if (data.ok) {
    await fetchState(true);
    refreshDiagramsNow();
    if (confirm(`Architecture Signed by ${reviewer}! Downstream DFD, STRIDE Risk Matrix, Security Controls & .TM7 Diagrams are ready. Proceed to Stage 6 (DFD Engine) or Stage 10 (Final Output)?`)) {
      switchStage(6);
    }
  } else {
    alert('Approval Error: ' + data.error);
  }
}

async function generateDownstream() {
  const res = await fetch('/api/generate-downstream', { method: 'POST' });
  const data = await res.json();
  if (data.ok) {
    await fetchState(true);
    refreshDiagramsNow();
    alert('DFD, STRIDE Risk Matrix, NIST Controls & Visual .TM7 Diagrams synchronized!');
  } else {
    alert('Error: ' + data.error);
  }
}

// Initial state fetch & non-flickering background poll
fetchState(true);
setInterval(() => fetchState(false), 3000);
</script>
</body>
</html>
"""


class AppServerHandler(BaseHTTPRequestHandler):
    server_version = "AIThreatModelingG3/2.0"

    def log_message(self, format_string: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format_string % args}")

    def send_bytes(self, payload: bytes, content_type: str, status: int = 200, filename: str | None = None, inline: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        if filename:
            disp = "inline" if inline else "attachment"
            self.send_header("Content-Disposition", f'{disp}; filename="{filename}"')
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, data: dict[str, Any], status: int = 200) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status=status)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        content = self.rfile.read(length).decode("utf-8")
        return json.loads(content)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_bytes(SPA_HTML_PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return

        if path == "/api/state":
            try:
                state = workflow.initialize_review()
                pub_state = workflow.public_state(state)
                pub_state["ollama_model"] = select_model()

                active_arch_rel = (
                    state["pending_preview"]["files"]["architecture"]
                    if isinstance(state.get("pending_preview"), dict)
                    else state.get("current_files", {}).get("architecture", "outputs/architecture_v1.json")
                )
                arch_path = BASE_DIR / active_arch_rel
                if not arch_path.exists():
                    arch_path = BASE_DIR / "outputs" / "architecture_v1.json"
                if arch_path.exists():
                    with arch_path.open("r", encoding="utf-8") as f:
                        pub_state["candidate_architecture"] = json.load(f)

                req_path = BASE_DIR / "outputs" / "requirements.json"
                if req_path.exists():
                    with req_path.open("r", encoding="utf-8") as f:
                        pub_state["requirements"] = json.load(f)

                cov_path = BASE_DIR / "outputs" / "coverage_report.json"
                if cov_path.exists():
                    with cov_path.open("r", encoding="utf-8") as f:
                        pub_state["coverage_report"] = json.load(f)

                dfd_path = BASE_DIR / "outputs" / "dfd.json"
                if dfd_path.exists():
                    with dfd_path.open("r", encoding="utf-8") as f:
                        pub_state["dfd"] = json.load(f)

                stride_path = BASE_DIR / "outputs" / "stride_threats.json"
                if stride_path.exists():
                    with stride_path.open("r", encoding="utf-8") as f:
                        pub_state["stride_threats"] = json.load(f)

                ctrl_path = BASE_DIR / "outputs" / "security_controls.json"
                if ctrl_path.exists():
                    with ctrl_path.open("r", encoding="utf-8") as f:
                        pub_state["security_controls"] = json.load(f)

                if state.get("approved"):
                    app_file = BASE_DIR / "outputs" / "review" / "approval.json"
                    if app_file.exists():
                        with app_file.open("r", encoding="utf-8") as f:
                            app_data = json.load(f)
                        if app_data.get("architecture_hash") == state.get("approved_hash"):
                            pub_state["approval"] = app_data

                history_path = BASE_DIR / "outputs" / "review" / "approval_history.json"
                if history_path.exists():
                    with history_path.open("r", encoding="utf-8") as f:
                        pub_state["approval_history"] = json.load(f)

                with PIPELINE_LOCK:
                    pub_state["pipeline_status"] = copy.deepcopy(PIPELINE_STATUS)

                self.send_json({"ok": True, "state": pub_state})
            except Exception as err:
                self.send_json({"ok": False, "error": str(err)}, status=500)
            return

        if path.startswith("/artifact/"):
            self.serve_artifact(path)
            return

        self.send_json({"ok": False, "error": "Not Found"}, status=404)

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        try:
            body = self.read_json()

            if path == "/api/upload-pdf":
                filename = Path(str(body.get("filename") or "uploaded_requirements.pdf")).name
                data_b64 = str(body.get("data_base64") or "")
                if not data_b64:
                    raise Exception("No PDF data provided.")
                raw_bytes = base64.b64decode(data_b64)
                uploads_dir = BASE_DIR / "uploads"
                uploads_dir.mkdir(parents=True, exist_ok=True)
                target_path = uploads_dir / filename
                target_path.write_bytes(raw_bytes)
                # Also write active_pdf.txt marker so pdf_test.py extracts this exact uploaded file
                marker = BASE_DIR / "outputs" / "active_pdf.txt"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(filename, encoding="utf-8")
                self.send_json({"ok": True, "message": f"Successfully uploaded '{filename}' ({len(raw_bytes)} bytes) and set as active SRS document."})
                return

            if path == "/api/run-step":
                step_num = int(body.get("step", 1))
                reset_logs = bool(body.get("reset_logs", False))
                ok, output = run_single_pipeline_step(step_num, reset_logs=reset_logs)
                if not ok:
                    self.send_json({"ok": False, "error": output}, status=400)
                    return
                self.send_json({"ok": True, "step": step_num, "output": output})
                return

            if path == "/api/run-pipeline":
                with PIPELINE_LOCK:
                    if PIPELINE_STATUS.get("running"):
                        self.send_json({"ok": True, "message": "Pipeline is already processing in background..."})
                        return
                worker_thread = threading.Thread(target=execute_pipeline_worker, daemon=True)
                worker_thread.start()
                self.send_json({"ok": True, "message": "Automated pipeline started..."})
                return

            if path == "/api/add-requirement":
                req_id = str(body.get("requirement_id", "")).strip().upper()
                title = str(body.get("title", "")).strip()
                description = str(body.get("description", "")).strip() or title
                category = str(body.get("category", "functional")).strip().lower()
                security_rel = body.get("security_relevance") is True or category == "security"

                if not req_id or not title:
                    raise Exception("Requirement ID and Title are required.")

                req_file = BASE_DIR / "outputs" / "requirements.json"
                req_data = {"functional_requirements": [], "non_functional_requirements": [], "security_requirements": [], "actors": []}
                if req_file.exists():
                    with req_file.open("r", encoding="utf-8") as f:
                        req_data = json.load(f)

                existing_ids = {
                    str(item.get("requirement_id", "")).strip().upper()
                    for sec in ("functional_requirements", "non_functional_requirements", "security_requirements")
                    for item in req_data.get(sec, [])
                    if isinstance(item, dict)
                }
                if req_id in existing_ids:
                    raise Exception(f"Requirement ID '{req_id}' already exists.")

                new_item = {
                    "requirement_id": req_id,
                    "title": title,
                    "description": description,
                    "security_relevance": security_rel,
                }

                if category == "security":
                    new_item["category"] = "Security"
                    new_item["security_relevance"] = True
                    req_data.setdefault("security_requirements", []).append(new_item)
                elif category == "non_functional":
                    new_item["category"] = "Custom"
                    req_data.setdefault("non_functional_requirements", []).append(new_item)
                else:
                    new_item["actor"] = "User"
                    req_data.setdefault("functional_requirements", []).append(new_item)

                with req_file.open("w", encoding="utf-8") as f:
                    json.dump(req_data, f, indent=4, ensure_ascii=False)

                # Automatically align the new requirement onto matching architecture components & update coverage
                import architecture_ai, coverage_report
                state = workflow.initialize_review()
                arch, layout = workflow.current_artifacts(state)
                arch = architecture_ai.ensure_full_requirement_alignment(arch, req_data)
                workflow.write_json(BASE_DIR / state["current_files"]["architecture"], arch)
                workflow.write_json(BASE_DIR / "outputs" / "architecture_v1.json", arch)
                coverage_report.main()
                state["coverage"] = workflow.calculate_coverage(arch, req_data)
                state["current_hash"] = workflow.canonical_hash(arch)
                state["source_hash"] = state["current_hash"]
                workflow.write_json(workflow.STATE_FILE, state)

                self.send_json({"ok": True, "message": f"Added and mapped custom requirement {req_id} to architecture!"})
                return

            if path == "/api/import-drawio":
                filename = str(body.get("filename", "edited.drawio"))
                content = str(body.get("content", ""))

                if filename.lower().endswith((".drawio", ".xml")):
                    state = workflow.import_drawio(content, filename)
                else:
                    base_state = workflow.initialize_review()
                    arch, layout = workflow.current_artifacts(base_state)
                    raw_img_bytes = None
                    if "base64," in content:
                        b64_part = content.split("base64,", 1)[1]
                        raw_img_bytes = base64.b64decode(b64_part)
                    patch = {
                        "summary": f"Uploaded custom visual diagram ({filename}).",
                        "operations": [],
                        "source": "diagram_image_upload",
                        "uploaded_filename": filename,
                        "generated_at": workflow.utc_now(),
                    }
                    state = workflow.stage_candidate_preview(
                        arch,
                        layout,
                        patch,
                        "diagram_image_upload",
                        custom_png_bytes=raw_img_bytes,
                    )

                pub_state = workflow.public_state(state)
                self.send_json({"ok": True, "state": pub_state, "message": f"Uploaded {filename} successfully."})
                return

            if path == "/api/feedback":
                state = workflow.apply_feedback(str(body.get("feedback", "")))
                self.send_json({"ok": True, "state": workflow.public_state(state)})
                return

            if path == "/api/accept-preview":
                state = workflow.accept_preview()
                self.send_json({"ok": True, "state": workflow.public_state(state)})
                return

            if path == "/api/discard-preview":
                state = workflow.discard_preview()
                self.send_json({"ok": True, "state": workflow.public_state(state)})
                return

            if path == "/api/approve":
                reviewer = str(body.get("reviewer", "")).strip()
                confirmed = body.get("confirmed") is True

                if not reviewer:
                    raise Exception("Reviewer Name is required to approve.")

                state = workflow.approve_current(reviewer, confirmed)

                history_file = BASE_DIR / "outputs" / "review" / "approval_history.json"
                history = []
                if history_file.exists():
                    try:
                        with history_file.open("r", encoding="utf-8") as f:
                            history = json.load(f)
                    except Exception:
                        history = []

                pub_state = workflow.public_state(state)
                pub_state["approval_history"] = history
                self.send_json({"ok": True, "state": pub_state, "message": f"Architecture v{state.get('current_version', 1)} Approved & Signed by {reviewer}!"})
                return

            if path == "/api/generate-downstream":
                workflow.sync_downstream_artifacts()
                self.send_json({"ok": True, "message": "DFD, STRIDE, Controls, and .TM7 diagrams generated successfully."})
                return

            self.send_json({"ok": False, "error": "Not Found"}, status=404)
        except Exception as err:
            self.send_json({"ok": False, "error": str(err)}, status=400)

    def serve_artifact(self, route: str) -> None:
        state = workflow.initialize_review()
        pending = state.get("pending_preview")
        if isinstance(pending, dict):
            files = pending["files"]
        else:
            files = state["current_files"]

        mapping = {
            "/artifact/current.png": (BASE_DIR / files["png"], "image/png", "architecture.png", True),
            "/artifact/current.svg": (BASE_DIR / "outputs" / "diagrams" / "architecture_professional_v1.svg", "image/svg+xml", "architecture.svg", True),
            "/artifact/current.drawio": (BASE_DIR / files["drawio"], "application/xml", "architecture.drawio", False),
            "/artifact/current.json": (BASE_DIR / files["architecture"], "application/json", "architecture.json", False),
            "/artifact/tm7.png": (BASE_DIR / "outputs" / "diagrams" / "tm7_threat_model_v1.png", "image/png", "tm7_threat_model.png", True),
            "/artifact/tm7.svg": (BASE_DIR / "outputs" / "diagrams" / "tm7_threat_model_v1.svg", "image/svg+xml", "tm7_threat_model.svg", True),
            "/artifact/coverage_report.json": (BASE_DIR / "outputs" / "coverage_report.json", "application/json", "coverage_report.json", False),
            "/artifact/dfd.json": (BASE_DIR / "outputs" / "dfd.json", "application/json", "dfd.json", False),
            "/artifact/stride_threats.json": (BASE_DIR / "outputs" / "stride_threats.json", "application/json", "stride_threats.json", False),
            "/artifact/security_controls.json": (BASE_DIR / "outputs" / "security_controls.json", "application/json", "security_controls.json", False),
            "/artifact/architecture_model.tm7": (BASE_DIR / "outputs" / "architecture_model.tm7", "application/xml", "architecture_model.tm7", False),
        }

        if route in mapping:
            file_path, content_type, filename, inline = mapping[route]
            if file_path.exists():
                self.send_bytes(file_path.read_bytes(), content_type, filename=filename, inline=inline)
                return

        self.send_json({"ok": False, "error": "Artifact not found"}, status=404)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Threat Modeling G3 Master Server & SPA Workbench")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Bind port")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print()
    print("==========================================================")
    print("  AI THREAT MODELING G3 -- MASTER WORKBENCH SERVER")
    print("==========================================================")
    print(f"  Server URL: {url}")
    print("  Ollama Model:", select_model())
    print("  Press Ctrl+C to stop the server.")
    print("==========================================================")
    print()

    server = ThreadingHTTPServer((args.host, args.port), AppServerHandler)
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMaster workbench server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
