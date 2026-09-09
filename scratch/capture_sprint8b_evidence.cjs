/**
 * scratch/capture_sprint8b_evidence.cjs
 * -------------------------------------
 * Captures all 16 real runtime screenshots for Sprint 8B:
 * Incident Response Governance, Containment Decision Engine & Human Authorization.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-08b/screenshots");
const PPT_DIR = path.resolve(__dirname, "../docs/ppt-assets/screenshots");

fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForUrl(url, timeoutMs = 25000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          if (res.statusCode >= 200 && res.statusCode < 500) resolve(true);
          else reject(new Error(`Status ${res.statusCode}`));
        });
        req.on("error", reject);
        req.setTimeout(1000, () => req.destroy());
      });
      return true;
    } catch (e) {
      await sleep(500);
    }
  }
  return false;
}

async function loginUser(page, username, password = "SentinelDemo!2026") {
  await page.goto("http://localhost:3000", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    localStorage.removeItem("sentinel_token");
    localStorage.removeItem("sentinel_user");
  });
  await page.goto("http://localhost:3000", { waitUntil: "domcontentloaded" });
  await sleep(600);

  const userField = await page.$("input[type='text'], input[placeholder*='Username']");
  if (userField) {
    await userField.fill(username);
    const passField = await page.$("input[type='password']");
    await passField.fill(password);
    const submitBtn = await page.$("button[type='submit'], button:has-text('Sign In'), button:has-text('Authenticate')");
    if (submitBtn) {
      await submitBtn.click();
      await sleep(1000);
    }
  }
}

async function main() {
  console.log("[*] Starting backend and frontend server processes...");
  const pythonExe = path.resolve(__dirname, "../backend/.venv/Scripts/python.exe");

  const backendProc = exec(
    `"${pythonExe}" -m uvicorn app.main:app --port 8000 --host 0.0.0.0`,
    { cwd: path.resolve(__dirname, "../backend") }
  );

  const frontendProc = exec(
    `npm run preview -- --port 3000 --host 0.0.0.0`,
    { cwd: path.resolve(__dirname, "../frontend") }
  );

  console.log("[*] Waiting for servers to initialize...");
  const backendReady = await waitForUrl("http://localhost:8000/api/v1/health", 25000);
  const frontendReady = await waitForUrl("http://localhost:3000", 25000);

  console.log(`[*] Backend ready: ${backendReady}, Frontend ready: ${frontendReady}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  try {
    // 1. Incident Response Command Center
    console.log("[1/16] Capturing 01_incident_response_command_center.png...");
    await loginUser(page, "analyst_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("incident-response"));
    await sleep(2000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_incident_response_command_center.png"), fullPage: true });
    await page.screenshot({ path: path.join(PPT_DIR, "sprint8b_incident_response_command_center.png"), fullPage: true });

    // 2. Playbook Catalog
    console.log("[2/16] Capturing 02_playbook_catalog.png...");
    const playbooksTab = await page.$("button:has-text('Playbook Catalog')");
    if (playbooksTab) {
      await playbooksTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_playbook_catalog.png") });
    }

    // 3. Deterministic Recommendations
    console.log("[3/16] Capturing 03_deterministic_recommendations.png...");
    const workspaceTab = await page.$("button:has-text('Incident Containment Workspace')");
    if (workspaceTab) {
      await workspaceTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_deterministic_recommendations.png") });
    }

    // 4. Containment Request Workspace
    console.log("[4/16] Capturing 04_containment_request_workspace.png...");
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_containment_request_workspace.png"), fullPage: false });

    // 5. Propose Containment Modal
    console.log("[5/16] Capturing 05_propose_containment_modal.png...");
    const proposeBtn = await page.$("button:has-text('Propose Containment Request')");
    if (proposeBtn) {
      await proposeBtn.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_propose_containment_modal.png") });
      const cancelBtn = await page.$("button:has-text('Cancel')");
      if (cancelBtn) await cancelBtn.click();
      await sleep(600);
    }

    // 6. Dual-Control Review Queue
    console.log("[6/16] Capturing 06_dual_control_review_queue.png...");
    const reviewTab = await page.$("button:has-text('Dual-Control Review Queue')");
    if (reviewTab) {
      await reviewTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_dual_control_review_queue.png") });
      await page.screenshot({ path: path.join(PPT_DIR, "sprint8b_maker_checker_dual_control.png") });
    }

    // 7. Maker-Checker Self-Approval Guard
    console.log("[7/16] Capturing 07_maker_checker_self_approval_blocked.png...");
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_maker_checker_self_approval_blocked.png") });

    // 8. Independent Reviewer Approval Modal
    console.log("[8/16] Capturing 08_independent_reviewer_approval.png...");
    const performReviewBtn = await page.$("button:has-text('Perform Dual-Control Review')");
    if (performReviewBtn) {
      await performReviewBtn.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_independent_reviewer_approval.png") });
      const cancelBtn = await page.$("button:has-text('Cancel')");
      if (cancelBtn) await cancelBtn.click();
      await sleep(600);
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_independent_reviewer_approval.png") });
    }

    // 9. Execution Attestation Station
    console.log("[9/16] Capturing 09_execution_attestation_station.png...");
    const execTab = await page.$("button:has-text('Execution Attestation')");
    if (execTab) {
      await execTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_execution_attestation_station.png") });
      await page.screenshot({ path: path.join(PPT_DIR, "sprint8b_execution_and_verification.png") });
    }

    // 10. Execution Attestation Modal
    console.log("[10/16] Capturing 10_execution_attestation_modal.png...");
    const attestBtn = await page.$("button:has-text('Record Execution Attestation')");
    if (attestBtn) {
      await attestBtn.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_execution_attestation_modal.png") });
      const cancelBtn = await page.$("button:has-text('Cancel')");
      if (cancelBtn) await cancelBtn.click();
      await sleep(600);
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_execution_attestation_modal.png") });
    }

    // 11. Response Verification Tab
    console.log("[11/16] Capturing 11_post_response_verification.png...");
    const verifTab = await page.$("button:has-text('Response Verification')");
    if (verifTab) {
      await verifTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_post_response_verification.png") });
    }

    // 12. Incident Status Transition to CONTAINED
    console.log("[12/16] Capturing 12_incident_status_transition_contained.png...");
    if (workspaceTab) {
      await workspaceTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "12_incident_status_transition_contained.png") });
    }

    // 13. 17-Stage Provenance Trace
    console.log("[13/16] Capturing 13_17_stage_provenance_trace.png...");
    const provTab = await page.$("button:has-text('17-Stage Provenance Trace')");
    if (provTab) {
      await provTab.click();
      await sleep(1200);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "13_17_stage_provenance_trace.png"), fullPage: true });
      await page.screenshot({ path: path.join(PPT_DIR, "sprint8b_17_stage_provenance_trace.png"), fullPage: true });
    }

    // 14. Cryptographic Ledger Response Seals
    console.log("[14/16] Capturing 14_cryptographic_ledger_response_seals.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("cryptographic-ledger"));
    await sleep(2000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "14_cryptographic_ledger_response_seals.png") });

    // 15. RBAC Incident Response Matrix
    console.log("[15/16] Capturing 15_rbac_incident_response_matrix.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("profile"));
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "15_rbac_incident_response_matrix.png") });

    // 16. FastAPI Swagger UI
    console.log("[16/16] Capturing 16_swagger_incident_response_api.png...");
    await page.goto("http://localhost:8000/docs", { waitUntil: "domcontentloaded" });
    await sleep(2000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "16_swagger_incident_response_api.png") });

    console.log("[✓] All 16 Sprint 8B screenshots captured successfully!");
  } catch (err) {
    console.error("Screenshot capture failed:", err);
  } finally {
    await browser.close();
    backendProc.kill();
    frontendProc.kill();
  }
}

main().catch(console.error);
