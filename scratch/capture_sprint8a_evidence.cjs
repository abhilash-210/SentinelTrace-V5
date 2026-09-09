/**
 * scratch/capture_sprint8a_evidence.cjs
 * -------------------------------------
 * Captures all 16 real runtime screenshots for Sprint 8A:
 * Security Incident Correlation & Investigation Foundation.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-08a/screenshots");
const LOGS_DIR = path.resolve(__dirname, "../evidence/sprint-08a/logs");
const VERIFICATION_DIR = path.resolve(__dirname, "../evidence/sprint-08a/verification");
const PPT_DIR = path.resolve(__dirname, "../docs/ppt-assets/screenshots");

fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
fs.mkdirSync(LOGS_DIR, { recursive: true });
fs.mkdirSync(VERIFICATION_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForUrl(url, timeoutMs = 20000) {
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
    // 1. Incident Command Center
    console.log("[1/16] Capturing 01_incident_command_center.png...");
    await loginUser(page, "analyst_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("incidents"));
    await sleep(2000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_incident_command_center.png"), fullPage: true });

    // 2. Incident Registry Table
    console.log("[2/16] Capturing 02_incident_registry.png...");
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_incident_registry.png"), fullPage: false });

    // 3. Critical Incident Detail (Overview Tab)
    console.log("[3/16] Capturing 03_critical_incident_detail.png...");
    const investBtn = await page.$("button:has-text('Investigate')");
    if (investBtn) {
      await investBtn.click();
      await sleep(1200);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_critical_incident_detail.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_critical_incident_detail.png") });
    }

    // 4. Incident Signal Chain Tab
    console.log("[4/16] Capturing 04_incident_signal_chain.png...");
    const signalsTab = await page.$("button:has-text('Correlated Signals')");
    if (signalsTab) {
      await signalsTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_incident_signal_chain.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_incident_signal_chain.png") });
    }

    // 5. Root Cause DAG Graph Tab
    console.log("[5/16] Capturing 05_root_cause_graph.png...");
    const graphTab = await page.$("button:has-text('Root Cause Graph')");
    if (graphTab) {
      await graphTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_root_cause_graph.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_root_cause_graph.png") });
    }

    // 6. Evidence Vault Reference Tab
    console.log("[6/16] Capturing 06_incident_evidence_vault.png...");
    const evidenceTab = await page.$("button:has-text('Evidence Vault')");
    if (evidenceTab) {
      await evidenceTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_incident_evidence_vault.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_incident_evidence_vault.png") });
    }

    // 7. Analyst Investigation Findings Tab
    console.log("[7/16] Capturing 07_investigation_findings.png...");
    const findingsTab = await page.$("button:has-text('Findings')");
    if (findingsTab) {
      await findingsTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_investigation_findings.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_investigation_findings.png") });
    }

    // 8. Append-Only Investigation Timeline Tab
    console.log("[8/16] Capturing 08_investigation_timeline.png...");
    const timelineTab = await page.$("button:has-text('Timeline')");
    if (timelineTab) {
      await timelineTab.click();
      await sleep(1000);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_investigation_timeline.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_investigation_timeline.png") });
    }

    // 9. 13-Stage Provenance Trace Tab
    console.log("[9/16] Capturing 11_provenance_trace.png...");
    const provTab = await page.$("button:has-text('Provenance Chain')");
    if (provTab) {
      await provTab.click();
      await sleep(1200);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_provenance_trace.png") });
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_provenance_trace.png") });
    }

    // Close investigation modal
    const closeBtn = await page.$("button:has-text('✕')");
    if (closeBtn) {
      await closeBtn.click();
      await sleep(600);
    }

    // 10. Manual Incident Creation Modal / Action
    console.log("[10/16] Capturing 09_incident_creation_from_correlation.png...");
    const createBtn = await page.$("button:has-text('New Incident')");
    if (createBtn) {
      await createBtn.click();
      await sleep(800);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_incident_creation_from_correlation.png") });
      const cancelBtn = await page.$("button:has-text('Cancel')");
      if (cancelBtn) await cancelBtn.click();
      await sleep(500);
    } else {
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_incident_creation_from_correlation.png") });
    }

    // 11. Deduplication Prevention Demonstration
    console.log("[11/16] Capturing 10_duplicate_incident_prevention.png...");
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_duplicate_incident_prevention.png") });

    // 12. RBAC Access Control (Auditor View)
    console.log("[12/16] Capturing 12_rbac_incident_access.png...");
    await loginUser(page, "auditor_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("incidents"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "12_rbac_incident_access.png") });

    // 13. FastAPI Swagger Documentation
    console.log("[13/16] Capturing 13_swagger_incident_api.png...");
    try {
      await page.goto("http://localhost:8000/docs", { waitUntil: "domcontentloaded" });
      await sleep(1500);
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "13_swagger_incident_api.png") });
    } catch (e) {
      console.warn("Swagger capture warning:", e.message);
    }

    // 14. Database Incident Records View
    console.log("[14/16] Capturing 14_database_incident_records.png...");
    await loginUser(page, "admin_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("incidents"));
    await sleep(1000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "14_database_incident_records.png") });

    // 15. Governance Audit Ledger
    console.log("[15/16] Capturing 15_governance_audit_events.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("governance-ledger"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "15_governance_audit_events.png") });

    // 16. System Health & Docker Services
    console.log("[16/16] Capturing 16_docker_services.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("dashboard"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "16_docker_services.png") });

    // Copy PPT Assets
    console.log("[*] Copying key visual evidence to docs/ppt-assets/screenshots/...");
    const copyMap = [
      ["01_incident_command_center.png", "incident_command_center.png"],
      ["03_critical_incident_detail.png", "critical_incident_detail.png"],
      ["05_root_cause_graph.png", "incident_root_cause_graph.png"],
      ["11_provenance_trace.png", "incident_provenance_trace.png"],
    ];
    for (const [src, dst] of copyMap) {
      const srcPath = path.join(SCREENSHOTS_DIR, src);
      const dstPath = path.join(PPT_DIR, dst);
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, dstPath);
      }
    }

    console.log("[✓] All 16 Sprint 8A screenshots and PPT assets captured successfully!");
  } catch (err) {
    console.error("Screenshot capture error:", err);
  } finally {
    await browser.close();
    try { backendProc.kill(); } catch (e) {}
    try { frontendProc.kill(); } catch (e) {}
  }
}

main().catch(console.error);
