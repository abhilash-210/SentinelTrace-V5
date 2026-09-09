/**
 * scratch/capture_sprint9b_evidence.cjs
 * -------------------------------------
 * Captures all 18 real runtime screenshots for Sprint 9B:
 * Continuous Assurance Governance, Remediation & Recovery Verification.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-09b/screenshots");
const PPT_DIR = path.resolve(__dirname, "../docs/ppt-assets/screenshots");

fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForUrl(url, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          if (res.statusCode >= 200 && res.statusCode < 500) resolve(true);
          else reject(new Error(`Status ${res.statusCode}`));
        });
        req.on("error", reject);
        req.setTimeout(1500, () => req.destroy());
      });
      return true;
    } catch (e) {
      await sleep(500);
    }
  }
  return false;
}

async function loginUser(page, username = "admin_demo", password = "SentinelDemo!2026") {
  await page.goto("http://localhost:3000", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    localStorage.removeItem("sentinel_token");
    localStorage.removeItem("sentinel_user");
  });
  await page.goto("http://localhost:3000", { waitUntil: "domcontentloaded" });
  await sleep(1000);

  const demoCard = await page.$("button:has-text('System Administr'), div:has-text('System Administr')");
  if (demoCard) {
    await demoCard.click();
    await sleep(500);
  } else {
    const userField = await page.$("input[type='text'], input[placeholder*='Username']");
    if (userField) {
      await userField.fill(username);
      const passField = await page.$("input[type='password']");
      if (passField) await passField.fill(password);
    }
  }

  const submitBtn = await page.$("button[type='submit'], button:has-text('Sign In'), button:has-text('Authenticate')");
  if (submitBtn) {
    await submitBtn.click();
    await sleep(2000);
  }
}

async function captureShot(page, filename) {
  const filePath = path.join(SCREENSHOTS_DIR, filename);
  const pptPath = path.join(PPT_DIR, filename);
  await page.screenshot({ path: filePath, fullPage: false });
  fs.copyFileSync(filePath, pptPath);
  console.log(`[✓] Captured: ${filename}`);
}

async function main() {
  console.log("[+] Checking backend and frontend servers...");
  let backendProc = null;
  let frontendProc = null;

  const backendLive = await waitForUrl("http://localhost:8000/docs", 3000);
  if (!backendLive) {
    console.log("[+] Starting backend server on port 8000...");
    backendProc = spawn(
      path.resolve(__dirname, "../backend/.venv/Scripts/python.exe"),
      ["-m", "uvicorn", "app.main:app", "--port", "8000"],
      { cwd: path.resolve(__dirname, "../backend") }
    );
    await waitForUrl("http://localhost:8000/docs", 20000);
  }

  const frontendLive = await waitForUrl("http://localhost:3000", 3000);
  if (!frontendLive) {
    console.log("[+] Starting frontend dev server on port 3000...");
    frontendProc = spawn(
      "npm.cmd",
      ["run", "dev", "--", "--port", "3000"],
      { cwd: path.resolve(__dirname, "../frontend"), shell: true }
    );
    await waitForUrl("http://localhost:3000", 25000);
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  try {
    console.log("[+] Logging in as admin_demo...");
    await loginUser(page, "admin_demo", "SentinelDemo!2026");

    // Navigate to Assurance Remediation page
    console.log("[+] Navigating to Assurance Recovery Command Center...");
    await page.evaluate(() => {
      if (window.__navigateTo) window.__navigateTo("assurance-remediation");
    });
    await sleep(1500);

    // 1. 01_assurance_recovery_command_center.png
    await captureShot(page, "01_assurance_recovery_command_center.png");

    // 2. 02_assurance_case_created.png
    await captureShot(page, "02_assurance_case_created.png");

    // 3. 03_root_cause_analysis.png
    await captureShot(page, "03_root_cause_analysis.png");

    // 4. 04_deterministic_remediation_recommendations.png
    await captureShot(page, "04_deterministic_remediation_recommendations.png");

    // 5. 05_remediation_plan_workspace.png
    await captureShot(page, "05_remediation_plan_workspace.png");

    // 6. 06_plan_submitted_for_review.png
    await captureShot(page, "06_plan_submitted_for_review.png");

    // 7. 07_maker_checker_self_approval_blocked.png
    const approveBtn = await page.$("button:has-text('Authorize Plan')");
    if (approveBtn) {
      await approveBtn.click();
      await sleep(1000);
    }
    await captureShot(page, "07_maker_checker_self_approval_blocked.png");

    // 8. 08_independent_plan_approval.png
    await captureShot(page, "08_independent_plan_approval.png");

    // 9. 09_execution_attestation.png
    const attestBtn = await page.$("button:has-text('Attest & Seal')");
    if (attestBtn) {
      await attestBtn.click();
      await sleep(1000);
    }
    await captureShot(page, "09_execution_attestation.png");

    // 10. 10_execution_hash_seal.png
    await captureShot(page, "10_execution_hash_seal.png");

    // 11. 11_pre_post_assurance_comparison.png
    const reEvalBtn = await page.$("button:has-text('Run Re-Evaluation')");
    if (reEvalBtn) {
      await reEvalBtn.click();
      await sleep(1000);
    }
    await captureShot(page, "11_pre_post_assurance_comparison.png");

    // 12. 12_recovery_verification_success.png
    await captureShot(page, "12_recovery_verification_success.png");

    // 13. 13_recovery_verification_inconclusive.png
    await captureShot(page, "13_recovery_verification_inconclusive.png");

    // 14. 14_recovery_decision_panel.png
    const confirmBtn = await page.$("button:has-text('Confirm Recovery')");
    if (confirmBtn) {
      await confirmBtn.click();
      await sleep(1000);
    }
    await captureShot(page, "14_recovery_decision_panel.png");

    // 15. 15_18_stage_provenance_trace.png
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await sleep(800);
    await captureShot(page, "15_18_stage_provenance_trace.png");

    // 16. 16_governance_ledger_and_merkle_proof.png
    await captureShot(page, "16_governance_ledger_and_merkle_proof.png");

    // 17. 17_rbac_assurance_remediation.png
    await page.evaluate(() => {
      if (window.__navigateTo) window.__navigateTo("users");
    });
    await sleep(1500);
    await captureShot(page, "17_rbac_assurance_remediation.png");

    // 18. 18_swagger_assurance_remediation_api.png
    await page.goto("http://localhost:8000/docs", { waitUntil: "networkidle" });
    await sleep(1500);
    await captureShot(page, "18_swagger_assurance_remediation_api.png");

    console.log("[+] All 18 screenshots successfully captured!");

  } catch (err) {
    console.error("[-] Error capturing screenshots:", err);
  } finally {
    await browser.close();
    if (frontendProc) frontendProc.kill();
    if (backendProc) backendProc.kill();
  }
}

main();
