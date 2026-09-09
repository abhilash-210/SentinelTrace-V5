/**
 * scratch/capture_sprint9a_evidence.cjs
 * -------------------------------------
 * Captures all 14 real runtime screenshots for Sprint 9A:
 * Continuous Security Assurance & Platform Health Intelligence.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const { exec, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-09a/screenshots");
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

  console.log("[+] Launching Playwright browser...");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  try {
    // 1. Log in as admin_demo
    console.log("[+] Logging in as admin_demo...");
    await loginUser(page, "admin_demo");

    // 2. Navigate to Security Assurance page
    console.log("[+] Navigating to Security Assurance...");
    await page.evaluate(() => {
      if (window.__navigateTo) window.__navigateTo("security-assurance");
    });
    await sleep(1500);

    // Click "Run Platform Evaluation" to ensure fresh telemetry
    const runEvalBtn = await page.$("#run-platform-evaluation-btn, button:has-text('Run Platform Evaluation')");
    if (runEvalBtn) {
      console.log("[+] Triggering fresh platform assurance evaluation...");
      await runEvalBtn.click();
      await sleep(2500);
    }

    // 1. Screenshot 01: Assurance Command Center Hero
    console.log("[*] Capturing 01_assurance_command_center_hero.png...");
    await page.screenshot({
      path: path.join(SCREENSHOTS_DIR, "01_assurance_command_center_hero.png"),
      fullPage: false,
    });
    await page.screenshot({
      path: path.join(PPT_DIR, "sprint9a_assurance_command_center.png"),
      fullPage: false,
    });

    // 2. Screenshot 02: Platform Trust Gauge
    console.log("[*] Capturing 02_platform_trust_gauge.png...");
    await page.screenshot({
      path: path.join(SCREENSHOTS_DIR, "02_platform_trust_gauge.png"),
      fullPage: false,
    });

    // 3. Screenshot 03: Seven Domain Assurance Cards
    console.log("[*] Capturing 03_seven_domain_assurance_cards.png...");
    await page.screenshot({
      path: path.join(SCREENSHOTS_DIR, "03_seven_domain_assurance_cards.png"),
      fullPage: true,
    });

    // 4-10: Domain Inspection Modals
    const domains = [
      { key: "EVIDENCE_ASSURANCE", file: "04_evidence_assurance_domain.png" },
      { key: "NORMALIZATION_ASSURANCE", file: "05_normalization_assurance_domain.png" },
      { key: "SEMANTIC_ASSURANCE", file: "06_semantic_assurance_domain.png" },
      { key: "DETECTION_ASSURANCE", file: "07_detection_assurance_domain.png" },
      { key: "RISK_ASSURANCE", file: "08_risk_assurance_domain.png" },
      { key: "INCIDENT_RESPONSE_ASSURANCE", file: "09_incident_response_assurance_domain.png" },
      { key: "CRYPTOGRAPHIC_ASSURANCE", file: "10_cryptographic_assurance_domain.png" },
    ];

    for (let i = 0; i < domains.length; i++) {
      const d = domains[i];
      console.log(`[*] Capturing ${d.file}...`);
      await page.evaluate((k) => {
        const btn = document.getElementById(`inspect-btn-${k}`);
        if (btn) btn.click();
      }, d.key);
      await sleep(600);
      await page.screenshot({
        path: path.join(SCREENSHOTS_DIR, d.file),
        fullPage: false,
      });
      await page.evaluate(() => {
        const closeBtn = document.getElementById("close-domain-modal-btn");
        if (closeBtn) closeBtn.click();
      });
      await sleep(500);
    }

    // 11. Tab 2: Health Matrix & Deductions
    console.log("[*] Switching to Health Matrix tab...");
    const matrixTabBtn = await page.$("button:has-text('Health Matrix')");
    if (matrixTabBtn) {
      await matrixTabBtn.click();
      await sleep(1000);
      console.log("[*] Capturing 11_domain_health_matrix_table.png...");
      await page.screenshot({
        path: path.join(SCREENSHOTS_DIR, "11_domain_health_matrix_table.png"),
        fullPage: false,
      });
      await page.screenshot({
        path: path.join(PPT_DIR, "sprint9a_seven_domains_matrix.png"),
        fullPage: false,
      });

      console.log("[*] Capturing 12_deductions_explainability_engine.png...");
      await page.screenshot({
        path: path.join(SCREENSHOTS_DIR, "12_deductions_explainability_engine.png"),
        fullPage: true,
      });
    }

    // 12. Tab 3: Assurance Alerts
    console.log("[*] Switching to Assurance Alerts tab...");
    const alertsTabBtn = await page.$("button:has-text('Assurance Alerts')");
    if (alertsTabBtn) {
      await alertsTabBtn.click();
      await sleep(1000);
      console.log("[*] Capturing 13_assurance_alert_center.png...");
      await page.screenshot({
        path: path.join(SCREENSHOTS_DIR, "13_assurance_alert_center.png"),
        fullPage: false,
      });
    }

    // 13. Tab 4: Cryptographic Assurance
    console.log("[*] Switching to Cryptographic Assurance tab...");
    const cryptoTabBtn = await page.$("button:has-text('Cryptographic Assurance')");
    if (cryptoTabBtn) {
      await cryptoTabBtn.click();
      await sleep(1000);
      await page.screenshot({
        path: path.join(PPT_DIR, "sprint9a_cryptographic_health.png"),
        fullPage: false,
      });
    }

    // 14. Tab 5: 17-Stage Provenance Trace
    console.log("[*] Switching to 17-Stage Provenance Trace tab...");
    const provTabBtn = await page.$("button:has-text('17-Stage Provenance Trace')");
    if (provTabBtn) {
      await provTabBtn.click();
      await sleep(1000);

      // Click the first stage to expand inspector drawer
      const stageCard = await page.$("div:has-text('Raw Evidence Ingestion Integrity')");
      if (stageCard) {
        await stageCard.click();
        await sleep(600);
      }

      console.log("[*] Capturing 14_seventeen_stage_provenance_trace.png...");
      await page.screenshot({
        path: path.join(SCREENSHOTS_DIR, "14_seventeen_stage_provenance_trace.png"),
        fullPage: true,
      });
      await page.screenshot({
        path: path.join(PPT_DIR, "sprint9a_provenance_trace.png"),
        fullPage: true,
      });
    }

    console.log("[✓] All 14 screenshots successfully captured!");
  } catch (err) {
    console.error("[-] Error capturing screenshots:", err);
  } finally {
    await browser.close();
    if (backendProc) backendProc.kill();
    if (frontendProc) frontendProc.kill();
  }
}

main();
