/**
 * scratch/capture_sprint7a_evidence.cjs
 * -------------------------------------
 * Captures all 12 real runtime screenshots for Sprint 7A:
 * Real-Time Detection Rule Execution Engine.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-07a/screenshots");
const PPT_DIR = path.resolve(__dirname, "../docs/ppt-assets/screenshots");
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForUrl(url, timeoutMs = 15000) {
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

  const pythonExe = `"d:\\SIH 2026\\SENTINEL-TRACE\\backend\\.venv\\Scripts\\python.exe"`;
  const backendProc = exec(
    `${pythonExe} -m uvicorn app.main:app --host 127.0.0.1 --port 8000`,
    { cwd: path.resolve(__dirname, "../backend") }
  );

  const frontendProc = exec(
    `npm run dev -- --port 3000 --host 127.0.0.1`,
    { cwd: path.resolve(__dirname, "../frontend") }
  );

  console.log("[*] Waiting for backend (8000) and frontend (3000) to be ready...");
  const backendReady = await waitForUrl("http://127.0.0.1:8000/docs", 15000);
  const frontendReady = await waitForUrl("http://127.0.0.1:3000", 15000);

  console.log(`[*] Status -> Backend: ${backendReady ? "ONLINE" : "OFFLINE"}, Frontend: ${frontendReady ? "ONLINE" : "OFFLINE"}`);

  console.log("[*] Launching browser for Sprint 7A evidence capture...");
  let browser;
  try {
    browser = await chromium.launch({
      channel: "msedge",
      headless: true,
    });
  } catch (e) {
    browser = await chromium.launch({
      headless: true,
    });
  }

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  try {
    // ----------------------------------------------------
    // 1. 01_detection_execution_dashboard.png
    // ----------------------------------------------------
    console.log("[1/12] Capturing 01_detection_execution_dashboard.png...");
    await loginUser(page, "analyst_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("detection-execution"));
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_detection_execution_dashboard.png") });

    // ----------------------------------------------------
    // 2. 02_active_rule_execution.png
    // ----------------------------------------------------
    console.log("[2/12] Capturing 02_active_rule_execution.png...");
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("RUN ACTIVE DETECTIONS"));
      if (btn) btn.click();
    });
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_active_rule_execution.png") });

    // ----------------------------------------------------
    // 3. 03_match_result.png
    // ----------------------------------------------------
    console.log("[3/12] Capturing 03_match_result.png...");
    const statusSelect = await page.$("select:has(option[value='MATCH'])");
    if (statusSelect) {
      await statusSelect.selectOption("MATCH");
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_match_result.png") });

    // ----------------------------------------------------
    // 4. 04_no_match_result.png
    // ----------------------------------------------------
    console.log("[4/12] Capturing 04_no_match_result.png...");
    if (statusSelect) {
      await statusSelect.selectOption("NO_MATCH");
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_no_match_result.png") });

    // ----------------------------------------------------
    // 5. 05_partial_missing_field.png
    // ----------------------------------------------------
    console.log("[5/12] Capturing 05_partial_missing_field.png...");
    if (statusSelect) {
      await statusSelect.selectOption("PARTIAL");
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_partial_missing_field.png") });

    // ----------------------------------------------------
    // 6. 06_condition_explainability.png
    // ----------------------------------------------------
    console.log("[6/12] Capturing 06_condition_explainability.png...");
    if (statusSelect) {
      await statusSelect.selectOption("ALL");
      await sleep(600);
    }
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Inspect"));
      if (btn) btn.click();
    });
    await sleep(800);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_condition_explainability.png") });

    // Close inspect modal
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("✕"));
      if (btn) btn.click();
    });
    await sleep(500);

    // ----------------------------------------------------
    // 7. 07_run_all_active_detections.png
    // ----------------------------------------------------
    console.log("[7/12] Capturing 07_run_all_active_detections.png...");
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("RUN ACTIVE DETECTIONS"));
      if (btn) btn.click();
    });
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_run_all_active_detections.png") });

    // ----------------------------------------------------
    // 8. 08_rule_version_binding.png
    // ----------------------------------------------------
    console.log("[8/12] Capturing 08_rule_version_binding.png...");
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Inspect"));
      if (btn) btn.click();
    });
    await sleep(800);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_rule_version_binding.png") });
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("✕"));
      if (btn) btn.click();
    });
    await sleep(500);

    // ----------------------------------------------------
    // 9. 09_execution_trace.png
    // ----------------------------------------------------
    console.log("[9/12] Capturing 09_execution_trace.png...");
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Trace"));
      if (btn) btn.click();
    });
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_execution_trace.png") });
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("✕"));
      if (btn) btn.click();
    });
    await sleep(500);

    // ----------------------------------------------------
    // 10. 10_rbac_execution_access.png
    // ----------------------------------------------------
    console.log("[10/12] Capturing 10_rbac_execution_access.png...");
    await loginUser(page, "viewer_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("detection-execution"));
    await sleep(1000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_rbac_execution_access.png") });

    // ----------------------------------------------------
    // 11. 11_swagger_detection_execution_api.png
    // ----------------------------------------------------
    console.log("[11/12] Capturing 11_swagger_detection_execution_api.png...");
    await page.goto("http://127.0.0.1:8000/docs", { waitUntil: "domcontentloaded" });
    await sleep(2000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_swagger_detection_execution_api.png") });

    // ----------------------------------------------------
    // 12. 12_docker_services.png
    // ----------------------------------------------------
    console.log("[12/12] Capturing 12_docker_services.png...");
    await loginUser(page, "admin_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("system-health"));
    await sleep(1000);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "12_docker_services.png") });

    // ----------------------------------------------------
    // Copy required PPT assets
    // ----------------------------------------------------
    console.log("[*] Copying PPT assets to docs/ppt-assets/screenshots/...");
    const pptFiles = [
      "03_match_result.png",
      "05_partial_missing_field.png",
      "06_condition_explainability.png",
      "09_execution_trace.png",
    ];
    for (const f of pptFiles) {
      const src = path.join(SCREENSHOTS_DIR, f);
      const dst = path.join(PPT_DIR, f);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dst);
        console.log(`  ✓ Copied ${f} -> docs/ppt-assets/screenshots/`);
      }
    }

    console.log("✅ All 12 screenshots captured and PPT assets copied successfully!");
  } catch (err) {
    console.error("Screenshot capture error:", err);
  } finally {
    await browser.close();
    try {
      backendProc.kill();
      frontendProc.kill();
    } catch (e) {}
    process.exit(0);
  }
}

main();
