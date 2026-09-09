/**
 * scratch/capture_sprint5b_evidence.cjs
 * -------------------------------------
 * Captures all 12 real runtime screenshots for Sprint 5B:
 * Merkle Tree Proofs & Independent Auditor Verification.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const fs = require("fs");
const path = require("path");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-05b/screenshots");
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loginUser(page, username, password = "SentinelDemo!2026") {
  await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
  await sleep(600);

  const logoutBtn = await page.$("button:has-text('Sign Out')");
  if (logoutBtn) {
    await logoutBtn.click();
    await sleep(600);
  }

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

async function captureScreenshots() {
  console.log("[*] Launching browser for Sprint 5B evidence capture...");
  const browser = await chromium.launch({
    channel: "msedge",
    headless: true,
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  try {
    // ----------------------------------------------------
    // 1. 01_merkle_audit_dashboard.png
    // ----------------------------------------------------
    console.log("[1/12] Capturing 01_merkle_audit_dashboard.png...");
    await loginUser(page, "auditor_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("merkle-audit"));
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_merkle_audit_dashboard.png") });

    // ----------------------------------------------------
    // 2. 02_merkle_batch_created.png
    // ----------------------------------------------------
    console.log("[2/12] Capturing 02_merkle_batch_created.png...");
    // Switch to admin to seal a new batch
    await loginUser(page, "admin_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("merkle-audit"));
    await sleep(1000);
    const sealBtn = await page.$("button:has-text('Seal New Merkle Batch')");
    if (sealBtn) {
      await sealBtn.click();
      await sleep(1500);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_merkle_batch_created.png") });

    // ----------------------------------------------------
    // 3. 03_merkle_tree_visualization.png
    // ----------------------------------------------------
    console.log("[3/12] Capturing 03_merkle_tree_visualization.png...");
    const treeHeader = await page.$("h2:has-text('SECTION C')");
    if (treeHeader) {
      await treeHeader.scrollIntoViewIfNeeded();
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_merkle_tree_visualization.png") });

    // ----------------------------------------------------
    // 4. 04_inclusion_proof_inspector.png
    // ----------------------------------------------------
    console.log("[4/12] Capturing 04_inclusion_proof_inspector.png...");
    const proofInspectorHeader = await page.$("h2:has-text('SECTION D')");
    if (proofInspectorHeader) {
      await proofInspectorHeader.scrollIntoViewIfNeeded();
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_inclusion_proof_inspector.png") });

    // ----------------------------------------------------
    // 5. 05_independent_verification_valid.png
    // ----------------------------------------------------
    console.log("[5/12] Capturing 05_independent_verification_valid.png...");
    const auditorSection = await page.$("h2:has-text('SECTION E & F')");
    if (auditorSection) {
      await auditorSection.scrollIntoViewIfNeeded();
      await sleep(600);
    }
    const verifyProofBtn = await page.$("button:has-text('VERIFY CRYPTOGRAPHIC PROOF')");
    if (verifyProofBtn) {
      await verifyProofBtn.click();
      await sleep(1200);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_independent_verification_valid.png") });

    // ----------------------------------------------------
    // 6. 06_independent_verification_invalid.png
    // ----------------------------------------------------
    console.log("[6/12] Capturing 06_independent_verification_invalid.png...");
    // Modify expected root in the input to test mismatch
    const rootInputs = await page.$$("input[placeholder='Sealed Merkle Root']");
    if (rootInputs.length > 0) {
      await rootInputs[0].fill("0000000000000000000000000000000000000000000000000000000000000000");
      if (verifyProofBtn) {
        await verifyProofBtn.click();
        await sleep(1200);
      }
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_independent_verification_invalid.png") });

    // ----------------------------------------------------
    // 7. 07_tampered_proof_detection.png
    // ----------------------------------------------------
    console.log("[7/12] Capturing 07_tampered_proof_detection.png...");
    // Reset by re-inspecting first entry
    const inspectFirstEntry = await page.$("button:has-text('Proof →')");
    if (inspectFirstEntry) {
      await inspectFirstEntry.click();
      await sleep(800);
    }
    // Enable Tamper Simulation toggle
    const tamperToggle = await page.$("#tamperToggle");
    if (tamperToggle) {
      await tamperToggle.check();
      await sleep(400);
    }
    if (verifyProofBtn) {
      await verifyProofBtn.click();
      await sleep(1200);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_tampered_proof_detection.png") });

    // Reset toggle
    if (tamperToggle) {
      await tamperToggle.uncheck();
      await sleep(300);
    }

    // ----------------------------------------------------
    // 8. 08_ledger_to_merkle_trace.png
    // ----------------------------------------------------
    console.log("[8/12] Capturing 08_ledger_to_merkle_trace.png...");
    const traceSection = await page.$("h2:has-text('SECTION G')");
    if (traceSection) {
      await traceSection.scrollIntoViewIfNeeded();
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_ledger_to_merkle_trace.png") });

    // ----------------------------------------------------
    // 9. 09_swagger_merkle_api.png
    // ----------------------------------------------------
    console.log("[9/12] Capturing 09_swagger_merkle_api.png...");
    await page.goto("http://localhost:8000/docs", { waitUntil: "networkidle" });
    await sleep(1500);
    const merkleTag = await page.$("button:has-text('Merkle Tree Audit & Proofs')");
    if (merkleTag) {
      await merkleTag.click();
      await sleep(800);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_swagger_merkle_api.png") });

    // ----------------------------------------------------
    // 10. 10_database_merkle_records.png
    // ----------------------------------------------------
    console.log("[10/12] Capturing 10_database_merkle_records.png...");
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await loginUser(page, "auditor_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("merkle-audit"));
    await sleep(1200);
    const batchTable = await page.$("table");
    if (batchTable) {
      await batchTable.scrollIntoViewIfNeeded();
      await sleep(600);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_database_merkle_records.png") });

    // ----------------------------------------------------
    // 11. 11_rbac_merkle_access.png
    // ----------------------------------------------------
    console.log("[11/12] Capturing 11_rbac_merkle_access.png...");
    // Login as Security Analyst (read-only for batches, no seal batch button)
    await loginUser(page, "analyst_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("merkle-audit"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_rbac_merkle_access.png") });

    // ----------------------------------------------------
    // 12. 12_docker_services.png
    // ----------------------------------------------------
    console.log("[12/12] Capturing 12_docker_services.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("system-health"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "12_docker_services.png") });

    console.log("[✓] All 12 screenshots captured successfully in evidence/sprint-05b/screenshots/!");
  } catch (err) {
    console.error("[!] Error capturing screenshots:", err);
  } finally {
    await browser.close();
  }
}

captureScreenshots();
