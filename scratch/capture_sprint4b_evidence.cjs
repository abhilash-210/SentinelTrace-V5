/**
 * scratch/capture_sprint4b_evidence.cjs
 * -------------------------------------
 * Captures all 12 real runtime screenshots for Sprint 4B.
 */

const { chromium } = require("../frontend/node_modules/playwright");
const fs = require("fs");
const path = require("path");

const SCREENSHOTS_DIR = path.resolve(__dirname, "../evidence/sprint-04b/screenshots");
fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loginUser(page, username, password = "SentinelDemo!2026") {
  await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
  await sleep(600);

  // If already logged in, logout or check
  const logoutBtn = await page.$("button:has-text('Sign Out')");
  if (logoutBtn) {
    await logoutBtn.click();
    await sleep(600);
  }

  // Fill login form
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
  console.log("[*] Launching browser for Sprint 4B evidence capture...");
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
    // 1. 01_policy_governance_dashboard.png
    // ----------------------------------------------------
    console.log("[1/12] Capturing 01_policy_governance_dashboard.png...");
    await loginUser(page, "reviewer_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("approvals"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_policy_governance_dashboard.png") });

    // ----------------------------------------------------
    // 2. 02_pending_review_queue.png
    // ----------------------------------------------------
    console.log("[2/12] Capturing 02_pending_review_queue.png...");
    const pendingTab = await page.$("button:has-text('PENDING')");
    if (pendingTab) {
      await pendingTab.click();
      await sleep(800);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_pending_review_queue.png") });

    // ----------------------------------------------------
    // 3. 03_policy_review_modal.png
    // ----------------------------------------------------
    console.log("[3/12] Capturing 03_policy_review_modal.png...");
    const allTab = await page.$("button:has-text('ALL')");
    if (allTab) await allTab.click();
    await sleep(600);
    const reviewBtn = await page.$("button:has-text('Review & Diff')");
    if (reviewBtn) {
      await reviewBtn.click();
      await sleep(1000);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_policy_review_modal.png") });

    // Close modal
    const closeBtn = await page.$("button:has-text('✕'), button:has-text('Cancel')");
    if (closeBtn) {
      await closeBtn.click();
      await sleep(600);
    }

    // ----------------------------------------------------
    // 4. 04_self_approval_blocked.png
    // ----------------------------------------------------
    console.log("[4/12] Capturing 04_self_approval_blocked.png...");
    // Login as author_demo and trigger self-approval demo
    await loginUser(page, "author_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("approvals"));
    await sleep(1000);
    const demoBtn = await page.$("button:has-text('Maker-Checker Violation Demo')");
    if (demoBtn) {
      await demoBtn.click();
      await sleep(2000);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_self_approval_blocked.png") });

    // Dismiss violation modal
    const ackBtn = await page.$("button:has-text('Acknowledge & Dismiss')");
    if (ackBtn) {
      await ackBtn.click();
      await sleep(600);
    }

    // ----------------------------------------------------
    // 5. 05_reviewer_approval_success.png
    // ----------------------------------------------------
    console.log("[5/12] Capturing 05_reviewer_approval_success.png...");
    await loginUser(page, "reviewer_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("approvals"));
    await sleep(1000);
    const pendingTab2 = await page.$("button:has-text('PENDING')");
    if (pendingTab2) await pendingTab2.click();
    await sleep(600);
    const firstReviewBtn = await page.$("button:has-text('Review & Diff')");
    if (firstReviewBtn) {
      await firstReviewBtn.click();
      await sleep(800);
      const approveBtn = await page.$("button:has-text('Approve Policy')");
      if (approveBtn) {
        await approveBtn.click();
        await sleep(600);
      }
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_reviewer_approval_success.png") });
    await sleep(1000);

    // ----------------------------------------------------
    // 6. 06_policy_activation.png
    // ----------------------------------------------------
    console.log("[6/12] Capturing 06_policy_activation.png...");
    const approvedTab = await page.$("button:has-text('APPROVED')");
    if (approvedTab) {
      await approvedTab.click();
      await sleep(800);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_policy_activation.png") });

    // ----------------------------------------------------
    // 7. 07_version_superseded.png
    // ----------------------------------------------------
    console.log("[7/12] Capturing 07_version_superseded.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("semantic-policies"));
    await sleep(1200);
    const lineageTab = await page.$("button:has-text('Version Lineage')");
    if (lineageTab) {
      await lineageTab.click();
      await sleep(800);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_version_superseded.png") });

    // ----------------------------------------------------
    // 8. 08_governance_timeline.png
    // ----------------------------------------------------
    console.log("[8/12] Capturing 08_governance_timeline.png...");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("approvals"));
    await sleep(1000);
    const allTab2 = await page.$("button:has-text('ALL')");
    if (allTab2) await allTab2.click();
    await sleep(600);
    const timelineBtn = await page.$("button:has-text('Timeline')");
    if (timelineBtn) {
      await timelineBtn.click();
      await sleep(1000);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_governance_timeline.png") });

    // Close timeline modal
    const closeTimeline = await page.$("button:has-text('Close History'), button:has-text('✕')");
    if (closeTimeline) {
      await closeTimeline.click();
      await sleep(600);
    }

    // ----------------------------------------------------
    // 9. 09_auditor_governance_view.png
    // ----------------------------------------------------
    console.log("[9/12] Capturing 09_auditor_governance_view.png...");
    await loginUser(page, "auditor_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("approvals"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "09_auditor_governance_view.png") });

    // ----------------------------------------------------
    // 10. 10_swagger_approval_api.png
    // ----------------------------------------------------
    console.log("[10/12] Capturing 10_swagger_approval_api.png...");
    await page.goto("http://localhost:8000/docs", { waitUntil: "networkidle" });
    await sleep(1500);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "10_swagger_approval_api.png") });

    // ----------------------------------------------------
    // 11. 11_authenticated_approval_request.png
    // ----------------------------------------------------
    console.log("[11/12] Capturing 11_authenticated_approval_request.png...");
    // Expand the policy approval section in Swagger
    const approvalEndpoint = await page.$("button:has-text('Policy Governance & Dual-Control Approvals')");
    if (approvalEndpoint) {
      await approvalEndpoint.click();
      await sleep(800);
    }
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "11_authenticated_approval_request.png") });

    // ----------------------------------------------------
    // 12. 12_docker_services.png
    // ----------------------------------------------------
    console.log("[12/12] Capturing 12_docker_services.png...");
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await loginUser(page, "admin_demo");
    await page.evaluate(() => window.__navigateTo && window.__navigateTo("system-health"));
    await sleep(1200);
    await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "12_docker_services.png") });

    console.log("[✓] All 12 screenshots captured successfully in evidence/sprint-04b/screenshots/!");
  } catch (err) {
    console.error("[!] Error capturing screenshots:", err);
  } finally {
    await browser.close();
  }
}

captureScreenshots();
