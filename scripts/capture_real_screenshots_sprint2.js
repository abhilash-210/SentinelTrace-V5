/**
 * capture_real_screenshots_sprint2.js
 * -----------------------------------
 * Captures all 8 real runtime screenshots for Sprint 2:
 * Source Parsing & OCSF-Aligned Canonical Normalization.
 */

import puppeteer from 'puppeteer-core';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const SCREENSHOTS_DIR = path.join(__dirname, "..", "evidence", "sprint-02", "screenshots");

fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function main() {
  console.log("=== Capturing Real Runtime Screenshots for Sprint 2 ===");

  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    headless: "new",
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1440,900']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  // 1. Pipeline Overview & Main Normalization Page
  console.log("[1/8] Capturing 01_raw_to_normalized_pipeline.png...");
  await page.goto("http://localhost:3000", { waitUntil: "networkidle0" });
  await page.waitForSelector("h1");
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_raw_to_normalized_pipeline.png") });
  console.log("  ✓ Saved 01_raw_to_normalized_pipeline.png");

  // 2. Syslog Filter (Network Activity)
  console.log("[2/8] Capturing 02_syslog_normalization.png (Network Activity)...");
  const buttons = await page.$$("button");
  for (const btn of buttons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.trim() === "Network") {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_syslog_normalization.png") });
  console.log("  ✓ Saved 02_syslog_normalization.png");

  // 3. JSON Filter (Authentication)
  console.log("[3/8] Capturing 03_json_normalization.png (Authentication)...");
  const buttonsAuth = await page.$$("button");
  for (const btn of buttonsAuth) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.trim() === "Auth") {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_json_normalization.png") });
  console.log("  ✓ Saved 03_json_normalization.png");

  // 4. CSV Filter (System Activity)
  console.log("[4/8] Capturing 04_csv_normalization.png (System Activity)...");
  const buttonsSys = await page.$$("button");
  for (const btn of buttonsSys) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.trim() === "System") {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_csv_normalization.png") });
  console.log("  ✓ Saved 04_csv_normalization.png");

  // 5. Dual-Pane Traceability Modal
  console.log("[5/8] Capturing 05_traceability_view.png (Traceability Link Modal)...");
  // Reset to All
  const buttonsAll = await page.$$("button");
  for (const btn of buttonsAll) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.trim() === "All") {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 500));

  // Click Trace Link on first row
  const traceBtns = await page.$$("button");
  for (const btn of traceBtns) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Trace Link")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 1200));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_traceability_view.png") });
  console.log("  ✓ Saved 05_traceability_view.png");

  // Close modal
  const closeBtns = await page.$$("button");
  for (const btn of closeBtns) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Close")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 500));

  // 6. Database Table View Scrolled
  console.log("[6/8] Capturing 07_database_normalized_events.png...");
  await page.evaluate(() => window.scrollTo(0, 350));
  await new Promise(r => setTimeout(r, 500));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "07_database_normalized_events.png") });
  console.log("  ✓ Saved 07_database_normalized_events.png");

  // 7. FastAPI Swagger Docs
  console.log("[7/8] Capturing 06_api_normalization.png (Swagger UI)...");
  await page.goto("http://localhost:8000/docs", { waitUntil: "networkidle0" });
  await page.waitForSelector(".swagger-ui");
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "06_api_normalization.png") });
  console.log("  ✓ Saved 06_api_normalization.png");

  // 8. Docker Services Status
  console.log("[8/8] Capturing 08_docker_services.png (Health & Status)...");
  await page.goto("http://localhost:8000/health", { waitUntil: "networkidle0" });
  await new Promise(r => setTimeout(r, 500));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "08_docker_services.png") });
  console.log("  ✓ Saved 08_docker_services.png");

  await browser.close();
  console.log("\n✅ All 8 real runtime screenshots captured successfully!");
}

main().catch(err => {
  console.error("Screenshot capture failed:", err);
  process.exit(1);
});
