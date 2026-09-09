/**
 * capture_real_screenshots.js
 * ----------------------------
 * Connects to live running SentinelTrace containers (http://localhost:3000 and http://localhost:8000)
 * using local Microsoft Edge via puppeteer-core to capture genuine runtime screenshots.
 */

import puppeteer from 'puppeteer-core';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const SCREENSHOTS_DIR = path.join(__dirname, "..", "evidence", "sprint-01", "screenshots");

fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function main() {
  console.log("=== Capturing Real Runtime Screenshots for Sprint 1 ===");
  
  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    headless: "new",
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1440,900']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  // 1. Dashboard / Event Ingestion Page
  console.log("[1/5] Navigating to http://localhost:3000 (Ingestion Dashboard)...");
  await page.goto("http://localhost:3000", { waitUntil: "networkidle0" });
  await page.waitForSelector("h1");
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "01_ingestion_dashboard.png") });
  console.log("  ✓ Saved 01_ingestion_dashboard.png");

  // 2. Preserve Event & Capture Success Banner
  console.log("[2/5] Preserving new security event...");
  const presetButtons = await page.$$("button");
  for (const btn of presetButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Auth Gateway")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 500));

  const buttonsAfterPreset = await page.$$("button");
  for (const btn of buttonsAfterPreset) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Preserve Evidence")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 1500));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "02_event_preserved.png") });
  console.log("  ✓ Saved 02_event_preserved.png");

  // 3. Inspect Modal & Integrity Verification
  console.log("[3/5] Opening Inspect Modal & Verifying Integrity...");
  const inspectBtns = await page.$$("button");
  for (const btn of inspectBtns) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.trim() === "Inspect") {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 800));

  const modalButtons = await page.$$("button");
  for (const btn of modalButtons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Run Live Verification")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 1200));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "03_integrity_verified.png") });
  console.log("  ✓ Saved 03_integrity_verified.png");

  const closeBtns = await page.$$("button");
  for (const btn of closeBtns) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes("Close")) {
      await btn.click();
      break;
    }
  }
  await new Promise(r => setTimeout(r, 500));

  // 4. Database Records Table View
  console.log("[4/5] Capturing Database Records Table...");
  await page.evaluate(() => window.scrollTo(0, 400));
  await new Promise(r => setTimeout(r, 500));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "05_database_records.png") });
  console.log("  ✓ Saved 05_database_records.png");

  // 5. FastAPI Swagger Docs
  console.log("[5/5] Navigating to http://localhost:8000/docs (Swagger API)...");
  await page.goto("http://localhost:8000/docs", { waitUntil: "networkidle0" });
  await page.waitForSelector(".swagger-ui");
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, "04_api_ingestion.png") });
  console.log("  ✓ Saved 04_api_ingestion.png");

  await browser.close();
  console.log("\n✅ All 5 genuine runtime screenshots captured successfully!");
}

main().catch(err => {
  console.error("Screenshot capture failed:", err);
  process.exit(1);
});
