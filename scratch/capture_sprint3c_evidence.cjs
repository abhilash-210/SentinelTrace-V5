const { chromium } = require('d:/SIH 2026/SENTINEL-TRACE/frontend/node_modules/playwright');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = 'd:/SIH 2026/SENTINEL-TRACE/evidence/sprint-03c/screenshots';
const PPT_DIR = 'd:/SIH 2026/SENTINEL-TRACE/docs/ppt-assets/screenshots';

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function captureAllSprint3CEvidence() {
  console.log('Launching browser for Sprint 3C Evidence Capture...');
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  // 1. Semantic Policy Registry Page Overview & Same Token Hero
  console.log('1. Policy Registry Page & Same Token Hero');
  await page.goto('http://localhost:3000');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '01_semantic_policy_registry.png') });
  await page.screenshot({ path: path.join(OUTPUT_DIR, '04_same_token_different_meaning.png') });

  // 2. Cisco Policy Detail Modal
  console.log('2. Cisco Policy Detail');
  const viewBtns = await page.$$('button:has-text("View Rules")');
  if (viewBtns.length > 0) {
    await viewBtns[1].click(); // Click Cisco ASA (v1)
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '02_cisco_policy_detail.png') });
    const closeBtn = await page.$('button:has-text("Close View")');
    if (closeBtn) await closeBtn.click();
    await page.waitForTimeout(500);
  }

  // 3. Demo Vendor Policy Detail Modal
  console.log('3. Demo Vendor Policy Detail');
  const allRows = await page.$$('tr');
  for (const row of allRows) {
    const txt = await row.innerText();
    if (txt.includes('Demo Vendor')) {
      const btn = await row.$('button:has-text("View Rules")');
      if (btn) {
        await btn.click();
        await page.waitForTimeout(1000);
        await page.screenshot({ path: path.join(OUTPUT_DIR, '03_demo_vendor_policy_detail.png') });
        const closeBtn = await page.$('button:has-text("Close View")');
        if (closeBtn) await closeBtn.click();
        await page.waitForTimeout(500);
        break;
      }
    }
  }

  // 4. Version Lineage Tab
  console.log('4. Version Lineage Tab');
  const lineageTab = await page.$('button:has-text("Version Lineage")');
  if (lineageTab) {
    await lineageTab.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '06_semantic_policy_versioning.png') });
  }

  // 5. Read-Only Policy Comparison Modal
  console.log('5. Read-Only Policy Comparison Modal');
  const compareBtn = await page.$('button:has-text("Compare Versions")');
  if (compareBtn) {
    await compareBtn.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '07_policy_comparison.png') });
    const closeBtn = await page.$('button:has-text("Close Comparison")');
    if (closeBtn) await closeBtn.click();
    await page.waitForTimeout(500);
  }

  // 6. Protected Semantic Fields Tab
  console.log('6. Protected Semantic Fields Tab');
  const protectedTab = await page.$('button:has-text("Protected Semantic Fields")');
  if (protectedTab) {
    await protectedTab.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '05_protected_semantic_fields.png') });
  }

  // 7. Register Draft Policy Modal
  console.log('7. Register Draft Policy Modal');
  const createBtn = await page.$('button:has-text("Register Draft Policy")');
  if (createBtn) {
    await createBtn.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(OUTPUT_DIR, '11_draft_policy_creation.png') });
    const cancelBtn = await page.$('button:has-text("Cancel")');
    if (cancelBtn) await cancelBtn.click();
    await page.waitForTimeout(500);
  }

  // 8. Semantic Intelligence & Drift Dashboard Page
  console.log('8. Semantic Intelligence & Traceability');
  const navIntelligence = await page.$('button:has-text("Semantic Intelligence")');
  if (navIntelligence) {
    await navIntelligence.click();
    await page.waitForTimeout(2000);

    // Click trace modal
    const inspectBtn = await page.$('button:has-text("Inspect Trace")');
    if (inspectBtn) {
      await inspectBtn.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '08_semantic_traceability_full_chain.png') });
      await page.screenshot({ path: path.join(OUTPUT_DIR, '10_explainability_panel.png') });
      const closeBtn = await page.$('button:has-text("Close")');
      if (closeBtn) await closeBtn.click();
      await page.waitForTimeout(500);
    }

    // Drift Alerts Tab
    const alertsTab = await page.$('button:has-text("Drift & Risk Alerts")');
    if (alertsTab) {
      await alertsTab.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '09_semantic_drift_dashboard.png') });
    }
  }

  // 9. Docker Services & Swagger Docs
  console.log('9. Docker Services Health & Swagger');
  await page.goto('http://localhost:8000/docs');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '12_docker_services.png') });

  await browser.close();

  // Copy PPT Assets
  console.log('Copying high-value screenshots to docs/ppt-assets/screenshots/...');
  const pptFiles = [
    '04_same_token_different_meaning.png',
    '08_semantic_traceability_full_chain.png',
    '09_semantic_drift_dashboard.png',
  ];
  for (const f of pptFiles) {
    const src = path.join(OUTPUT_DIR, f);
    const dest = path.join(PPT_DIR, f);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      console.log(`Copied ${f} to PPT assets directory.`);
    }
  }

  console.log('Sprint 3C Real Screenshots Captured & Processed Successfully!');
}

captureAllSprint3CEvidence().catch((err) => {
  console.error('Error during capture:', err);
  process.exit(1);
});
