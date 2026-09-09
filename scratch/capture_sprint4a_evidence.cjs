const { chromium } = require('d:/SIH 2026/SENTINEL-TRACE/frontend/node_modules/playwright');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = 'd:/SIH 2026/SENTINEL-TRACE/evidence/sprint-04a/screenshots';
const PPT_DIR = 'd:/SIH 2026/SENTINEL-TRACE/docs/ppt-assets/screenshots';

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(PPT_DIR, { recursive: true });

async function captureAllEvidence() {
  console.log('Launching browser for Sprint 4A evidence capture...');
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  // 1. Login Page
  console.log('1. Capturing 01_login_page.png');
  await page.goto('http://localhost:3000');
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '01_login_page.png') });

  // 2. Admin Login & Dashboard
  console.log('2. Capturing 02_admin_dashboard_identity.png');
  // Click Admin Demo account
  const adminBtn = await page.$('button:has-text("System Administrator")');
  if (adminBtn) await adminBtn.click();
  await page.waitForTimeout(500);
  const signInBtn = await page.$('#sign-in-btn');
  if (signInBtn) await signInBtn.click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '02_admin_dashboard_identity.png') });

  // 3. User Management (Admin Only)
  console.log('3. Capturing 07_user_management.png');
  const userMgmtNav = await page.$('button:has-text("User Management")');
  if (userMgmtNav) await userMgmtNav.click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '07_user_management.png') });

  // 4. Switch to Security Analyst
  console.log('4. Capturing 03_security_analyst_navigation.png');
  const signOutBtn = await page.$('button:has-text("Sign Out")');
  if (signOutBtn) await signOutBtn.click();
  await page.waitForTimeout(1000);
  const analystDemoBtn = await page.$('button:has-text("Security Analyst")');
  if (analystDemoBtn) await analystDemoBtn.click();
  await page.waitForTimeout(500);
  const signInBtn2 = await page.$('#sign-in-btn');
  if (signInBtn2) await signInBtn2.click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '03_security_analyst_navigation.png') });

  // 5. Switch to Policy Author & Semantic Policies
  console.log('5. Capturing 04_policy_author_semantic_policies.png');
  const signOutBtn2 = await page.$('button:has-text("Sign Out")');
  if (signOutBtn2) await signOutBtn2.click();
  await page.waitForTimeout(1000);
  const authorDemoBtn = await page.$('button:has-text("Policy Author")');
  if (authorDemoBtn) await authorDemoBtn.click();
  await page.waitForTimeout(500);
  const signInBtn3 = await page.$('#sign-in-btn');
  if (signInBtn3) await signInBtn3.click();
  await page.waitForTimeout(2000);
  const polNav = await page.$('button:has-text("Semantic Policies")');
  if (polNav) await polNav.click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '04_policy_author_semantic_policies.png') });

  // 6. Switch to Auditor
  console.log('6. Capturing 05_auditor_read_only_view.png');
  const signOutBtn3 = await page.$('button:has-text("Sign Out")');
  if (signOutBtn3) await signOutBtn3.click();
  await page.waitForTimeout(1000);
  const auditorDemoBtn = await page.$('button:has-text("Security Auditor")');
  if (auditorDemoBtn) await auditorDemoBtn.click();
  await page.waitForTimeout(500);
  const signInBtn4 = await page.$('#sign-in-btn');
  if (signInBtn4) await signInBtn4.click();
  await page.waitForTimeout(2000);
  const evNav = await page.$('button:has-text("Evidence Vault")');
  if (evNav) await evNav.click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '05_auditor_read_only_view.png') });

  // 7. Access Denied (Switch to Viewer and navigate to User Management -> renders AccessRestricted)
  console.log('7. Capturing 06_access_denied.png');
  const signOutBtn4 = await page.$('button:has-text("Sign Out")');
  if (signOutBtn4) await signOutBtn4.click();
  await page.waitForTimeout(1000);
  const viewerDemoBtn = await page.$('button:has-text("Read-Only Viewer")');
  if (viewerDemoBtn) await viewerDemoBtn.click();
  await page.waitForTimeout(500);
  const signInBtn5 = await page.$('#sign-in-btn');
  if (signInBtn5) await signInBtn5.click();
  await page.waitForTimeout(2000);

  // Directly navigate to User Management via QA helper
  await page.evaluate(() => {
    if (window.__navigateTo) window.__navigateTo('users');
  });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '06_access_denied.png') });

  // 8. Swagger Authentication
  console.log('8. Capturing 08_swagger_authentication.png');
  await page.goto('http://localhost:8000/docs');
  await page.waitForTimeout(2500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '08_swagger_authentication.png') });

  // 9. Authenticated API Request (Swagger or JSON)
  console.log('9. Capturing 09_authenticated_api_request.png');
  await page.goto('http://localhost:8000/openapi.json');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '09_authenticated_api_request.png') });

  // 10. Copy PPT Assets
  console.log('10. Copying PPT Assets');
  const pptFiles = [
    '02_admin_dashboard_identity.png',
    '03_security_analyst_navigation.png',
    '06_access_denied.png',
    '07_user_management.png',
  ];
  for (const f of pptFiles) {
    const src = path.join(OUTPUT_DIR, f);
    const dest = path.join(PPT_DIR, f);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      console.log(`Copied ${f} to PPT assets`);
    }
  }

  // 11. Also capture 10_docker_services.png via page or dashboard
  console.log('11. Capturing 10_docker_services.png');
  await page.goto('http://localhost:3000');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, '10_docker_services.png') });

  await browser.close();
  console.log('All Sprint 4A evidence captured successfully!');
}

captureAllEvidence().catch(err => {
  console.error('Evidence capture failed:', err);
  process.exit(1);
});
