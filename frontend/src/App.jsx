/**
 * App.jsx
 * -------
 * Root application shell for SENTINEL-TRACE.
 *
 * Sprint 4A: Identity & Role-Based Access Control (RBAC) + Full Platform Navigation.
 */

import React, { useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import EvidenceVault from "./pages/EvidenceVault";
import Normalization from "./pages/Normalization";
import SemanticPolicies from "./pages/SemanticPolicies";
import SemanticIntelligence from "./pages/SemanticIntelligence";
import UserManagement from "./pages/UserManagement";
import UserProfile from "./pages/UserProfile";
import PolicyApprovals from "./pages/PolicyApprovals";
import GovernanceLedger from "./pages/GovernanceLedger";
import MerkleVerification from "./pages/MerkleVerification";
import DetectionRules from "./pages/DetectionRules";
import DetectionTrust from "./pages/DetectionTrust";
import DetectionRuleGovernance from "./pages/DetectionRuleGovernance";
import DetectionExecution from "./pages/DetectionExecution";
import RiskRemediation from "./pages/RiskRemediation";
import SecurityIncidents from "./pages/SecurityIncidents";
import IncidentResponse from "./pages/IncidentResponse";
import SecurityAssurance from "./pages/SecurityAssurance";
import AssuranceRemediation from "./pages/AssuranceRemediation";
import ExecutiveSecurityIntelligence from "./pages/ExecutiveSecurityIntelligence";
import SecurityScenarioCommandCenter from "./pages/SecurityScenarioCommandCenter";
import ComplianceIntelligence from "./pages/ComplianceIntelligence";
import ThreatIntelligenceCommandCenter from "./pages/ThreatIntelligenceCommandCenter";
import SecurityInvestigationCommandCenter from "./pages/SecurityInvestigationCommandCenter";
import SecurityAnalyticsCommandCenter from "./pages/SecurityAnalyticsCommandCenter";
import Login from "./pages/Login";

// Placeholder page for future navigation items
function ComingSoonPage({ page }) {
  return (
    <main className="flex-1 flex items-center justify-center bg-sentinel-950 p-8">
      <div className="text-center space-y-4 animate-fade-in max-w-md">
        <div className="text-5xl">🚧</div>
        <h2 className="text-xl font-bold text-slate-200 capitalize font-mono">
          {page.replace(/-/g, " ")}
        </h2>
        <p className="text-slate-500 text-xs leading-relaxed">
          This governance module is planned for an upcoming sprint.
          <br />
          Sprint 4A (Identity & RBAC) is live and active.
        </p>
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-accent-cyan/5 border border-accent-cyan/20 text-accent-cyan text-xs font-mono">
          Sprint 4B/5 Roadmap Target
        </div>
      </div>
    </main>
  );
}

function MainAppShell() {
  const { isAuthenticated, loading } = useAuth();
  const [activePage, setActivePage] = useState("dashboard");

  // Expose navigation helper for test automation and QA
  if (typeof window !== "undefined") {
    window.__navigateTo = setActivePage;
  }

  if (loading) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-sentinel-950 text-slate-400 font-mono">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs tracking-widest uppercase">Verifying Security Session...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => setActivePage("dashboard")} />;
  }

  const renderPage = () => {
    switch (activePage) {
      case "dashboard":
        return <Dashboard onNavigate={setActivePage} />;
      case "evidence-vault":
      case "log-ingestion":
        return <EvidenceVault />;
      case "normalization":
        return <Normalization />;
      case "semantic-policies":
        return <SemanticPolicies />;
      case "semantic-intelligence":
      case "alerts":
        return <SemanticIntelligence />;
      case "users":
        return <UserManagement />;
      case "approvals":
      case "policy-approvals":
      case "governance":
        return <PolicyApprovals />;
      case "cryptographic-ledger":
      case "governance-ledger":
      case "ledger":
        return <GovernanceLedger />;
      case "merkle-audit":
      case "merkle":
      case "merkle-verification":
        return <MerkleVerification />;
      case "detection-rules":
        return <DetectionRules />;
      case "detection-trust":
      case "trust":
      case "detection-rule-trust":
        return <DetectionTrust />;
      case "detection-rule-governance":
      case "rule-governance":
      case "governance-rules":
        return <DetectionRuleGovernance />;
      case "detection-execution":
      case "execution":
      case "rule-execution":
      case "detections":
        return <DetectionExecution />;
      case "risk-remediation":
      case "remediation":
      case "risk-intelligence":
      case "posture":
        return <RiskRemediation />;
      case "incidents":
      case "security-incidents":
      case "incident-investigation":
      case "soc":
        return <SecurityIncidents />;
      case "incident-response":
      case "containment":
      case "response":
        return <IncidentResponse />;
      case "security-assurance":
      case "assurance":
      case "platform-health":
      case "health-intelligence":
        return <SecurityAssurance />;
      case "assurance-remediation":
      case "remediation-governance":
      case "assurance-recovery":
      case "recovery":
        return <AssuranceRemediation />;
      case "executive-security":
      case "executive-intelligence":
      case "command-center":
      case "risk-posture":
        return <ExecutiveSecurityIntelligence />;
      case "security-scenarios":
      case "scenarios":
      case "orchestration":
      case "replay":
        return <SecurityScenarioCommandCenter />;
      case "compliance-intelligence":
      case "compliance":
      case "controls":
      case "governance-controls":
      case "frameworks":
        return <ComplianceIntelligence />;
      case "threat-intelligence":
      case "threat-intel":
      case "ioc-explorer":
      case "adversary-intel":
        return <ThreatIntelligenceCommandCenter />;
      case "investigations":
      case "security-investigations":
      case "cases":
      case "investigation-workspace":
      case "soc-investigation":
        return <SecurityInvestigationCommandCenter />;
      case "security-analytics":
      case "analytics":
      case "reports":
      case "evidence-packages":
      case "security-reports":
        return <SecurityAnalyticsCommandCenter />;
      case "profile":
        return <UserProfile onNavigate={setActivePage} />;
      default:
        return <ComingSoonPage page={activePage} />;
    }
  };

  return (
    <div className="h-full flex overflow-hidden">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />
      {renderPage()}
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainAppShell />
    </AuthProvider>
  );
}
