/**
 * SemanticPolicies.jsx
 * --------------------
 * Semantic Policy Registry, Versioning, Read-Only Comparison, Protected Fields,
 * and Vendor Semantic Isolation Dashboard for SentinelTrace V5 (Sprint 3C).
 */

import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { API_V1_URL } from "../apiConfig";

const API_BASE = API_V1_URL;

export default function SemanticPolicies() {
  const { user, authFetch } = useAuth();
  const [policies, setPolicies] = useState([]);
  const [protectedFields, setProtectedFields] = useState([]);
  const [loading, setLoading] = useState(false);

  // Selected policy for View detail modal
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Comparison State
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [sourcePolId, setSourcePolId] = useState("spol_cisco_asa_v1");
  const [targetPolId, setTargetPolId] = useState("spol_cisco_asa_v2_draft");
  const [comparisonResult, setComparisonResult] = useState(null);
  const [compareLoading, setCompareLoading] = useState(false);

  // Draft Creation Modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState({
    policy_name: "",
    vendor_name: "",
    source_profile_id: "sp_firewall_syslog",
    version: 1,
    description: "",
    rule_source_field: "action",
    rule_source_value: "",
    rule_canonical_field: "action.result",
    rule_canonical_value: "",
    rule_classification: "EQUIVALENT",
    rule_risk_level: "LOW",
  });
  const [createSuccessMsg, setCreateSuccessMsg] = useState(null);
  const [createErrorMsg, setCreateErrorMsg] = useState(null);

  // Lineage View Tab inside Policy Registry
  const [viewTab, setViewTab] = useState("policies"); // 'policies' | 'lineage' | 'protected'

  const fetchData = async () => {
    setLoading(true);
    try {
      const [resPols, resFields] = await Promise.all([
        fetch(`${API_BASE}/semantic-policies`),
        fetch(`${API_BASE}/protected-fields`),
      ]);
      if (resPols.ok) {
        const data = await resPols.json();
        setPolicies(data || []);
      }
      if (resFields.ok) {
        const data = await resFields.json();
        setProtectedFields(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch policies or fields:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const openPolicyDetail = async (policyId) => {
    setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/semantic-policies/${policyId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedPolicy(data);
      }
    } catch (err) {
      console.error("Failed to load policy detail:", err);
    } finally {
      setDetailLoading(false);
    }
  };

  const runComparison = async (sId, tId) => {
    setCompareLoading(true);
    try {
      const res = await fetch(`${API_BASE}/semantic-policies/compare?source_policy_id=${sId}&target_policy_id=${tId}`);
      if (res.ok) {
        const data = await res.json();
        setComparisonResult(data);
      }
    } catch (err) {
      console.error("Comparison failed:", err);
    } finally {
      setCompareLoading(false);
    }
  };

  const handleOpenCompareModal = (pol) => {
    const sId = pol?.policy_id || "spol_cisco_asa_v1";
    const tId = pol?.supersedes_policy_id || (sId === "spol_cisco_asa_v1" ? "spol_cisco_asa_v2_draft" : "spol_cisco_asa_v1");
    setSourcePolId(sId);
    setTargetPolId(tId);
    setIsCompareOpen(true);
    runComparison(sId, tId);
  };

  const handleCreateDraft = async (e) => {
    e.preventDefault();
    setCreateSuccessMsg(null);
    setCreateErrorMsg(null);

    const payload = {
      policy_name: createForm.policy_name,
      vendor_name: createForm.vendor_name,
      source_profile_id: createForm.source_profile_id,
      version: parseInt(createForm.version, 10) || 1,
      status: "DRAFT",
      description: createForm.description,
      rules: createForm.rule_source_value ? [
        {
          source_field: createForm.rule_source_field,
          source_value: createForm.rule_source_value,
          canonical_field: createForm.rule_canonical_field,
          canonical_value: createForm.rule_canonical_value,
          equivalence_classification: createForm.rule_classification,
          risk_level: createForm.rule_risk_level,
          description: "Initial rule registered during draft policy creation",
        }
      ] : [],
    };

    try {
      const res = await fetch(`${API_BASE}/semantic-policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        setCreateSuccessMsg(`Policy '${data.policy_name}' created successfully in forced DRAFT state.`);
        fetchData();
        setTimeout(() => {
          setIsCreateOpen(false);
          setCreateSuccessMsg(null);
        }, 1800);
      } else {
        const err = await res.json();
        setCreateErrorMsg(err.detail || "Failed to create policy");
      }
    } catch (err) {
      setCreateErrorMsg("Network error creating policy.");
    }
  };

  // Metrics
  const totalPolicies = policies.length;
  const activePolicies = policies.filter((p) => p.status === "ACTIVE").length;
  const draftPolicies = policies.filter((p) => p.status === "DRAFT").length;
  const protectedCount = protectedFields.length;

  return (
    <div className="flex-1 overflow-y-auto bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-wider text-slate-100 font-mono">
              SEMANTIC POLICY REGISTRY
            </h1>
            <span className="px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Sprint 3C Active
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Deterministic vendor-scoped semantic mapping rules, version governance, and zero global assumptions.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => handleOpenCompareModal(null)}
            className="px-4 py-2 rounded-lg bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 hover:bg-indigo-600/30 text-sm font-medium transition-all flex items-center gap-2"
          >
            <span>⚖️</span> Compare Versions
          </button>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2 rounded-lg bg-cyan-600/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-600/30 text-sm font-medium transition-all flex items-center gap-2"
          >
            <span>➕</span> Register Draft Policy
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="text-xs uppercase font-mono tracking-wider text-slate-400">Total Policies</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{totalPolicies}</div>
          <div className="text-xs text-slate-500 mt-1">Scoped to vendor profiles</div>
        </div>
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="text-xs uppercase font-mono tracking-wider text-emerald-400">Active Policies</div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">{activePolicies}</div>
          <div className="text-xs text-slate-500 mt-1">Live semantic authority</div>
        </div>
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="text-xs uppercase font-mono tracking-wider text-amber-400">Draft Policies</div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{draftPolicies}</div>
          <div className="text-xs text-slate-500 mt-1">Pending governance review</div>
        </div>
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="text-xs uppercase font-mono tracking-wider text-cyan-400">Protected Fields</div>
          <div className="text-2xl font-bold font-mono text-cyan-300 mt-1">{protectedCount}</div>
          <div className="text-xs text-slate-500 mt-1">High-scrutiny security fields</div>
        </div>
      </div>

      {/* FEATURE 3: HERO COMPONENT — "Same Token, Different Meaning" */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-900 border border-cyan-500/30 rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="text-xl">⚡</span>
            <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-cyan-300">
              Core Architectural Demonstration: Same Token, Different Meaning
            </h2>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-500/20">
            No Global Assumptions
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          {/* Left: Cisco ASA */}
          <div className="bg-slate-950/80 border border-emerald-500/30 rounded-lg p-4 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>VENDOR A</span>
              <span className="text-emerald-400 font-semibold">Cisco ASA Firewall</span>
            </div>
            <div className="text-xs text-slate-400">Policy: <code className="text-slate-300">spol_cisco_asa_v1</code></div>
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Raw Token</span>
                <span className="text-base font-bold font-mono text-cyan-400">PERMIT</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Interpreted Value</span>
                <span className="text-sm font-bold font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  ALLOWED
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono pt-1 text-slate-400">
              <span>Classification: <strong className="text-emerald-400">COMPATIBLE</strong></span>
              <span>Risk: <strong className="text-emerald-400">LOW</strong></span>
            </div>
          </div>

          {/* Center: Vendor Context Isolation Engine */}
          <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-4 text-center space-y-2">
            <div className="text-xs font-mono uppercase text-slate-400 tracking-wider">
              RAW LOG TOKEN: <code className="text-cyan-400 font-bold text-sm">"PERMIT"</code>
            </div>
            <div className="text-slate-500 text-lg">↓</div>
            <div className="px-3 py-1.5 rounded-md bg-indigo-950/60 border border-indigo-500/40 text-indigo-300 text-xs font-mono font-semibold inline-block">
              VENDOR CONTEXT ISOLATION
            </div>
            <div className="text-slate-500 text-lg">↓</div>
            <div className="text-xs text-slate-300 font-medium">
              DIFFERENT CANONICAL MEANINGS
            </div>
          </div>

          {/* Right: Demo Vendor */}
          <div className="bg-slate-950/80 border border-amber-500/30 rounded-lg p-4 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>VENDOR B</span>
              <span className="text-amber-400 font-semibold">Demo Vendor Appliance</span>
            </div>
            <div className="text-xs text-slate-400">Policy: <code className="text-slate-300">spol_demo_vendor_v1</code></div>
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Raw Token</span>
                <span className="text-base font-bold font-mono text-cyan-400">PERMIT</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] uppercase font-mono text-slate-500 block">Interpreted Value</span>
                <span className="text-sm font-bold font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  MONITORED
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono pt-1 text-slate-400">
              <span>Classification: <strong className="text-amber-400">AMBIGUOUS</strong></span>
              <span>Risk: <strong className="text-amber-400">MEDIUM</strong></span>
            </div>
          </div>
        </div>

        <p className="text-xs text-slate-400 mt-4 italic bg-slate-950/60 p-2.5 rounded border border-slate-800">
          "SentinelTrace does not use global semantic assumptions. Interpretation is scoped exclusively to vendor, source profile, and policy version."
        </p>
      </div>

      {/* Tabs for Policy Registry Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-800">
        <button
          onClick={() => setViewTab("policies")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-all ${
            viewTab === "policies"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          📋 Policy Registry Table ({policies.length})
        </button>
        <button
          onClick={() => setViewTab("lineage")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-all ${
            viewTab === "lineage"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          🌿 Version Lineage & History
        </button>
        <button
          onClick={() => setViewTab("protected")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-all ${
            viewTab === "protected"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          🛡️ Protected Semantic Fields ({protectedFields.length})
        </button>
      </div>

      {/* TAB 1: MAIN POLICY TABLE */}
      {viewTab === "policies" && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
            <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Registered Vendor Semantic Policies
            </h3>
            <span className="text-xs text-slate-500 font-mono">
              Activation governance requires future dual-control review
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Policy ID</th>
                  <th className="p-3">Vendor</th>
                  <th className="p-3">Source Profile</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Rules</th>
                  <th className="p-3">Supersedes</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono text-slate-300">
                {policies.map((p) => (
                  <tr key={p.policy_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3 font-semibold text-cyan-300">{p.policy_id}</td>
                    <td className="p-3 text-slate-200">{p.vendor_name}</td>
                    <td className="p-3 text-slate-400">{p.source_profile_id}</td>
                    <td className="p-3">v{p.version}</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          p.status === "ACTIVE"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : p.status === "DRAFT"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : p.status === "SUPERSEDED"
                            ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {p.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">{p.rule_count} rules</td>
                    <td className="p-3 text-slate-500">{p.supersedes_policy_id || "—"}</td>
                    <td className="p-3 text-right space-x-2">
                      {p.status === "DRAFT" && (
                        <button
                          onClick={async () => {
                            try {
                              const res = await (authFetch ? authFetch(`/api/v1/semantic-policies/${p.policy_id}/submit`, { method: "POST" }) : fetch(`${API_BASE}/semantic-policies/${p.policy_id}/submit`, { method: "POST" }));
                              if (res.ok) {
                                alert(`Policy ${p.policy_id} submitted for dual-control review!`);
                                fetchData();
                              } else {
                                const err = await res.json();
                                alert(`Submission failed: ${err.detail || 'Error'}`);
                              }
                            } catch (e) {
                              alert(`Error submitting policy: ${e.message}`);
                            }
                          }}
                          className="px-2.5 py-1 rounded bg-amber-950/70 hover:bg-amber-900 border border-amber-500/50 text-amber-300 text-[11px] transition-all font-mono"
                        >
                          Submit
                        </button>
                      )}
                      <button
                        onClick={() => openPolicyDetail(p.policy_id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] transition-all"
                      >
                        View Rules
                      </button>
                      <button
                        onClick={() => handleOpenCompareModal(p)}
                        className="px-2.5 py-1 rounded bg-indigo-900/40 hover:bg-indigo-900/60 text-indigo-300 border border-indigo-700/50 text-[11px] transition-all"
                      >
                        Compare
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: VERSION LINEAGE & VISUALIZATION */}
      {viewTab === "lineage" && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Policy Version Lineage & Lifecycle Trace
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Historical lineage across revisions. Policy versions remain distinct database records and are never overwritten.
            </p>
          </div>

          {/* Cisco ASA Version Lineage Diagram */}
          <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-cyan-400 font-semibold uppercase">
              Cisco ASA Semantic Policy Lineage Graph
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
              {/* v0: SUPERSEDED */}
              <div className="bg-slate-900/90 border border-purple-500/30 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-purple-400 font-bold">VERSION 0</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950/60 text-purple-300 border border-purple-500/30">
                    SUPERSEDED
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-300 font-semibold">spol_cisco_asa_v0</div>
                <div className="text-[11px] text-slate-400">
                  Legacy interpretation: <code className="text-amber-400">PERMIT → MONITORED</code> (AMBIGUOUS)
                </div>
                <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
                  Superseded by <span className="text-cyan-400 font-mono">spol_cisco_asa_v1</span>
                </div>
              </div>

              {/* Arrow 1 */}
              <div className="text-center text-slate-500 font-mono text-lg">
                <span className="hidden md:inline">➔</span>
                <span className="md:hidden block">↓</span>
                <div className="text-[10px] text-slate-500 uppercase mt-1">Version Migration</div>
              </div>

              {/* v1: ACTIVE */}
              <div className="bg-slate-900/90 border border-emerald-500/40 rounded-lg p-4 space-y-2 ring-1 ring-emerald-500/20 shadow-md">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-emerald-400 font-bold">VERSION 1 (CURRENT)</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
                    ACTIVE
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-200 font-semibold">spol_cisco_asa_v1</div>
                <div className="text-[11px] text-slate-300">
                  Standardized: <code className="text-emerald-400">PERMIT → ALLOWED</code> (COMPATIBLE)
                </div>
                <div className="text-[10px] text-emerald-400/80 pt-2 border-t border-slate-800">
                  Live Active Authority in Production
                </div>
              </div>
            </div>

            {/* Candidate v2 */}
            <div className="mt-4 pt-4 border-t border-slate-800/80">
              <div className="text-xs font-mono text-amber-400 font-semibold uppercase mb-2">
                Proposed Candidate Lineage (Under Evaluation)
              </div>
              <div className="bg-slate-900/70 border border-amber-500/30 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-amber-300">VERSION 2 (CANDIDATE)</span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-amber-950/60 text-amber-300 border border-amber-500/30">
                      DRAFT
                    </span>
                    <span className="text-xs font-mono text-slate-400">spol_cisco_asa_v2_draft</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Proposes reclassifying <code className="text-amber-400">PERMIT → MONITORED</code> for deep observation & adding <code className="text-cyan-400">BYPASS → ALLOWED</code> rule.
                  </p>
                </div>
                <button
                  onClick={() => runComparison("spol_cisco_asa_v1", "spol_cisco_asa_v2_draft") || setIsCompareOpen(true)}
                  className="px-3 py-1.5 rounded bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/40 text-xs font-medium whitespace-nowrap"
                >
                  View Diff vs Active v1
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: PROTECTED SEMANTIC FIELDS */}
      {viewTab === "protected" && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider">
                Protected Semantic Fields Catalog
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Canonical security telemetry fields requiring strict governance and elevated drift alerts.
              </p>
            </div>
            <div className="px-3 py-1.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
              ⚠️ Strict Scrutiny Policy
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {protectedFields.map((f) => (
              <div key={f.field_name} className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan-400">{f.field_name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                      f.criticality === "CRITICAL"
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                    }`}
                  >
                    {f.criticality}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>Protection Status:</span>
                  <span className="text-emerald-400 font-semibold">ENFORCED</span>
                </div>
              </div>
            ))}
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-amber-500/20 text-xs text-slate-300 leading-relaxed">
            <span className="font-bold text-amber-300 font-mono">GOVERNANCE ENFORCEMENT NOTE: </span>
            "Changes affecting protected semantic fields receive elevated interpretation scrutiny, trigger high-severity drift alerts, and cannot be silently treated as harmless."
          </div>
        </div>
      )}

      {/* MODAL 1: POLICY DETAIL VIEW */}
      {selectedPolicy && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-lg font-bold font-mono text-slate-100">
                  {selectedPolicy.policy_name}
                </h3>
                <span className="text-xs font-mono text-slate-400">ID: {selectedPolicy.policy_id}</span>
              </div>
              <button
                onClick={() => setSelectedPolicy(null)}
                className="text-slate-400 hover:text-slate-100 text-lg font-mono px-2 py-1"
              >
                ✕
              </button>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950 p-4 rounded-lg text-xs font-mono border border-slate-800">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Vendor</span>
                <span className="text-slate-200 font-semibold">{selectedPolicy.vendor_name}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Source Profile</span>
                <span className="text-slate-200 font-semibold">{selectedPolicy.source_profile_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Version</span>
                <span className="text-cyan-400 font-semibold">v{selectedPolicy.version}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Status</span>
                <span className="text-emerald-400 font-semibold">{selectedPolicy.status}</span>
              </div>
            </div>

            <p className="text-xs text-slate-400 italic">{selectedPolicy.description}</p>

            {/* Semantic Rules Table */}
            <div>
              <h4 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider mb-2">
                Scoped Semantic Mapping Rules ({selectedPolicy.rules?.length || 0})
              </h4>
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Source Field</th>
                      <th className="p-2.5">Source Value</th>
                      <th className="p-2.5">Canonical Field</th>
                      <th className="p-2.5">Target Value</th>
                      <th className="p-2.5">Classification</th>
                      <th className="p-2.5">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono text-slate-300">
                    {selectedPolicy.rules?.map((r) => (
                      <tr key={r.rule_id} className="hover:bg-slate-800/40">
                        <td className="p-2.5 text-slate-400">{r.source_field}</td>
                        <td className="p-2.5 font-bold text-cyan-300">{r.source_value}</td>
                        <td className="p-2.5 text-slate-400">{r.canonical_field}</td>
                        <td className="p-2.5 font-bold text-emerald-300">{r.canonical_value}</td>
                        <td className="p-2.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              r.equivalence_classification === "EQUIVALENT"
                                ? "bg-emerald-500/20 text-emerald-300"
                                : r.equivalence_classification === "COMPATIBLE"
                                ? "bg-cyan-500/20 text-cyan-300"
                                : "bg-amber-500/20 text-amber-300"
                            }`}
                          >
                            {r.equivalence_classification}
                          </span>
                        </td>
                        <td className="p-2.5">
                          <span className={`text-[10px] font-bold ${r.risk_level === "LOW" ? "text-emerald-400" : "text-amber-400"}`}>
                            {r.risk_level}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPolicy(null)}
                className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono"
              >
                Close View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: READ-ONLY POLICY COMPARISON VIEW */}
      {isCompareOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-xl">⚖️</span>
                <div>
                  <h3 className="text-base font-bold font-mono text-slate-100">
                    READ-ONLY POLICY VERSION COMPARISON
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    Deterministic diff of semantic mappings across revisions
                  </span>
                </div>
              </div>
              <button
                onClick={() => setIsCompareOpen(false)}
                className="text-slate-400 hover:text-slate-100 text-lg font-mono px-2 py-1"
              >
                ✕
              </button>
            </div>

            {/* Read-Only Banner */}
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-300 flex items-center justify-between">
              <span>⚠️ <strong>Governance Notice:</strong> Policy comparison is read-only. Candidate policies cannot be activated without formal approval workflow.</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-500/30">
                READ ONLY
              </span>
            </div>

            {/* Selectors */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Source (Base Version):</label>
                <select
                  value={sourcePolId}
                  onChange={(e) => {
                    setSourcePolId(e.target.value);
                    runComparison(e.target.value, targetPolId);
                  }}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200"
                >
                  {policies.map((p) => (
                    <option key={p.policy_id} value={p.policy_id}>
                      {p.policy_name} (v{p.version} - {p.status})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Target (Candidate / Comparison):</label>
                <select
                  value={targetPolId}
                  onChange={(e) => {
                    setTargetPolId(e.target.value);
                    runComparison(sourcePolId, e.target.value);
                  }}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200"
                >
                  {policies.map((p) => (
                    <option key={p.policy_id} value={p.policy_id}>
                      {p.policy_name} (v{p.version} - {p.status})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Comparison Metrics */}
            {comparisonResult && (
              <div className="space-y-4">
                <div className="grid grid-cols-4 gap-3 text-center font-mono text-xs">
                  <div className="bg-slate-950 p-3 rounded border border-slate-800">
                    <div className="text-slate-500 text-[10px] uppercase">Unchanged Rules</div>
                    <div className="text-lg font-bold text-slate-200">{comparisonResult.summary?.unchanged_count || 0}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded border border-rose-500/30">
                    <div className="text-rose-400 text-[10px] uppercase">Changed Meanings</div>
                    <div className="text-lg font-bold text-rose-300">{comparisonResult.summary?.changed_count || 0}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded border border-emerald-500/30">
                    <div className="text-emerald-400 text-[10px] uppercase">Added Rules</div>
                    <div className="text-lg font-bold text-emerald-300">{comparisonResult.summary?.added_count || 0}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded border border-slate-800">
                    <div className="text-slate-500 text-[10px] uppercase">Removed Rules</div>
                    <div className="text-lg font-bold text-slate-400">{comparisonResult.summary?.removed_count || 0}</div>
                  </div>
                </div>

                {/* Changed Semantic Meanings Section */}
                {comparisonResult.changed_rules?.length > 0 && (
                  <div className="bg-rose-950/20 border border-rose-500/30 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-rose-400 font-bold uppercase tracking-wider">
                        ⚠️ Semantic Meaning Shift Detected ({comparisonResult.changed_rules.length})
                      </span>
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px]">
                        HIGH SEMANTIC IMPACT
                      </span>
                    </div>

                    <div className="space-y-2">
                      {comparisonResult.changed_rules.map((c, idx) => (
                        <div key={idx} className="bg-slate-950 p-3 rounded border border-slate-800 text-xs font-mono space-y-2">
                          <div className="flex items-center justify-between text-slate-300">
                            <span>Field: <strong className="text-cyan-300">{c.source_field}</strong> | Token: <strong className="text-cyan-300">"{c.source_value}"</strong></span>
                            <span className="text-rose-400 font-bold">Impact: {c.semantic_impact}</span>
                          </div>
                          <div className="grid grid-cols-2 gap-3 text-[11px] pt-2 border-t border-slate-850">
                            <div className="p-2 rounded bg-slate-900 border border-slate-800">
                              <span className="text-slate-500 block text-[9px] uppercase">Old Canonical Meaning</span>
                              <div className="font-bold text-slate-200 mt-0.5">{c.old_canonical_value}</div>
                              <div className="text-[10px] text-slate-400">{c.old_classification} · {c.old_risk_level} Risk</div>
                            </div>
                            <div className="p-2 rounded bg-slate-900 border border-amber-500/30">
                              <span className="text-amber-400 block text-[9px] uppercase">New Candidate Meaning</span>
                              <div className="font-bold text-amber-300 mt-0.5">{c.new_canonical_value}</div>
                              <div className="text-[10px] text-amber-400/80">{c.new_classification} · {c.new_risk_level} Risk</div>
                            </div>
                          </div>
                          {c.description && <p className="text-[11px] text-slate-400 italic">{c.description}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Added Rules Section */}
                {comparisonResult.added_rules?.length > 0 && (
                  <div className="bg-slate-950 border border-emerald-500/30 rounded-lg p-3 space-y-2">
                    <span className="text-xs font-mono font-bold text-emerald-400 uppercase">
                      ➕ Added Rules in Target Version ({comparisonResult.added_rules.length})
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                      {comparisonResult.added_rules.map((r) => (
                        <div key={r.rule_id} className="bg-slate-900 p-2.5 rounded border border-slate-800">
                          <div className="text-cyan-300 font-bold">{r.source_field} = "{r.source_value}"</div>
                          <div className="text-emerald-400 text-[11px]">→ {r.canonical_field} = {r.canonical_value} ({r.equivalence_classification})</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setIsCompareOpen(false)}
                className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono"
              >
                Close Comparison
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: CREATE DRAFT POLICY */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold font-mono text-slate-100">
                REGISTER DRAFT SEMANTIC POLICY
              </h3>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="text-slate-400 hover:text-slate-100 text-lg font-mono px-2 py-1"
              >
                ✕
              </button>
            </div>

            {/* Governance Warning */}
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-300">
              ⚠️ <strong>Governance Constraint:</strong> Newly registered policies are strictly initialized to <code>DRAFT</code> status. Policy activation requires governance workflow in a later sprint.
            </div>

            {createSuccessMsg && (
              <div className="p-3 bg-emerald-500/20 border border-emerald-500/40 rounded text-xs text-emerald-300 font-mono">
                ✓ {createSuccessMsg}
              </div>
            )}
            {createErrorMsg && (
              <div className="p-3 bg-rose-500/20 border border-rose-500/40 rounded text-xs text-rose-300 font-mono">
                ✕ {createErrorMsg}
              </div>
            )}

            <form onSubmit={handleCreateDraft} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Policy Title:</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Fortinet FortiGate Baseline Policy"
                  value={createForm.policy_name}
                  onChange={(e) => setCreateForm({ ...createForm, policy_name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Vendor Name:</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Fortinet"
                    value={createForm.vendor_name}
                    onChange={(e) => setCreateForm({ ...createForm, vendor_name: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Source Profile:</label>
                  <select
                    value={createForm.source_profile_id}
                    onChange={(e) => setCreateForm({ ...createForm, source_profile_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                  >
                    <option value="sp_firewall_syslog">sp_firewall_syslog (Syslog)</option>
                    <option value="sp_auth_json">sp_auth_json (JSON)</option>
                    <option value="sp_process_csv">sp_process_csv (CSV)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Description / Rationale:</label>
                <textarea
                  rows={2}
                  placeholder="Technical justification and telemetry scoping"
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                />
              </div>

              {/* Initial Rule Definition */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-[11px] font-bold text-slate-300 uppercase">Optional Initial Rule</span>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    type="text"
                    placeholder="Source Value (e.g. ACCEPT)"
                    value={createForm.rule_source_value}
                    onChange={(e) => setCreateForm({ ...createForm, rule_source_value: e.target.value })}
                    className="bg-slate-950 border border-slate-700 rounded p-1.5 text-slate-100 text-xs"
                  />
                  <input
                    type="text"
                    placeholder="Target Value (e.g. ALLOWED)"
                    value={createForm.rule_canonical_value}
                    onChange={(e) => setCreateForm({ ...createForm, rule_canonical_value: e.target.value })}
                    className="bg-slate-950 border border-slate-700 rounded p-1.5 text-slate-100 text-xs"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs font-mono"
                >
                  Save Draft Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
