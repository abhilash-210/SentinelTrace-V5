"""
tests/test_sprint11b_threat_intelligence.py
-------------------------------------------
Comprehensive automated test suite for Sprint 11B:
- Threat Intelligence Ingestion, Canonical Normalization & IOC Validation
- Multi-feed Source Trust Levels & Artifact Hashing
- IOC Normalization (IP, Domain, URL, Hash, Email, Hostname)
- Deterministic Threat Trust Scoring (Base 100 with Explainable Deductions)
- Cryptographic Dominance Override: Forced Crypto Failure forces score 0.0 & UNTRUSTED status
- Adversary Context: Threat Actors, Campaigns, Actor-Campaign Mappings
- MITRE ATT&CK Tactic & Technique Mappings
- Deterministic IOC Observable Event Correlation Engine
- 15-Stage Unbroken Cryptographic Provenance Lineage
- Centralized RBAC Enforcement across Platform Roles
- Full REST API Test Coverage
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import unittest
import uuid
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.threat_intelligence import (
    ThreatIntelligenceSource,
    ThreatIntelligenceArtifact,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    ThreatActorCampaignMapping,
    ThreatMitreMapping,
    ThreatIntelligenceCorrelation,
    ThreatIntelligenceTrustEvaluation,
    ThreatIntelligenceInsight,
    ThreatProvenanceRecord,
    ARTIFACT_DOMAIN_PREFIX,
    INDICATOR_DOMAIN_PREFIX,
    CAMPAIGN_DOMAIN_PREFIX,
    TRUST_EVALUATION_DOMAIN_PREFIX,
    CORRELATION_DOMAIN_PREFIX,
    PROVENANCE_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.threat_indicator_service import ThreatIndicatorService
from app.services.threat_intelligence_trust_service import ThreatIntelligenceTrustService
from app.services.threat_actor_campaign_service import ThreatActorCampaignService
from app.services.threat_mitre_mapping_service import ThreatMitreMappingService
from app.services.threat_intelligence_correlation_service import ThreatIntelligenceCorrelationService
from app.services.threat_intelligence_provenance_service import ThreatIntelligenceProvenanceService, PROVENANCE_15_STAGES
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint11BThreatIntelligence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.db = SessionLocal()
        # Seed dependencies
        NormalizationService.ensure_default_source_profiles(cls.db)
        SemanticPolicyService.seed_defaults(cls.db)
        UserService.seed_demo_users(cls.db)
        ThreatActorCampaignService.seed_default_threat_intelligence(cls.db)
        cls.db.commit()

        # Auth headers by Role
        cls.admin_headers = get_auth_headers("ADMIN")
        cls.analyst_headers = get_auth_headers("SECURITY_ANALYST")
        cls.reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        cls.author_headers = get_auth_headers("POLICY_AUTHOR")
        cls.auditor_headers = get_auth_headers("AUDITOR")
        cls.viewer_headers = get_auth_headers("VIEWER")

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # ── 1. Source Management & Trust Levels ───────────────────────────────────
    def test_01_create_and_query_threat_source(self):
        source = ThreatIntelligenceSource(
            source_name=f"Custom Threat Feed {uuid.uuid4().hex[:6]}",
            source_type="COMMERCIAL",
            description="High fidelity commercial feed.",
            provider="Vendor Threat Labs",
            trust_level="TRUSTED",
            is_active=True,
        )
        self.db.add(source)
        self.db.commit()

        found = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.id == source.id).first()
        self.assertIsNotNone(found)
        self.assertEqual(found.trust_level, "TRUSTED")
        self.assertEqual(found.source_type, "COMMERCIAL")

    def test_02_source_trust_level_variations(self):
        for tlevel in ["TRUSTED", "CONDITIONALLY_TRUSTED", "UNVERIFIED", "UNTRUSTED"]:
            src = ThreatIntelligenceSource(
                source_name=f"Feed-{tlevel}-{uuid.uuid4().hex[:6]}",
                source_type="OPEN_SOURCE",
                provider="Community",
                trust_level=tlevel,
            )
            self.db.add(src)
        self.db.commit()

    # ── 2. IOC Canonical Normalization & Validation ───────────────────────────
    def test_03_normalize_ip_address(self):
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("IP_ADDRESS", "  192.168.1.100  ")
        self.assertEqual(norm_type, "IP_ADDRESS")
        self.assertEqual(norm_val, "192.168.1.100")

        # IPv6
        norm_type_v6, norm_val_v6 = ThreatIndicatorService.normalize_indicator("IP", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(norm_type_v6, "IP_ADDRESS")
        self.assertEqual(norm_val_v6, "2001:db8:85a3::8a2e:370:7334")

    def test_04_normalize_ip_address_invalid_rejection(self):
        with self.assertRaises(ValueError):
            ThreatIndicatorService.normalize_indicator("IP_ADDRESS", "999.999.999.999")

    def test_05_normalize_domain(self):
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("DOMAIN", "  https://WWW.Malicious-Domain.COM/login  ")
        self.assertEqual(norm_type, "DOMAIN")
        self.assertEqual(norm_val, "malicious-domain.com")

    def test_06_normalize_domain_invalid_rejection(self):
        with self.assertRaises(ValueError):
            ThreatIndicatorService.normalize_indicator("DOMAIN", "invalid..domain!!!")

    def test_07_normalize_url(self):
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("URL", "HTTP://Evil.com:8080/Phish/Path/?q=1 ")
        self.assertEqual(norm_type, "URL")
        self.assertEqual(norm_val, "http://evil.com:8080/Phish/Path?q=1")

    def test_08_normalize_file_hash(self):
        # SHA-256
        h256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("FILE_HASH", h256)
        self.assertEqual(norm_type, "FILE_HASH")
        self.assertEqual(norm_val, h256.lower())

        # MD5
        md5 = "D41D8CD98F00B204E9800998ECF8427E"
        norm_type_md5, norm_val_md5 = ThreatIndicatorService.normalize_indicator("FILE_HASH", md5)
        self.assertEqual(norm_val_md5, md5.lower())

    def test_09_normalize_file_hash_invalid_rejection(self):
        with self.assertRaises(ValueError):
            ThreatIndicatorService.normalize_indicator("FILE_HASH", "not_a_valid_hex_string_12345")

    def test_10_normalize_email_address(self):
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("EMAIL_ADDRESS", " Phisher@ATTACKER.Org ")
        self.assertEqual(norm_type, "EMAIL_ADDRESS")
        self.assertEqual(norm_val, "phisher@attacker.org")

    def test_11_normalize_hostname(self):
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator("HOSTNAME", " C2-SERVER-NODE1 ")
        self.assertEqual(norm_type, "HOSTNAME")
        self.assertEqual(norm_val, "c2-server-node1")

    # ── 3. IOC Registration & Expiration ──────────────────────────────────────
    def test_12_register_indicator_and_hash(self):
        ind = ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="198.51.100.99",
            indicator_type="IP_ADDRESS",
            confidence_score=90.0,
            severity="HIGH",
        )
        self.db.commit()
        self.assertIsNotNone(ind.id)
        self.assertEqual(len(ind.indicator_hash), 64)
        self.assertEqual(ind.normalized_value, "198.51.100.99")

    def test_13_duplicate_indicator_updates_existing(self):
        ind1 = ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="203.0.113.50",
            indicator_type="IP_ADDRESS",
            confidence_score=70.0,
            severity="MEDIUM",
        )
        self.db.commit()
        orig_id = ind1.id

        ind2 = ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="  203.0.113.50  ",
            indicator_type="IP_ADDRESS",
            confidence_score=85.0,
            severity="HIGH",
        )
        self.db.commit()

        self.assertEqual(ind2.id, orig_id)
        self.assertEqual(ind2.confidence_score, 85.0)
        self.assertEqual(ind2.severity, "HIGH")

    def test_14_expired_indicator_status(self):
        past = datetime.now(timezone.utc) - timedelta(days=5)
        ind = ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="expired-phish.com",
            indicator_type="DOMAIN",
            expires_at=past,
        )
        self.db.commit()
        self.assertEqual(ind.status, "EXPIRED")
        self.assertFalse(ind.is_active)

    # ── 4. Deterministic Trust Scoring & Explainable Deductions ────────────────
    def test_15_artifact_trust_scoring_high_trust(self):
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-TEST-HEALTHY-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="cisa_bulletin.json",
            normalized_content={"indicators": ["1.1.1.1"]},
            content_hash="",
            integrity_status="VALID",
            confidence_score=100.0,
            trust_status="TRUSTED",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=60),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(self.db, art.id)
        self.db.commit()

        self.assertEqual(eval_res.final_trust_score, 100.0)
        self.assertEqual(eval_res.trust_status, "HIGH_TRUST")
        self.assertEqual(len(eval_res.deductions_json), 0)

    def test_16_artifact_trust_scoring_with_deductions(self):
        src_unverified = ThreatIntelligenceSource(
            source_name=f"Unverified-{uuid.uuid4().hex[:6]}",
            source_type="OPEN_SOURCE",
            provider="Scraper",
            trust_level="UNVERIFIED",
        )
        self.db.add(src_unverified)
        self.db.commit()

        now = datetime.now(timezone.utc)
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-STALE-{uuid.uuid4().hex[:6]}",
            source_id=src_unverified.id,
            artifact_type="IOC",
            raw_content_reference=None,  # Unknown origin (-15)
            normalized_content={},  # Incomplete context (-15)
            content_hash="hash",
            integrity_status="VALID",
            first_seen=now - timedelta(days=100),
            last_seen=now - timedelta(days=100),  # Stale (-20)
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        # Unverified source (-25) + Stale (-20) + Incomplete context (-15) + Unknown origin (-15) + Conflicting (-15) + No cross-val (-10) = -100 deduction
        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(
            self.db,
            art.id,
            conflicting_intelligence=True,
            missing_cross_validation=True,
        )
        self.db.commit()

        self.assertEqual(eval_res.final_trust_score, 0.0)
        self.assertEqual(eval_res.trust_status, "UNTRUSTED")
        deduction_reasons = [d["reason"] for d in eval_res.deductions_json]
        self.assertIn("UNVERIFIED_SOURCE", deduction_reasons)
        self.assertIn("STALE_INTELLIGENCE", deduction_reasons)
        self.assertIn("INCOMPLETE_CONTEXT", deduction_reasons)
        self.assertIn("UNKNOWN_ORIGIN", deduction_reasons)
        self.assertIn("CONFLICTING_INTELLIGENCE", deduction_reasons)
        self.assertIn("NO_CROSS_VALIDATION", deduction_reasons)

    def test_17_cryptographic_dominance_override(self):
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-CRYPTO-FAIL-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="MALWARE_REPORT",
            raw_content_reference="sample.json",
            normalized_content={"malware": "trojan"},
            content_hash="tampered_hash",
            integrity_status="VALID",
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        # Force cryptographic failure
        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(
            self.db,
            art.id,
            force_crypto_failure=True,
        )
        self.db.commit()

        self.assertEqual(eval_res.final_trust_score, 0.0)
        self.assertEqual(eval_res.trust_status, "UNTRUSTED")
        self.assertEqual(eval_res.integrity_score, 0.0)
        self.assertEqual(art.integrity_status, "TAMPERED")
        deduction_reasons = [d["reason"] for d in eval_res.deductions_json]
        self.assertIn("CRYPTOGRAPHIC_INTEGRITY_FAILURE", deduction_reasons)

    # ── 5. Adversary Context: Threat Actors & Campaigns ────────────────────────
    def test_18_create_threat_actor(self):
        actor = ThreatActorCampaignService.create_actor(
            db=self.db,
            actor_name=f"ACTOR-VIPER-{uuid.uuid4().hex[:6]}",
            aliases=["VIPER_SNAKE", "APT-999"],
            motivation="ESPIONAGE",
            sophistication="ADVANCED",
            origin_context="ASIA",
            confidence_score=90.0,
        )
        self.db.commit()
        self.assertIsNotNone(actor.id)
        self.assertEqual(actor.motivation, "ESPIONAGE")

    def test_19_create_campaign_and_hash(self):
        cmp = ThreatActorCampaignService.create_campaign(
            db=self.db,
            campaign_reference=f"CMP-TEST-{uuid.uuid4().hex[:6]}",
            campaign_name="Operation Test Campaign",
            description="Campaign test.",
            severity="HIGH",
            confidence_score=85.0,
        )
        self.db.commit()
        self.assertIsNotNone(cmp.id)
        self.assertEqual(len(cmp.campaign_hash), 64)

    def test_20_map_actor_to_campaign(self):
        actor = ThreatActorCampaignService.create_actor(db=self.db, actor_name=f"ACTOR-MAPPED-{uuid.uuid4().hex[:6]}")
        cmp = ThreatActorCampaignService.create_campaign(db=self.db, campaign_reference=f"CMP-MAPPED-{uuid.uuid4().hex[:6]}", campaign_name="Mapped Campaign")
        mapping = ThreatActorCampaignService.map_actor_to_campaign(self.db, actor.id, cmp.id, "ATTRIBUTED", 95.0)
        self.db.commit()

        self.assertEqual(mapping.actor_id, actor.id)
        self.assertEqual(mapping.campaign_id, cmp.id)
        self.assertEqual(mapping.relationship_type, "ATTRIBUTED")

    # ── 6. MITRE ATT&CK Mapping ───────────────────────────────────────────────
    def test_21_create_and_retrieve_mitre_mapping(self):
        cmp = self.db.query(ThreatCampaign).first()
        mapping = ThreatMitreMappingService.create_mapping(
            db=self.db,
            tactic_id="TA0001",
            technique_id="T1566",
            subtechnique_id="T1566.002",
            campaign_id=cmp.id,
            mapping_confidence=92.0,
        )
        self.db.commit()

        mappings = ThreatMitreMappingService.get_mappings_for_campaign(self.db, cmp.id)
        self.assertGreaterEqual(len(mappings), 1)
        self.assertEqual(mappings[0].tactic_id, "TA0001")
        self.assertEqual(mappings[0].technique_id, "T1566")

    # ── 7. IOC Observable Event Correlation Engine ────────────────────────────
    def test_22_exact_ioc_event_correlation(self):
        # Register a high trust IOC
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-CORR-EXACT-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            confidence_score=100.0,
            trust_status="HIGH_TRUST",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        test_ip = "198.51.100.222"
        ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value=test_ip,
            indicator_type="IP_ADDRESS",
            artifact_id=art.id,
            confidence_score=100.0,
            severity="CRITICAL",
        )
        self.db.commit()

        # Execute correlation
        corr = ThreatIntelligenceCorrelationService.correlate_observable(
            db=self.db,
            event_reference="EVT-2026-CORR-001",
            observable_value=test_ip,
            observable_type="IP_ADDRESS",
        )
        self.db.commit()

        self.assertIsNotNone(corr)
        self.assertEqual(corr.correlation_type, "EXACT_MATCH")
        self.assertEqual(corr.match_strength, 1.00)
        self.assertAlmostEqual(corr.correlation_confidence, 1.00, places=2)
        self.assertEqual(corr.status, "ENRICHED")
        self.assertEqual(len(corr.correlation_hash), 64)

    def test_23_partial_domain_correlation(self):
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-CORR-PARTIAL-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            confidence_score=90.0,
            trust_status="TRUSTED",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="badsite.org",
            indicator_type="DOMAIN",
            artifact_id=art.id,
        )
        self.db.commit()

        corr = ThreatIntelligenceCorrelationService.correlate_observable(
            db=self.db,
            event_reference="EVT-PARTIAL-001",
            observable_value="subdomain.badsite.org",
            observable_type="DOMAIN",
        )
        self.db.commit()

        self.assertIsNotNone(corr)
        self.assertEqual(corr.correlation_type, "PARTIAL_MATCH")
        self.assertEqual(corr.match_strength, 0.60)

    def test_24_untrusted_ioc_correlation_inconclusive(self):
        src_untrusted = ThreatIntelligenceSource(
            source_name=f"Untrusted-{uuid.uuid4().hex[:6]}",
            source_type="OPEN_SOURCE",
            provider="Unknown",
            trust_level="UNTRUSTED",
        )
        self.db.add(src_untrusted)
        self.db.commit()

        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-UNTRUSTED-{uuid.uuid4().hex[:6]}",
            source_id=src_untrusted.id,
            artifact_type="IOC",
            confidence_score=0.0,
            trust_status="UNTRUSTED",
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        ThreatIndicatorService.register_indicator(
            db=self.db,
            indicator_value="192.0.2.77",
            indicator_type="IP_ADDRESS",
            artifact_id=art.id,
        )
        self.db.commit()

        corr = ThreatIntelligenceCorrelationService.correlate_observable(
            db=self.db,
            event_reference="EVT-UNTRUSTED-001",
            observable_value="192.0.2.77",
            observable_type="IP_ADDRESS",
        )
        self.db.commit()

        self.assertIsNotNone(corr)
        self.assertEqual(corr.correlation_confidence, 0.0)
        self.assertEqual(corr.status, "INCONCLUSIVE")

    def test_25_no_match_returns_none(self):
        corr = ThreatIntelligenceCorrelationService.correlate_observable(
            db=self.db,
            event_reference="EVT-NO-MATCH",
            observable_value="8.8.8.8",
            observable_type="IP_ADDRESS",
        )
        self.assertIsNone(corr)

    # ── 8. 15-Stage Cryptographic Provenance Lineage ──────────────────────────
    def test_26_generate_15_stage_provenance_chain(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        records = ThreatIntelligenceProvenanceService.generate_provenance_chain(self.db, art.id)
        self.db.commit()

        self.assertEqual(len(records), 15)
        for idx, (order, name, _) in enumerate(PROVENANCE_15_STAGES):
            self.assertEqual(records[idx].stage_order, order)
            self.assertEqual(records[idx].provenance_stage, name)
            self.assertEqual(len(records[idx].current_hash), 64)
            if idx > 0:
                self.assertEqual(records[idx].previous_hash, records[idx - 1].current_hash)
            else:
                self.assertEqual(records[0].previous_hash, "0" * 64)

    # ── 9. Dashboard KPIs & Threat Landscape ───────────────────────────────────
    def test_27_dashboard_summary_and_landscape(self):
        summary = ThreatIntelligenceCorrelationService.get_dashboard_summary(self.db)
        self.assertIn("global_threat_intel_score", summary)
        self.assertIn("active_ioc_count", summary)
        self.assertIn("active_campaigns_count", summary)
        self.assertGreaterEqual(summary["active_ioc_count"], 1)

        landscape = ThreatIntelligenceCorrelationService.get_threat_landscape(self.db)
        self.assertIn("severity_distribution", landscape)
        self.assertIn("indicator_type_distribution", landscape)
        self.assertIn("active_campaigns", landscape)

    # ── 10. RBAC Authorization & Restrictions ─────────────────────────────────
    def test_28_rbac_admin_full_access(self):
        res = client.get("/api/v1/threat-intelligence/sources", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)

        res_post = client.post(
            "/api/v1/threat-intelligence/sources",
            headers=self.admin_headers,
            json={
                "source_name": f"Admin Source {uuid.uuid4().hex[:6]}",
                "source_type": "INTERNAL",
                "provider": "Admin",
                "trust_level": "TRUSTED",
            },
        )
        self.assertEqual(res_post.status_code, 201)

    def test_29_rbac_analyst_can_ingest_and_correlate(self):
        # Analyst has THREAT_INTELLIGENCE_INGEST and THREAT_CORRELATION_EXECUTE
        res = client.get("/api/v1/threat-intelligence/indicators", headers=self.analyst_headers)
        self.assertEqual(res.status_code, 200)

    def test_30_rbac_viewer_write_forbidden(self):
        # Viewer has THREAT_INTELLIGENCE_READ, but lacks THREAT_INTELLIGENCE_SOURCE_MANAGE
        res = client.post(
            "/api/v1/threat-intelligence/sources",
            headers=self.viewer_headers,
            json={
                "source_name": "Viewer Forbidden Source",
                "source_type": "INTERNAL",
                "provider": "Viewer",
            },
        )
        self.assertEqual(res.status_code, 403)

    # ── 11. REST API Endpoints ────────────────────────────────────────────────
    def test_31_api_get_sources(self):
        res = client.get("/api/v1/threat-intelligence/sources", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_32_api_get_single_source(self):
        src = self.db.query(ThreatIntelligenceSource).first()
        res = client.get(f"/api/v1/threat-intelligence/sources/{src.id}", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["id"], src.id)

    def test_33_api_patch_source(self):
        src = self.db.query(ThreatIntelligenceSource).first()
        res = client.patch(
            f"/api/v1/threat-intelligence/sources/{src.id}",
            headers=self.admin_headers,
            json={"description": "Updated description via API."},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["description"], "Updated description via API.")

    def test_34_api_create_and_get_artifact(self):
        src = self.db.query(ThreatIntelligenceSource).first()
        ref = f"TIA-API-{uuid.uuid4().hex[:6]}"
        res = client.post(
            "/api/v1/threat-intelligence/artifacts",
            headers=self.admin_headers,
            json={
                "artifact_reference": ref,
                "source_id": src.id,
                "artifact_type": "IOC",
                "raw_content_reference": "api_test.json",
                "normalized_content": {"status": "ok"},
                "confidence_score": 95.0,
            },
        )
        self.assertEqual(res.status_code, 201)
        art_id = res.json()["id"]

        get_res = client.get(f"/api/v1/threat-intelligence/artifacts/{art_id}", headers=self.admin_headers)
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["artifact_reference"], ref)

    def test_35_api_create_and_list_indicators(self):
        res = client.post(
            "/api/v1/threat-intelligence/indicators",
            headers=self.admin_headers,
            json={
                "indicator_value": "198.51.100.77",
                "indicator_type": "IP_ADDRESS",
                "confidence_score": 90.0,
                "severity": "HIGH",
            },
        )
        self.assertEqual(res.status_code, 201)

        list_res = client.get("/api/v1/threat-intelligence/indicators?indicator_type=IP_ADDRESS", headers=self.admin_headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(len(list_res.json()), 1)

    def test_36_api_evaluate_artifact_trust(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        res = client.post(
            f"/api/v1/threat-intelligence/artifacts/{art.id}/evaluate-trust?force_crypto_failure=false",
            headers=self.admin_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("final_trust_score", res.json())
        self.assertIn("trust_status", res.json())

    def test_37_api_get_artifact_trust_history(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        res = client.get(f"/api/v1/threat-intelligence/artifacts/{art.id}/trust", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_38_api_actors_crud(self):
        name = f"APT-API-{uuid.uuid4().hex[:6]}"
        res = client.post(
            "/api/v1/threat-intelligence/actors",
            headers=self.admin_headers,
            json={
                "actor_name": name,
                "aliases": ["SHADOW"],
                "motivation": "ESPIONAGE",
                "sophistication": "ADVANCED",
                "confidence_score": 90.0,
            },
        )
        self.assertEqual(res.status_code, 201)
        actor_id = res.json()["id"]

        get_res = client.get(f"/api/v1/threat-intelligence/actors/{actor_id}", headers=self.admin_headers)
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["actor_name"], name)

    def test_39_api_campaigns_crud(self):
        ref = f"CMP-API-{uuid.uuid4().hex[:6]}"
        res = client.post(
            "/api/v1/threat-intelligence/campaigns",
            headers=self.admin_headers,
            json={
                "campaign_reference": ref,
                "campaign_name": "API Campaign",
                "severity": "HIGH",
                "confidence_score": 88.0,
            },
        )
        self.assertEqual(res.status_code, 201)
        cmp_id = res.json()["id"]

        get_res = client.get(f"/api/v1/threat-intelligence/campaigns/{cmp_id}", headers=self.admin_headers)
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["campaign_reference"], ref)

    def test_40_api_mitre_mapping(self):
        cmp = self.db.query(ThreatCampaign).first()
        res = client.post(
            "/api/v1/threat-intelligence/mitre-mappings",
            headers=self.admin_headers,
            json={
                "tactic_id": "TA0002",
                "technique_id": "T1059",
                "subtechnique_id": "T1059.001",
                "campaign_id": cmp.id,
                "mapping_confidence": 95.0,
            },
        )
        self.assertEqual(res.status_code, 201)

        list_res = client.get(f"/api/v1/threat-intelligence/mitre-mappings?campaign_id={cmp.id}", headers=self.admin_headers)
        self.assertEqual(list_res.status_code, 200)

    def test_41_api_execute_correlation_and_list(self):
        # Correlate against seeded CISA indicator 198.51.100.42
        res = client.post(
            "/api/v1/threat-intelligence/correlations/execute",
            headers=self.admin_headers,
            json={
                "event_reference": "EVT-API-CORR-01",
                "observable_value": "198.51.100.42",
                "observable_type": "IP_ADDRESS",
            },
        )
        self.assertEqual(res.status_code, 200)
        corr_id = res.json()["id"]

        get_res = client.get(f"/api/v1/threat-intelligence/correlations/{corr_id}", headers=self.admin_headers)
        self.assertEqual(get_res.status_code, 200)

        list_res = client.get("/api/v1/threat-intelligence/correlations", headers=self.admin_headers)
        self.assertEqual(list_res.status_code, 200)

    def test_42_api_provenance_lineage(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        res = client.get(f"/api/v1/threat-intelligence/artifacts/{art.id}/provenance", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()), 15)

    def test_43_api_dashboard_kpis(self):
        res_sum = client.get("/api/v1/threat-intelligence/dashboard/summary", headers=self.admin_headers)
        self.assertEqual(res_sum.status_code, 200)
        self.assertIn("global_threat_intel_score", res_sum.json())

        res_land = client.get("/api/v1/threat-intelligence/dashboard/threat-landscape", headers=self.admin_headers)
        self.assertEqual(res_land.status_code, 200)
        self.assertIn("severity_distribution", res_land.json())

    # ── 12. Individual Deduction Rules & Edge Cases ───────────────────────────
    def test_44_deduction_unverified_source_25_points(self):
        src = ThreatIntelligenceSource(
            source_name=f"Src-Unverified-{uuid.uuid4().hex[:6]}",
            source_type="OPEN_SOURCE",
            provider="Scraper",
            trust_level="UNVERIFIED",
        )
        self.db.add(src)
        self.db.commit()

        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-DED-UNV-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="raw.json",
            normalized_content={"data": "test"},
            content_hash="hash",
            integrity_status="VALID",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(self.db, art.id)
        self.assertEqual(eval_res.final_trust_score, 75.0)
        self.assertEqual(eval_res.trust_status, "TRUSTED")

    def test_45_deduction_conditionally_trusted_source_10_points(self):
        src = ThreatIntelligenceSource(
            source_name=f"Src-Cond-{uuid.uuid4().hex[:6]}",
            source_type="COMMERCIAL",
            provider="Vendor B",
            trust_level="CONDITIONALLY_TRUSTED",
        )
        self.db.add(src)
        self.db.commit()

        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-DED-COND-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="raw.json",
            normalized_content={"data": "test"},
            content_hash="hash",
            integrity_status="VALID",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(self.db, art.id)
        self.assertEqual(eval_res.final_trust_score, 90.0)
        self.assertEqual(eval_res.trust_status, "HIGH_TRUST")

    def test_46_deduction_stale_intelligence_20_points(self):
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        now = datetime.now(timezone.utc)
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-DED-STALE-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="raw.json",
            normalized_content={"data": "test"},
            content_hash="hash",
            integrity_status="VALID",
            first_seen=now - timedelta(days=120),
            last_seen=now - timedelta(days=100),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(self.db, art.id)
        self.assertEqual(eval_res.final_trust_score, 80.0)

    def test_47_deduction_expired_indicator_30_points(self):
        src = self.db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.trust_level == "TRUSTED").first()
        now = datetime.now(timezone.utc)
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-DED-EXP-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="raw.json",
            normalized_content={"data": "test"},
            content_hash="hash",
            integrity_status="VALID",
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(days=1),
            expires_at=now - timedelta(days=1),
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(self.db, art.id)
        self.assertEqual(eval_res.final_trust_score, 70.0)
        self.assertEqual(eval_res.trust_status, "CONDITIONAL")

    def test_48_trust_classification_low_trust(self):
        src = ThreatIntelligenceSource(
            source_name=f"Src-Low-{uuid.uuid4().hex[:6]}",
            source_type="OPEN_SOURCE",
            provider="Scraper",
            trust_level="UNVERIFIED",
        )
        self.db.add(src)
        self.db.commit()

        now = datetime.now(timezone.utc)
        art = ThreatIntelligenceArtifact(
            artifact_reference=f"TIA-LOW-{uuid.uuid4().hex[:6]}",
            source_id=src.id,
            artifact_type="IOC",
            raw_content_reference="raw.json",
            normalized_content={"data": "test"},
            content_hash="hash",
            integrity_status="VALID",
            first_seen=now - timedelta(days=100),
            last_seen=now - timedelta(days=100),  # -20 stale
        )
        art.content_hash = art.compute_content_hash()
        self.db.add(art)
        self.db.commit()

        # Unverified (-25) + Stale (-20) + Conflicting (-15) = 40 (LOW_TRUST)
        eval_res = ThreatIntelligenceTrustService.evaluate_artifact_trust(
            self.db, art.id, conflicting_intelligence=True
        )
        self.assertEqual(eval_res.final_trust_score, 40.0)
        self.assertEqual(eval_res.trust_status, "LOW_TRUST")

    # ── 13. RBAC Granular Matrix Tests ────────────────────────────────────────
    def test_49_rbac_author_can_create_source_and_campaign(self):
        res = client.post(
            "/api/v1/threat-intelligence/sources",
            headers=self.author_headers,
            json={
                "source_name": f"Author Feed {uuid.uuid4().hex[:6]}",
                "source_type": "INTERNAL",
                "provider": "Policy Team",
                "trust_level": "TRUSTED",
            },
        )
        self.assertEqual(res.status_code, 201)

        res_cmp = client.post(
            "/api/v1/threat-intelligence/campaigns",
            headers=self.author_headers,
            json={
                "campaign_reference": f"CMP-AUTH-{uuid.uuid4().hex[:6]}",
                "campaign_name": "Author Campaign",
            },
        )
        self.assertEqual(res_cmp.status_code, 201)

    def test_50_rbac_author_cannot_execute_correlation(self):
        # Author lacks THREAT_CORRELATION_EXECUTE
        res = client.post(
            "/api/v1/threat-intelligence/correlations/execute",
            headers=self.author_headers,
            json={
                "event_reference": "EVT-AUTH-DENIED",
                "observable_value": "198.51.100.42",
            },
        )
        self.assertEqual(res.status_code, 403)

    def test_51_rbac_reviewer_can_evaluate_trust(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        res = client.post(
            f"/api/v1/threat-intelligence/artifacts/{art.id}/evaluate-trust",
            headers=self.reviewer_headers,
        )
        self.assertEqual(res.status_code, 200)

    def test_52_rbac_reviewer_cannot_manage_sources(self):
        res = client.post(
            "/api/v1/threat-intelligence/sources",
            headers=self.reviewer_headers,
            json={
                "source_name": "Reviewer Forbidden",
                "source_type": "INTERNAL",
                "provider": "Rev",
            },
        )
        self.assertEqual(res.status_code, 403)

    def test_53_rbac_auditor_can_read_and_audit(self):
        res = client.get("/api/v1/threat-intelligence/sources", headers=self.auditor_headers)
        self.assertEqual(res.status_code, 200)
        res_corr = client.get("/api/v1/threat-intelligence/correlations", headers=self.auditor_headers)
        self.assertEqual(res_corr.status_code, 200)

    def test_54_rbac_auditor_cannot_create_indicators(self):
        res = client.post(
            "/api/v1/threat-intelligence/indicators",
            headers=self.auditor_headers,
            json={
                "indicator_value": "1.2.3.4",
                "indicator_type": "IP_ADDRESS",
            },
        )
        self.assertEqual(res.status_code, 403)

    # ── 14. Domain Prefixes & Canonical Hashing Invariants ───────────────────
    def test_55_artifact_domain_prefix(self):
        self.assertEqual(ARTIFACT_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_INTELLIGENCE_ARTIFACT_V1")

    def test_56_indicator_domain_prefix(self):
        self.assertEqual(INDICATOR_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_INDICATOR_V1")

    def test_57_campaign_domain_prefix(self):
        self.assertEqual(CAMPAIGN_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_CAMPAIGN_V1")

    def test_58_trust_evaluation_domain_prefix(self):
        self.assertEqual(TRUST_EVALUATION_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_TRUST_EVALUATION_V1")

    def test_59_correlation_domain_prefix(self):
        self.assertEqual(CORRELATION_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_CORRELATION_V1")

    def test_60_provenance_domain_prefix(self):
        self.assertEqual(PROVENANCE_DOMAIN_PREFIX, "SENTINELTRACE_THREAT_PROVENANCE_V1")

    # ── 15. API Error Handling & Conflicts ────────────────────────────────────
    def test_61_api_duplicate_source_conflict_409(self):
        src = self.db.query(ThreatIntelligenceSource).first()
        res = client.post(
            "/api/v1/threat-intelligence/sources",
            headers=self.admin_headers,
            json={
                "source_name": src.source_name,
                "source_type": "INTERNAL",
                "provider": "Duplicate",
            },
        )
        self.assertEqual(res.status_code, 409)

    def test_62_api_duplicate_artifact_conflict_409(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        res = client.post(
            "/api/v1/threat-intelligence/artifacts",
            headers=self.admin_headers,
            json={
                "artifact_reference": art.artifact_reference,
                "source_id": art.source_id,
                "artifact_type": "IOC",
            },
        )
        self.assertEqual(res.status_code, 409)

    def test_63_api_invalid_indicator_bad_request_400(self):
        res = client.post(
            "/api/v1/threat-intelligence/indicators",
            headers=self.admin_headers,
            json={
                "indicator_value": "not-an-ip",
                "indicator_type": "IP_ADDRESS",
            },
        )
        self.assertEqual(res.status_code, 400)

    def test_64_api_not_found_endpoints_404(self):
        res1 = client.get("/api/v1/threat-intelligence/sources/nonexistent", headers=self.admin_headers)
        self.assertEqual(res1.status_code, 404)
        res2 = client.get("/api/v1/threat-intelligence/artifacts/nonexistent", headers=self.admin_headers)
        self.assertEqual(res2.status_code, 404)
        res3 = client.get("/api/v1/threat-intelligence/indicators/nonexistent", headers=self.admin_headers)
        self.assertEqual(res3.status_code, 404)

    def test_65_api_patch_indicator(self):
        ind = self.db.query(ThreatIndicator).first()
        res = client.patch(
            f"/api/v1/threat-intelligence/indicators/{ind.id}",
            headers=self.admin_headers,
            json={"severity": "CRITICAL", "confidence_score": 99.0},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["severity"], "CRITICAL")
        self.assertEqual(res.json()["confidence_score"], 99.0)

    def test_66_api_actor_campaign_mapping_endpoint(self):
        actor = self.db.query(ThreatActor).first()
        cmp = self.db.query(ThreatCampaign).first()
        res = client.post(
            "/api/v1/threat-intelligence/actor-campaign-mappings",
            headers=self.admin_headers,
            json={
                "actor_id": actor.id,
                "campaign_id": cmp.id,
                "relationship_type": "ATTRIBUTED",
                "confidence_score": 91.0,
            },
        )
        self.assertEqual(res.status_code, 201)

    def test_67_zero_trust_axiom_ioc_match_does_not_create_incident(self):
        # Ensure that executing correlation records correlation but does NOT insert any incident automatically
        from app.models.security_incident import SecurityIncident
        inc_count_before = self.db.query(SecurityIncident).count()

        ThreatIntelligenceCorrelationService.correlate_observable(
            db=self.db,
            event_reference="EVT-ZT-TEST",
            observable_value="198.51.100.42",
            observable_type="IP_ADDRESS",
        )
        self.db.commit()

        inc_count_after = self.db.query(SecurityIncident).count()
        self.assertEqual(inc_count_before, inc_count_after)

    def test_68_missing_provenance_auto_generates_15_stages(self):
        art = self.db.query(ThreatIntelligenceArtifact).first()
        # Delete records
        self.db.query(ThreatProvenanceRecord).filter(ThreatProvenanceRecord.artifact_id == art.id).delete()
        self.db.commit()

        records = ThreatIntelligenceProvenanceService.get_provenance_chain(self.db, art.id)
        self.assertEqual(len(records), 15)


if __name__ == "__main__":
    unittest.main()

