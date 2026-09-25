import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db
from app.routers.auth import get_current_user
from app.models.user import User
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.quarantined_event import QuarantinedEvent
from datetime import datetime, timezone

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_sentinel.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def override_get_current_user():
    return User(
        user_id="user_admin",
        username="admin",
        role="ADMIN",
        is_active=True
    )

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)

class TestDashboardStats:
    @classmethod
    def setup_class(cls):
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS sentinel"))
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        
        # Seed dummy data
        db = TestingSessionLocal()
        
        # Ingested Event
        e1 = IngestedEvent(
            event_id="evt_01",
            source_name="fw-1",
            source_type="firewall",
            file_format="syslog",
            raw_content="fake",
            raw_content_hash="hash",
            content_size=4,
            processing_status="PRESERVED",
            ingested_at=datetime.now(timezone.utc)
        )
        db.add(e1)
        
        # Normalized Event
        n1 = NormalizedEvent(
            original_event_id="evt_01",
            source_name="fw-1",
            source_type="firewall",
            normalization_status="NORMALIZED",
            class_name="Network Activity",
            activity_name="Traffic",
            parser_name="TestParser",
            normalized_at=datetime.now(timezone.utc)
        )
        db.add(n1)
        
        # Quarantined Event
        q1 = QuarantinedEvent(
            quarantine_id="qrn_01",
            source_name="fw-unknown",
            source_type="unknown",
            original_event_id="evt_02",
            raw_content="junk",
            failure_reason="schema error",
            status="QUARANTINED",
            quarantined_at=datetime.now(timezone.utc)
        )
        db.add(q1)
        
        db.commit()
        db.close()

    @classmethod
    def teardown_class(cls):
        Base.metadata.drop_all(bind=engine)

    def test_pipeline_stats(self):
        response = client.get("/api/v1/events/pipeline-stats")
        assert response.status_code == 200
        data = response.json()
        assert data["received"] == 1
        assert data["parsed"] == 2
        assert data["normalized"] == 1
        assert data["quarantined"] == 1
        assert data["replayed"] == 0
        assert "forwarded" in data
        assert len(data["recent_events"]) == 2
        
        statuses = [evt["status"] for evt in data["recent_events"]]
        assert "NORMALIZED" in statuses
        assert "QUARANTINED" in statuses
