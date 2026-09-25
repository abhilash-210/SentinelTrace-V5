import pytest
import os
import shutil
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db
from app.routers.auth import get_current_user
from app.models.user import User
from app.models.normalized_event import NormalizedEvent
from app.models.quarantined_event import QuarantinedEvent
from app.services.parquet_export_service import EXPORT_DIR
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

class TestParquetExport:
    @classmethod
    def setup_class(cls):
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS sentinel"))
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        
        # Clean export directory if it exists
        if os.path.exists(EXPORT_DIR):
            shutil.rmtree(EXPORT_DIR)
            
        # Seed dummy data
        db = TestingSessionLocal()
        
        # 1 Valid Normalized Event
        n1 = NormalizedEvent(
            original_event_id="evt_valid_1",
            source_name="fw-1",
            source_type="firewall",
            normalization_status="NORMALIZED",
            class_name="Network Activity",
            activity_name="Traffic",
            parser_name="TestParser",
            action="ALLOW",
            unmapped_data={"vendor_flag": "x"},
            normalized_at=datetime.now(timezone.utc)
        )
        db.add(n1)
        
        # 1 Failed Normalized Event (should not be exported)
        n2 = NormalizedEvent(
            original_event_id="evt_failed_1",
            source_name="fw-1",
            source_type="firewall",
            normalization_status="FAILED",
            class_name="Network Activity",
            activity_name="Traffic",
            parser_name="TestParser",
            normalized_at=datetime.now(timezone.utc)
        )
        db.add(n2)
        
        # Quarantined Event (should not be exported)
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
        # Clean export directory
        if os.path.exists(EXPORT_DIR):
            shutil.rmtree(EXPORT_DIR)

    def test_01_export_parquet(self):
        response = client.post("/api/v1/export/parquet")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        # Only 1 NORMALIZED event should be exported
        assert data["exported_count"] == 1
        assert "export_path" in data
        assert os.path.exists(data["export_path"])
        
    def test_02_verify_exported_data(self):
        try:
            import pandas as pd
            import pyarrow as pa
            # Read the parquet dataset
            df = pd.read_parquet(EXPORT_DIR)
            assert len(df) == 1
            row = df.iloc[0]
            
            assert row["original_event_id"] == "evt_valid_1"
            assert row["source_name"] == "fw-1"
            assert row["class_name"] == "Network Activity"
            assert row["action"] == "ALLOW"
            
            import json
            unmapped = json.loads(row["unmapped_data"])
            assert unmapped["vendor_flag"] == "x"
        except ImportError:
            # Fallback to verify jsonl mock
            import jsonlines
            with jsonlines.open(os.path.join(EXPORT_DIR, 'mock_parquet_export.jsonl')) as reader:
                records = list(reader)
                
            assert len(records) == 1
            row = records[0]
            
            assert row["original_event_id"] == "evt_valid_1"
            assert row["source_name"] == "fw-1"
            assert row["class_name"] == "Network Activity"
            assert row["action"] == "ALLOW"
            
            import json
            unmapped = json.loads(row["unmapped_data"])
            assert unmapped["vendor_flag"] == "x"
