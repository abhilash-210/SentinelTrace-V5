"""create_identity_and_rbac_tables

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-06 21:45:00.000000

Sprint 4A — Identity & Role-Based Access Control (RBAC).
Creates sentinel.users table for verifiable user identities, secure password hashes,
and role-based governance attribution.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create sentinel.users table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False, comment="Surrogate integer primary key"),
        sa.Column("user_id", sa.String(length=64), nullable=False, comment="Unique public user identifier"),
        sa.Column("username", sa.String(length=64), nullable=False, comment="Unique login username"),
        sa.Column("email", sa.String(length=255), nullable=False, comment="Unique user email address"),
        sa.Column("full_name", sa.String(length=255), nullable=False, comment="Display name of the user"),
        sa.Column("password_hash", sa.String(length=255), nullable=False, comment="Bcrypt-hashed password"),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="VIEWER", comment="RBAC role"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true"), comment="Account active state"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), comment="UTC account creation timestamp"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), comment="UTC last account update timestamp"),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True, comment="UTC timestamp of most recent login"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
        schema="sentinel",
    )
    op.create_index("ix_users_user_id", "users", ["user_id"], unique=True, schema="sentinel")
    op.create_index("ix_users_username", "users", ["username"], unique=True, schema="sentinel")
    op.create_index("ix_users_email", "users", ["email"], unique=True, schema="sentinel")
    op.create_index("ix_users_role", "users", ["role"], unique=False, schema="sentinel")
    op.create_index("ix_users_is_active", "users", ["is_active"], unique=False, schema="sentinel")


def downgrade() -> None:
    op.drop_index("ix_users_is_active", table_name="users", schema="sentinel")
    op.drop_index("ix_users_role", table_name="users", schema="sentinel")
    op.drop_index("ix_users_email", table_name="users", schema="sentinel")
    op.drop_index("ix_users_username", table_name="users", schema="sentinel")
    op.drop_index("ix_users_user_id", table_name="users", schema="sentinel")
    op.drop_table("users", schema="sentinel")
