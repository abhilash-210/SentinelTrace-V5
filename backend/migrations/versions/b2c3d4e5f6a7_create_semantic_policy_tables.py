"""create_semantic_policy_tables

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-06 18:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Semantic Policies Table
    op.create_table(
        'semantic_policies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('policy_id', sa.String(length=64), nullable=False),
        sa.Column('policy_name', sa.String(length=255), nullable=False),
        sa.Column('vendor_name', sa.String(length=255), nullable=False),
        sa.Column('source_profile_id', sa.String(length=64), nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='DRAFT', nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('supersedes_policy_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_semantic_policies_policy_id', 'semantic_policies', ['policy_id'], unique=True, schema='sentinel')
    op.create_index('ix_semantic_policies_vendor_name', 'semantic_policies', ['vendor_name'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_policies_source_profile_id', 'semantic_policies', ['source_profile_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_policies_status', 'semantic_policies', ['status'], unique=False, schema='sentinel')

    # 2. Semantic Policy Rules Table
    op.create_table(
        'semantic_policy_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('policy_id', sa.String(length=64), nullable=False),
        sa.Column('source_field', sa.String(length=100), nullable=False),
        sa.Column('source_value', sa.String(length=255), nullable=False),
        sa.Column('canonical_field', sa.String(length=100), nullable=False),
        sa.Column('canonical_value', sa.String(length=255), nullable=False),
        sa.Column('equivalence_classification', sa.String(length=32), server_default='EQUIVALENT', nullable=False),
        sa.Column('risk_level', sa.String(length=32), server_default='LOW', nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['sentinel.semantic_policies.policy_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_semantic_policy_rules_rule_id', 'semantic_policy_rules', ['rule_id'], unique=True, schema='sentinel')
    op.create_index('ix_semantic_policy_rules_policy_id', 'semantic_policy_rules', ['policy_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_policy_rules_source_field', 'semantic_policy_rules', ['source_field'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_policy_rules_canonical_field', 'semantic_policy_rules', ['canonical_field'], unique=False, schema='sentinel')

    # 3. Protected Semantic Fields Table
    op.create_table(
        'protected_semantic_fields',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('field_name', sa.String(length=100), nullable=False),
        sa.Column('criticality', sa.String(length=32), server_default='HIGH', nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('is_protected', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_protected_semantic_fields_field_name', 'protected_semantic_fields', ['field_name'], unique=True, schema='sentinel')


def downgrade() -> None:
    op.drop_index('ix_protected_semantic_fields_field_name', table_name='protected_semantic_fields', schema='sentinel')
    op.drop_table('protected_semantic_fields', schema='sentinel')

    op.drop_index('ix_semantic_policy_rules_canonical_field', table_name='semantic_policy_rules', schema='sentinel')
    op.drop_index('ix_semantic_policy_rules_source_field', table_name='semantic_policy_rules', schema='sentinel')
    op.drop_index('ix_semantic_policy_rules_policy_id', table_name='semantic_policy_rules', schema='sentinel')
    op.drop_index('ix_semantic_policy_rules_rule_id', table_name='semantic_policy_rules', schema='sentinel')
    op.drop_table('semantic_policy_rules', schema='sentinel')

    op.drop_index('ix_semantic_policies_status', table_name='semantic_policies', schema='sentinel')
    op.drop_index('ix_semantic_policies_source_profile_id', table_name='semantic_policies', schema='sentinel')
    op.drop_index('ix_semantic_policies_vendor_name', table_name='semantic_policies', schema='sentinel')
    op.drop_index('ix_semantic_policies_policy_id', table_name='semantic_policies', schema='sentinel')
    op.drop_table('semantic_policies', schema='sentinel')
