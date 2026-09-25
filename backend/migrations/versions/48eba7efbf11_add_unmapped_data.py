"""add_unmapped_data

Revision ID: 48eba7efbf11
Revises: w3x4y5z6a7b9
Create Date: 2026-09-24 21:39:03.244665

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '48eba7efbf11'
down_revision: Union[str, None] = 'w3x4y5z6a7b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("normalized_events", sa.Column("unmapped_data", sa.JSON(), nullable=True), schema="sentinel")

def downgrade() -> None:
    op.drop_column("normalized_events", "unmapped_data", schema="sentinel")
