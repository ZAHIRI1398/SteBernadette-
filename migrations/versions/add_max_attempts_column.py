"""add max_attempts column

Revision ID: add_max_attempts_column
Create Date: 2025-03-24 18:22:24.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_max_attempts_column'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Ajouter la colonne max_attempts avec une valeur par défaut de 3
    op.add_column('exercise', sa.Column('max_attempts', sa.Integer(), nullable=True, server_default='3'))


def downgrade():
    # Supprimer la colonne max_attempts
    op.drop_column('exercise', 'max_attempts')
