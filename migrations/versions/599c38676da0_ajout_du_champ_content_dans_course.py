"""Ajout du champ content dans Course

Revision ID: 599c38676da0
Revises: 4a5d05177ada
Create Date: 2025-01-31 20:44:11.236516

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '599c38676da0'
down_revision = '4a5d05177ada'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('course', schema=None) as batch_op:
        batch_op.add_column(sa.Column('content', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(), nullable=True))
        batch_op.alter_column('title',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=200),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('course', schema=None) as batch_op:
        batch_op.alter_column('title',
               existing_type=sa.String(length=200),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
        batch_op.drop_column('updated_at')
        batch_op.drop_column('content')

    # ### end Alembic commands ###
