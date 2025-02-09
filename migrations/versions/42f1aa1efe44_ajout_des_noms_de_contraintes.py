"""Ajout des noms de contraintes

Revision ID: 42f1aa1efe44
Revises: 599c38676da0
Create Date: 2025-01-31 20:57:02.597963

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '42f1aa1efe44'
down_revision = '599c38676da0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('exercise', schema=None) as batch_op:
        batch_op.add_column(sa.Column('course_id', sa.Integer(), nullable=True))
        batch_op.alter_column('title',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=200),
               existing_nullable=False)
        batch_op.create_foreign_key('fk_exercise_course', 'course', ['course_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('exercise', schema=None) as batch_op:
        batch_op.drop_constraint('fk_exercise_course', type_='foreignkey')
        batch_op.alter_column('title',
               existing_type=sa.String(length=200),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
        batch_op.drop_column('course_id')

    # ### end Alembic commands ###
