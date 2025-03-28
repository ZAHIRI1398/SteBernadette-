"""Add image_path to Exercise model

Revision ID: 4a5d05177ada
Revises: 
Create Date: 2025-01-31 17:04:01.496390

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4a5d05177ada'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('student_progress')
    with op.batch_alter_table('exercise', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image_path', sa.String(length=255), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('exercise', schema=None) as batch_op:
        batch_op.drop_column('image_path')

    op.create_table('student_progress',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('student_id', sa.INTEGER(), nullable=False),
    sa.Column('course_id', sa.INTEGER(), nullable=False),
    sa.Column('exercise_id', sa.INTEGER(), nullable=False),
    sa.Column('completed', sa.BOOLEAN(), nullable=True),
    sa.Column('score', sa.FLOAT(), nullable=True),
    sa.Column('last_attempt', sa.DATETIME(), nullable=True),
    sa.ForeignKeyConstraint(['course_id'], ['course.id'], ),
    sa.ForeignKeyConstraint(['exercise_id'], ['exercise.id'], ),
    sa.ForeignKeyConstraint(['student_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
