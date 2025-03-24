from app import app, db
from models import Exercise, User, Class, Course, ExerciseAttempt, CourseFile
from flask_migrate import Migrate, upgrade

migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        # Créer toutes les tables si elles n'existent pas
        db.create_all()
        
        # Ajouter la colonne max_attempts si elle n'existe pas
        from sqlalchemy import text
        try:
            db.session.execute(text('ALTER TABLE exercise ADD COLUMN max_attempts INTEGER DEFAULT 3'))
            db.session.commit()
        except Exception as e:
            print(f"Note: La colonne max_attempts existe peut-être déjà: {e}")
            db.session.rollback()
        
        print("Migration de la base de données terminée.")
