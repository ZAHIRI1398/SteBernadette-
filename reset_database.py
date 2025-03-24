from app import app, db
from models import Exercise, User, Class, Course, ExerciseAttempt, CourseFile
import os

def reset_database():
    with app.app_context():
        # Supprimer la base de données existante
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"Base de données supprimée : {db_path}")
        
        # Créer toutes les tables
        db.create_all()
        print("Nouvelles tables créées")
        
        # Créer un utilisateur admin par défaut
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("Utilisateur admin créé")
        
        print("Réinitialisation de la base de données terminée")
