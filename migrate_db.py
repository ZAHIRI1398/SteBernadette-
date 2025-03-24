from app import app, db
from models import Exercise, User, Class, Course, ExerciseAttempt, CourseFile
from flask_migrate import Migrate, upgrade
import sqlite3

migrate = Migrate(app, db)

def add_column_if_not_exists(table_name, column_name, column_type):
    """Ajoute une colonne si elle n'existe pas déjà"""
    try:
        with sqlite3.connect('instance/classenumerique.db') as conn:
            cursor = conn.cursor()
            # Vérifier si la colonne existe
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [col[1] for col in cursor.fetchall()]
            
            if column_name not in columns:
                print(f"Ajout de la colonne {column_name} à la table {table_name}")
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                conn.commit()
                return True
            return False
    except Exception as e:
        print(f"Erreur lors de l'ajout de la colonne: {e}")
        return False

if __name__ == '__main__':
    with app.app_context():
        try:
            # Créer toutes les tables si elles n'existent pas
            db.create_all()
            print("Tables créées/vérifiées avec succès")
            
            # Ajouter la colonne max_attempts si elle n'existe pas
            if add_column_if_not_exists('exercise', 'max_attempts', 'INTEGER DEFAULT 3'):
                print("Colonne max_attempts ajoutée avec succès")
            else:
                print("La colonne max_attempts existe déjà")
                
            print("Migration terminée avec succès")
            
        except Exception as e:
            print(f"Erreur lors de la migration: {e}")
            raise
