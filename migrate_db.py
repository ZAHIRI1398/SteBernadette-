from app import app, db
from models import Exercise, User, Class, Course, ExerciseAttempt, CourseFile
from flask_migrate import Migrate, upgrade
import sqlite3
import os

migrate = Migrate(app, db)

def create_tables():
    """Crée les tables de la base de données"""
    with app.app_context():
        # S'assurer que le dossier instance existe
        if not os.path.exists('instance'):
            os.makedirs('instance')
            print("Dossier instance créé")
        
        # Créer toutes les tables
        db.create_all()
        print("Tables créées avec succès")

def add_column_if_not_exists(table_name, column_name, column_type):
    """Ajoute une colonne si elle n'existe pas déjà"""
    try:
        db_path = os.path.join('instance', 'classenumerique.db')
        with sqlite3.connect(db_path) as conn:
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

def check_table_exists(table_name):
    """Vérifie si une table existe"""
    try:
        db_path = os.path.join('instance', 'classenumerique.db')
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            return cursor.fetchone() is not None
    except Exception as e:
        print(f"Erreur lors de la vérification de la table: {e}")
        return False

if __name__ == '__main__':
    with app.app_context():
        try:
            # Vérifier si la table exercise existe
            if not check_table_exists('exercise'):
                print("La table exercise n'existe pas, création des tables...")
                create_tables()
            else:
                print("La table exercise existe déjà")
            
            # Ajouter la colonne max_attempts
            if add_column_if_not_exists('exercise', 'max_attempts', 'INTEGER DEFAULT 3'):
                print("Colonne max_attempts ajoutée avec succès")
            else:
                print("La colonne max_attempts existe déjà ou n'a pas pu être ajoutée")
            
            print("Migration terminée avec succès")
            
        except Exception as e:
            print(f"Erreur lors de la migration: {e}")
            raise
