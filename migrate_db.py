from app import app, db
from models import Exercise, User, Class, Course, ExerciseAttempt, CourseFile
import os
import sqlite3

def get_db_path():
    """Retourne le chemin absolu de la base de données"""
    instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
    db_path = os.path.join(instance_path, 'app.db')  # Utiliser app.db au lieu de classenumerique.db
    return instance_path, db_path

def initialize_database():
    """Initialise la base de données"""
    instance_path, db_path = get_db_path()
    
    print(f"Chemin de la base de données: {db_path}")
    
    # Créer le dossier instance s'il n'existe pas
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        print(f"Dossier créé: {instance_path}")
    
    with app.app_context():
        # Créer toutes les tables
        db.create_all()
        print("Tables créées avec succès")
        
        # Vérifier que la table exercise a été créée
        try:
            Exercise.query.first()
            print("Table exercise vérifiée avec succès")
        except Exception as e:
            print(f"Erreur lors de la vérification de la table exercise: {e}")
            raise

def add_max_attempts_column():
    """Ajoute la colonne max_attempts à la table exercise"""
    _, db_path = get_db_path()
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Vérifier si la colonne existe
            cursor.execute("PRAGMA table_info(exercise)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'max_attempts' not in columns:
                print("Ajout de la colonne max_attempts...")
                cursor.execute("ALTER TABLE exercise ADD COLUMN max_attempts INTEGER DEFAULT 3")
                conn.commit()
                print("Colonne max_attempts ajoutée avec succès")
            else:
                print("La colonne max_attempts existe déjà")
                
    except Exception as e:
        print(f"Erreur lors de l'ajout de la colonne: {e}")
        raise

def cleanup_unused_db():
    """Nettoie les bases de données inutilisées"""
    instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
    unused_db = os.path.join(instance_path, 'classenumerique.db')
    
    if os.path.exists(unused_db):
        try:
            os.remove(unused_db)
            print(f"Base de données inutilisée supprimée: {unused_db}")
        except Exception as e:
            print(f"Erreur lors de la suppression de la base inutilisée: {e}")

if __name__ == '__main__':
    try:
        print("Début de la migration...")
        cleanup_unused_db()  # Nettoyer d'abord les bases inutilisées
        initialize_database()
        add_max_attempts_column()
        print("Migration terminée avec succès")
    except Exception as e:
        print(f"Erreur fatale lors de la migration: {e}")
        raise
