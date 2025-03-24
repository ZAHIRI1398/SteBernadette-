from app import app, db
from flask_migrate import Migrate, upgrade

migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        # Créer toutes les tables
        db.create_all()
        
        # Appliquer les migrations
        try:
            upgrade()
        except Exception as e:
            print(f"Note: Erreur lors de la mise à jour de la base de données: {e}")
            print("Les tables ont été créées mais les migrations n'ont pas pu être appliquées.")
