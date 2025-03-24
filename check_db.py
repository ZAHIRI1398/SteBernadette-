import sqlite3
from pprint import pprint

def check_database_structure():
    """Vérifie la structure de la base de données"""
    try:
        with sqlite3.connect('instance/classenumerique.db') as conn:
            cursor = conn.cursor()
            
            # Obtenir la liste des tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            print("\nTables trouvées:")
            print("-" * 50)
            
            # Pour chaque table, afficher sa structure
            for table in tables:
                table_name = table[0]
                print(f"\nStructure de la table '{table_name}':")
                print("-" * 50)
                
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                for col in columns:
                    print(f"Colonne: {col[1]}")
                    print(f"Type: {col[2]}")
                    print(f"Nullable: {not col[3]}")
                    print(f"Default: {col[4]}")
                    print("-" * 30)
                    
    except Exception as e:
        print(f"Erreur lors de la vérification de la base de données: {e}")

if __name__ == '__main__':
    check_database_structure()
