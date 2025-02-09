from app import app
from models import db, User, Class, Course, Exercise, ExerciseAttempt
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import json

def init_db():
    with app.app_context():
        # Supprimer et recréer toutes les tables
        db.drop_all()
        db.create_all()
        
        # Créer un utilisateur administrateur
        admin = User(
            username='admin',
            email='admin@example.com',
            name='Administrateur',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Créer un professeur
        teacher = User(
            username='prof',
            email='prof@example.com',
            name='Professeur',
            role='teacher'
        )
        teacher.set_password('prof123')
        db.session.add(teacher)
        
        # Créer quelques étudiants
        students = []
        for i in range(1, 4):
            student = User(
                username=f'student{i}',
                email=f'student{i}@example.com',
                name=f'Étudiant {i}',
                role='student'
            )
            student.set_password(f'student{i}')
            students.append(student)
            db.session.add(student)
        
        # Sauvegarder pour obtenir les IDs
        db.session.commit()
        
        # Créer une classe
        class1 = Class(
            name='Classe de Mathématiques',
            description='Cours de mathématiques niveau seconde',
            teacher_id=teacher.id,
            access_code='ABC123'
        )
        db.session.add(class1)
        
        # Ajouter les étudiants à la classe
        for student in students:
            class1.students.append(student)
        
        # Sauvegarder pour obtenir l'ID de la classe
        db.session.commit()
        
        # Créer un cours
        course1 = Course(
            title='Algèbre',
            description='Introduction à l\'algèbre',
            content='Introduction aux concepts de base de l\'algèbre',
            class_id=class1.id
        )
        db.session.add(course1)
        
        # Sauvegarder pour obtenir l'ID du cours
        db.session.commit()
        
        # Créer quelques exercices
        exercises = []
        for i in range(1, 4):
            exercise = Exercise(
                title=f'Exercice {i}',
                description=f'Description de l\'exercice {i}',
                exercise_type='qcm',
                content=json.dumps({
                    'questions': [f'Question {i}'],
                    'options': [['A', 'B', 'C', 'D']],
                    'correct_answers': [0]
                }),
                teacher_id=teacher.id,
                course_id=course1.id
            )
            exercises.append(exercise)
            db.session.add(exercise)
        
        # Sauvegarder pour obtenir les IDs des exercices
        db.session.commit()
        
        # Créer quelques tentatives d'exercices
        for student in students:
            for exercise in exercises:
                attempt = ExerciseAttempt(
                    student_id=student.id,
                    exercise_id=exercise.id,
                    course_id=course1.id,
                    score=75.0,
                    answers={'selected_answers': [0]}
                )
                db.session.add(attempt)
        
        # Sauvegarder tous les changements
        db.session.commit()
        
        print("Base de données initialisée avec succès !")

if __name__ == '__main__':
    init_db()
