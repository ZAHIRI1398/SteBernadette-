from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()

# Table d'association pour les étudiants et les classes
student_class_association = db.Table('student_class',
    db.Column('student_id', db.Integer, db.ForeignKey('user.id', name='fk_student_class'), primary_key=True),
    db.Column('class_id', db.Integer, db.ForeignKey('class.id', name='fk_class_student'), primary_key=True)
)

# Table d'association entre Course et Exercise
course_exercise = db.Table('course_exercise',
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    db.Column('exercise_id', db.Integer, db.ForeignKey('exercise.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='student')  # 'admin', 'teacher', 'student'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    classes_enrolled = db.relationship('Class', secondary=student_class_association, back_populates='students')
    classes_teaching = db.relationship('Class', backref='teacher', lazy=True, foreign_keys='Class.teacher_id')
    exercises = db.relationship('Exercise', backref='teacher', lazy=True)
    exercise_attempts = db.relationship('ExerciseAttempt', backref='student', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_teacher(self):
        return self.role == 'teacher'
    
    @property
    def is_student(self):
        return self.role == 'student'
    
    @property
    def is_admin(self):
        return self.role == 'admin'

    def is_enrolled(self, class_id):
        """Check if the user is enrolled in a specific class."""
        return any(class_obj.id == class_id for class_obj in self.classes_enrolled)

    def get_average_score(self, course_id=None):
        """Obtenir la moyenne des scores pour tous les exercices ou pour un cours spécifique"""
        query = self.exercise_attempts
        if course_id:
            query = query.filter_by(course_id=course_id)
        scores = [attempt.score for attempt in query.all()]
        return sum(scores) / len(scores) if scores else 0
    
    def get_exercise_stats(self, exercise_id):
        """Obtenir les statistiques pour un exercice spécifique"""
        attempts = self.exercise_attempts.filter_by(exercise_id=exercise_id).all()
        if not attempts:
            return None
        scores = [attempt.score for attempt in attempts]
        return {
            'attempts_count': len(attempts),
            'best_score': max(scores),
            'average_score': sum(scores) / len(scores),
            'last_attempt': attempts[-1]
        }

class Class(db.Model):
    __tablename__ = 'class'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_class_teacher'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_code = db.Column(db.String(6), unique=True, nullable=False)
    
    # Relations
    students = db.relationship('User', secondary=student_class_association, back_populates='classes_enrolled')
    courses = db.relationship('Course', backref='class_obj', lazy=True)

class Course(db.Model):
    __tablename__ = 'course'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    course_files = db.relationship('CourseFile', backref='course', lazy=True, cascade='all, delete-orphan')
    exercises = db.relationship('Exercise', secondary=course_exercise, back_populates='course_exercises', lazy=True)
    
    def __repr__(self):
        return f'<Course {self.title}>'
    
    def get_student_stats(self, student_id):
        """Obtenir les statistiques d'un élève pour ce cours"""
        attempts = ExerciseAttempt.query.filter_by(
            course_id=self.id,
            student_id=student_id
        ).all()
        
        if not attempts:
            return {
                'exercises_attempted': 0,
                'exercises_completed': 0,
                'average_score': 0,
                'best_exercise': None,
                'needs_improvement': None
            }
        
        # Grouper les tentatives par exercice
        exercise_attempts = {}
        for attempt in attempts:
            if attempt.exercise_id not in exercise_attempts:
                exercise_attempts[attempt.exercise_id] = []
            exercise_attempts[attempt.exercise_id].append(attempt)
        
        # Calculer les meilleures notes pour chaque exercice
        best_scores = {}
        completed_exercises = 0
        for ex_id, ex_attempts in exercise_attempts.items():
            best_score = max((a.score for a in ex_attempts if a.score is not None), default=None)
            best_scores[ex_id] = best_score
            if best_score is not None and best_score >= 70:  # Considérer un exercice comme complété si score >= 70%
                completed_exercises += 1
        
        # Trouver le meilleur et le pire exercice
        best_exercise = max(best_scores.items(), key=lambda x: x[1])[0] if best_scores else None
        needs_improvement = min(best_scores.items(), key=lambda x: x[1])[0] if best_scores else None
        
        return {
            'exercises_attempted': len(exercise_attempts),
            'exercises_completed': completed_exercises,
            'average_score': sum(best_scores.values()) / len(best_scores) if best_scores else 0,
            'best_exercise': Exercise.query.get(best_exercise) if best_exercise else None,
            'needs_improvement': Exercise.query.get(needs_improvement) if needs_improvement else None
        }

class Exercise(db.Model):
    __tablename__ = 'exercise'
    
    EXERCISE_TYPES = [
        ('qcm', 'QCM'),
        ('drag_and_drop', 'Mots à placer'),
        ('pairs', 'Paires à associer'),
        ('file', 'Dépôt de fichier'),
        ('word_search', 'Mots mêlés')
    ]
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    exercise_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text)
    image_path = db.Column(db.String(200))
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    course_exercises = db.relationship('Course', secondary=course_exercise, back_populates='exercises', lazy=True)
    attempts = db.relationship('ExerciseAttempt', backref='exercise', lazy=True)
    
    def __repr__(self):
        return f'<Exercise {self.title}>'
    
    def get_content(self):
        """Récupère le contenu de l'exercice sous forme de dictionnaire."""
        try:
            print(f"\n[DEBUG] get_content pour exercice {self.id}")
            print(f"[DEBUG] Content brut: {self.content}")
            if not self.content:
                print("[DEBUG] Pas de contenu, retourne dict vide")
                return {}
            content = json.loads(self.content)
            print(f"[DEBUG] Content parsé: {content}")
            return content
        except json.JSONDecodeError as e:
            print(f"[ERROR] Erreur de décodage JSON: {str(e)}")
            return {}
    
    def set_content(self, content):
        """Enregistre le contenu de l'exercice"""
        if isinstance(content, dict):
            self.content = json.dumps(content)
        else:
            self.content = content

    def get_student_progress(self, student_id):
        """Récupère la progression d'un étudiant sur cet exercice"""
        from app import ExerciseAttempt
        
        # Récupérer toutes les tentatives de l'étudiant pour cet exercice
        attempts = ExerciseAttempt.query.filter_by(
            exercise_id=self.id,
            student_id=student_id
        ).order_by(ExerciseAttempt.created_at.desc()).all()
        
        if not attempts:
            return {
                'status': 'not_started',
                'attempts_count': 0,
                'best_score': None,
                'last_attempt': None,
                'needs_grading': False
            }
        
        # Calculer les statistiques
        best_score = max((a.score for a in attempts if a.score is not None), default=None)
        last_attempt = attempts[0]
        needs_grading = any(a.score is None for a in attempts)
        
        # Déterminer le statut
        if best_score is None and needs_grading:
            status = 'needs_grading'
        elif best_score == 100:
            status = 'completed'
        elif best_score is not None:
            status = 'in_progress'
        else:
            status = 'not_started'
        
        return {
            'status': status,
            'attempts_count': len(attempts),
            'best_score': best_score,
            'last_attempt': last_attempt,
            'needs_grading': needs_grading
        }
    
    def get_stats(self, course_id=None):
        """Obtenir les statistiques pour cet exercice"""
        query = ExerciseAttempt.query.filter_by(exercise_id=self.id)
        if course_id:
            query = query.filter_by(course_id=course_id)
        attempts = query.all()
        
        if not attempts:
            return {
                'total_attempts': 0,
                'total_students': 0,
                'average_score': 0,
                'completion_rate': 0,
                'success_rate': 0,
                'student_stats': []
            }
        
        # Calculer les statistiques globales
        total_students = len(set(a.student_id for a in attempts))
        average_score = sum(a.score for a in attempts) / len(attempts)
        
        # Calculer le taux de complétion (pourcentage d'élèves ayant tenté l'exercice)
        if course_id:
            course = Course.query.get(course_id)
            total_possible_students = len(course.class_obj.students)
        else:
            # Si pas de cours spécifié, on considère tous les élèves qui ont tenté l'exercice
            total_possible_students = total_students
        
        completion_rate = (total_students / total_possible_students * 100) if total_possible_students > 0 else 0
        
        # Calculer le taux de réussite (pourcentage de tentatives avec un score >= 70%)
        successful_attempts = sum(1 for a in attempts if a.score >= 70)
        success_rate = (successful_attempts / len(attempts) * 100)
        
        # Calculer les statistiques par élève
        student_stats = {}
        for attempt in attempts:
            if attempt.student_id not in student_stats:
                student_stats[attempt.student_id] = {
                    'student': attempt.student,
                    'attempts': 0,
                    'best_score': 0,
                    'last_score': 0,
                    'average_score': 0,
                    'total_score': 0
                }
            stats = student_stats[attempt.student_id]
            stats['attempts'] += 1
            stats['total_score'] += attempt.score
            stats['average_score'] = stats['total_score'] / stats['attempts']
            stats['best_score'] = max(stats['best_score'], attempt.score)
            stats['last_score'] = attempt.score  # Le dernier score sera le plus récent car les tentatives sont triées
        
        return {
            'total_attempts': len(attempts),
            'total_students': total_students,
            'average_score': average_score,
            'completion_rate': completion_rate,
            'success_rate': success_rate,
            'student_stats': list(student_stats.values())
        }

class ExerciseAttempt(db.Model):
    __tablename__ = 'exercise_attempt'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise_id = db.Column(db.Integer, db.ForeignKey('exercise.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    score = db.Column(db.Float)
    answers = db.Column(db.Text)  # Stocké en JSON
    feedback = db.Column(db.Text)  # Stocké en JSON
    completed = db.Column(db.Boolean, default=True)  # Par défaut True car une tentative est considérée comme complétée
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations avec les paramètres overlaps pour éviter les avertissements
    student_user = db.relationship('User', foreign_keys=[student_id], overlaps="exercise_attempts,student")
    exercise_ref = db.relationship('Exercise', overlaps="attempts,exercise", backref=db.backref('student_attempts', lazy=True, overlaps="exercise,attempts"))
    course_ref = db.relationship('Course', backref=db.backref('exercise_attempts', lazy=True))
    
    def get_feedback(self):
        """Récupères le feedback formaté de la tentative."""
        if not self.feedback:
            return None
            
        try:
            return json.loads(self.feedback)
        except json.JSONDecodeError:
            return {
                'error': 'Format de feedback invalide',
                'raw': self.feedback
            }

class CourseFile(db.Model):
    __tablename__ = 'course_file'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)  # Taille en bytes
    course_id = db.Column(db.Integer, db.ForeignKey('course.id', name='fk_file_course'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
