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
        ('word_search', 'Mots mêlés'),
        ('pairs', 'Association de paires'),
        ('fill_in_blanks', 'Texte à trous'),
        ('file', 'Dépôt de fichier')
    ]
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    exercise_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text)
    image_path = db.Column(db.String(200))
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    max_attempts = db.Column(db.Integer, default=3)  # Nombre maximum de tentatives autorisées
    
    # Relations
    course_exercises = db.relationship('Course', secondary=course_exercise, back_populates='exercises', lazy=True)
    attempts = db.relationship('ExerciseAttempt', backref='exercise', lazy=True)
    
    def __repr__(self):
        return f'<Exercise {self.title}>'
    
    def get_content(self):
        """Récupères le contenu de l'exercice sous forme de dictionnaire."""
        try:
            return json.loads(self.content) if self.content else {}
        except:
            return {}
    
    def set_content(self, content):
        """Enregistre le contenu de l'exercice"""
        self.content = json.dumps(content)
    
    def get_student_progress(self, student_id):
        """Récupère la progression d'un étudiant sur cet exercice"""
        attempts = ExerciseAttempt.query.filter_by(
            exercise_id=self.id,
            student_id=student_id
        ).order_by(ExerciseAttempt.created_at.desc()).all()
        
        if not attempts:
            return None
            
        return {
            'attempts_count': len(attempts),
            'remaining_attempts': self.max_attempts - len(attempts) if self.max_attempts else None,
            'best_score': max(attempt.score for attempt in attempts),
            'last_attempt': attempts[0]
        }
    
    def get_stats(self, course_id=None):
        """Récupère les statistiques globales de l'exercice."""
        # Filtrer les tentatives par cours si spécifié
        attempts = self.attempts
        if course_id:
            attempts = [a for a in attempts if a.course_id == course_id]
        
        if not attempts:
            return {
                'total_attempts': 0,
                'total_students': 0,
                'average_score': 0,
                'completion_rate': 0,
                'success_rate': 0
            }
        
        # Calculer les statistiques
        total_attempts = len(attempts)
        unique_students = len(set(attempt.student_id for attempt in attempts))
        scores = [attempt.score for attempt in attempts if attempt.score is not None]
        average_score = sum(scores) / len(scores) if scores else 0
        
        # Calculer le taux de complétion (pourcentage d'étudiants ayant fait au moins une tentative)
        students_query = User.query.filter_by(role='student')
        if course_id:
            course = Course.query.get(course_id)
            if course:
                students_query = course.class_obj.students
        total_students = students_query.count()
        completion_rate = (unique_students / total_students * 100) if total_students > 0 else 0
        
        # Calculer le taux de réussite (pourcentage de tentatives avec un score >= 70%)
        successful_attempts = len([score for score in scores if score >= 70])
        success_rate = (successful_attempts / len(scores) * 100) if scores else 0
        
        return {
            'total_attempts': total_attempts,
            'total_students': unique_students,
            'average_score': average_score,
            'completion_rate': completion_rate,
            'success_rate': success_rate
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
