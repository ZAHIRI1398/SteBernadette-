from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import time
from functools import wraps
from models import db, User, Class, Course, Exercise, ExerciseAttempt, CourseFile, course_exercise
import json
import random
import string
import logging
import unicodedata
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, MultipleFileField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_clé_secrète_ici'  # À changer en production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# S'assurer que le dossier d'upload existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configuration de l'extension pour les fichiers
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialisation des extensions
db.init_app(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Décorateurs
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.role == 'teacher':
            flash('Accès réservé aux enseignants.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def sanitize_filename(filename):
    # Supprimer les accents
    filename = ''.join(c for c in unicodedata.normalize('NFD', filename)
                      if unicodedata.category(c) != 'Mn')
    # Remplacer les espaces par des underscores
    filename = filename.replace(' ', '_')
    # Garder uniquement les caractères alphanumériques et quelques caractères spéciaux
    filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
    return filename

def generate_unique_filename(original_filename):
    # Séparer le nom de fichier et l'extension
    name, ext = os.path.splitext(original_filename)
    # Générer un timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # Générer une chaîne aléatoire
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    # Combiner le tout
    return f"{name}_{timestamp}_{random_string}{ext}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.after_request
def add_csrf_token(response):
    if 'csrf_token' not in request.cookies:
        response.set_cookie('csrf_token', generate_csrf())
    return response

@app.route('/')
@login_required
def index():
    if current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        return redirect(url_for('view_student_classes'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email ou mot de passe incorrect.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

@app.route('/register/teacher', methods=['GET', 'POST'])
def register_teacher():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'error')
            return redirect(url_for('register_teacher'))
        
        # Générer un username à partir de l'email
        username = email.split('@')[0]
        
        user = User(
            username=username,
            name=name,
            email=email,
            role='teacher'
        )
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Erreur lors de l\'inscription.', 'error')
            print(f"Erreur d'inscription : {str(e)}")
    
    return render_template('register_teacher.html')

@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        app.logger.info("Données du formulaire reçues : %s", request.form)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        app.logger.info("Valeurs extraites - username: %s, email: %s", username, email)
        
        # Vérifier que tous les champs sont remplis
        if not all([username, email, password, confirm_password]):
            missing_fields = []
            if not username: missing_fields.append('nom d\'utilisateur')
            if not email: missing_fields.append('email')
            if not password: missing_fields.append('mot de passe')
            if not confirm_password: missing_fields.append('confirmation du mot de passe')
            
            flash(f'Les champs suivants sont obligatoires : {", ".join(missing_fields)}.', 'error')
            return redirect(url_for('register_student'))
            
        # Vérifier que les mots de passe correspondent
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return redirect(url_for('register_student'))
        
        # Vérifier si l'email est déjà utilisé
        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'error')
            return redirect(url_for('register_student'))
            
        # Vérifier si le nom d'utilisateur est déjà utilisé
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur est déjà utilisé.', 'error')
            return redirect(url_for('register_student'))
        
        try:
            user = User(
                username=username,
                name=username,  # Utiliser le username comme nom par défaut
                email=email,
                role='student'
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            app.logger.info("Nouvel utilisateur créé avec succès - username: %s, email: %s", username, email)
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error("Erreur lors de la création de l'utilisateur : %s", str(e))
            flash('Erreur lors de l\'inscription.', 'error')
            return redirect(url_for('register_student'))
    
    return render_template('register_student.html')

@app.route('/setup-admin')
def setup_admin():
    # Vérifier si un utilisateur existe déjà
    if User.query.first() is not None:
        flash('Un utilisateur existe déjà', 'warning')
        return redirect(url_for('login'))
    
    # Créer un compte administrateur par défaut
    admin = User(
        username='admin',
        name='Admin',
        email='admin@example.com',
        role='admin'
    )
    admin.set_password('admin')
    
    try:
        db.session.add(admin)
        db.session.commit()
        flash('Compte administrateur créé avec succès. Email: admin@example.com, Mot de passe: admin', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Erreur lors de la création du compte administrateur', 'error')
    
    return redirect(url_for('login'))

@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if not current_user.role == 'teacher':
        flash('Accès non autorisé.', 'error')
        return redirect(url_for('index'))
    
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher_dashboard.html', classes=classes)

@app.route('/class/<int:class_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    # Vérifier que l'utilisateur est le professeur de la classe
    if class_obj.teacher_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à supprimer cette classe.', 'error')
        return redirect(url_for('index'))
    
    try:
        db.session.delete(class_obj)
        db.session.commit()
        flash('Classe supprimée avec succès !', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Erreur lors de la suppression de la classe.', 'error')
        print(f"Erreur : {str(e)}")
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/course/<int:course_id>/delete', methods=['POST'])
@login_required
def delete_course(course_id):
    if not current_user.role == 'teacher':
        flash('Seuls les enseignants peuvent supprimer des cours.', 'error')
        return redirect(url_for('index'))
    
    course = Course.query.get_or_404(course_id)
    class_obj = Class.query.get_or_404(course.class_id)
    
    # Vérifier que l'enseignant est bien le propriétaire de la classe
    if class_obj.teacher_id != current_user.id:
        flash('Vous n\'avez pas la permission de supprimer ce cours.', 'error')
        return redirect(url_for('view_class', class_id=class_obj.id))
    
    try:
        # Supprimer les fichiers physiques
        for course_file in course.course_files:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], course_file.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                app.logger.error(f"Erreur lors de la suppression du fichier {course_file.filename}: {str(e)}")
        
        # Supprimer le cours (les fichiers et exercices seront supprimés automatiquement grâce à cascade)
        db.session.delete(course)
        db.session.commit()
        flash('Le cours a été supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Une erreur est survenue lors de la suppression du cours.', 'error')
        app.logger.error(f"Erreur lors de la suppression du cours {course_id}: {str(e)}")
    
    return redirect(url_for('view_class', class_id=class_obj.id))

@app.route('/teacher/class/<int:class_id>/remove-student/<int:student_id>', methods=['POST'])
@login_required
def remove_student(class_id, student_id):
    if not current_user.role == 'teacher':
        flash('Accès non autorisé.', 'error')
        return redirect(url_for('index'))
    
    class_obj = Class.query.filter_by(id=class_id, teacher_id=current_user.id).first_or_404()
    student = User.query.filter_by(id=student_id, is_teacher=False).first_or_404()
    
    if student in class_obj.students:
        try:
            class_obj.students.remove(student)
            db.session.commit()
            flash('Élève retiré avec succès !', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Erreur lors du retrait de l\'élève.', 'error')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/exercise-library')
@login_required
@teacher_required
def exercise_library():
    # Créer un formulaire vide juste pour le jeton CSRF
    class EmptyForm(FlaskForm):
        pass
    
    form = EmptyForm()
    exercises = Exercise.query.all()
    return render_template('exercise_library.html', 
                         exercises=exercises,
                         form=form)

@app.route('/exercise/<int:exercise_id>')
@login_required
def view_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    print(f"Exercise content: {exercise.content}")
    print(f"Exercise type: {exercise.exercise_type}")
    
    last_attempt = None
    last_attempts = None
    if current_user.is_authenticated:
        if exercise.exercise_type == 'file':
            # Pour les exercices de type fichier, récupérer toutes les tentatives
            last_attempts = ExerciseAttempt.query.filter_by(
                student_id=current_user.id,
                exercise_id=exercise_id
            ).order_by(ExerciseAttempt.created_at.desc()).all()
        else:
            # Pour les autres types, récupérer seulement la dernière tentative
            last_attempt = ExerciseAttempt.query.filter_by(
                student_id=current_user.id,
                exercise_id=exercise_id
            ).order_by(ExerciseAttempt.created_at.desc()).first()
    
    # Vérifier que l'utilisateur a accès à cet exercice
    if not current_user.is_teacher:
        course = Course.query.join(course_exercise).filter(course_exercise.c.exercise_id == exercise_id).first()
        if not course or not current_user.is_enrolled(course.class_id):
            flash("Vous n'avez pas accès à cet exercice.", 'error')
            return redirect(url_for('student_classes'))
    
    # Récupérer la dernière tentative de l'étudiant pour cet exercice
    last_attempt = None
    if not current_user.is_teacher:
        last_attempt = ExerciseAttempt.query.filter_by(
            student_id=current_user.id,
            exercise_id=exercise_id
        ).order_by(ExerciseAttempt.created_at.desc()).first()
    
    # Choisir le template en fonction du type d'exercice
    if exercise.exercise_type == 'qcm':
        return render_template('view_qcm_exercise.html', exercise=exercise, last_attempt=last_attempt)
    elif exercise.exercise_type == 'text':
        return render_template('view_text_exercise.html', exercise=exercise, last_attempt=last_attempt)
    elif exercise.exercise_type == 'file':
        return render_template('view_file_exercise.html', exercise=exercise, last_attempt=last_attempt)
    elif exercise.exercise_type == 'drag_and_drop':
        return render_template('view_drag_and_drop_exercise.html', exercise=exercise, last_attempt=last_attempt)
    elif exercise.exercise_type == 'word_search':
        return render_template('view_word_search_exercise.html', exercise=exercise, last_attempt=last_attempt)
    elif exercise.exercise_type == 'pairs':
        exercise_content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
        return render_template('view_pairs_exercise.html', exercise=exercise, exercise_content=exercise_content, last_attempt=last_attempt)
    else:
        flash('Type d\'exercice non supporté.', 'error')
        return redirect(url_for('index'))

@app.route('/exercise/<int:exercise_id>/submit', methods=['POST'])
@login_required
def submit_answer(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    
    # Récupérer le cours associé à l'exercice
    course = Course.query.join(course_exercise).filter(
        course_exercise.c.exercise_id == exercise_id
    ).first()
    
    if not course:
        flash("Cet exercice n'est associé à aucun cours.", 'error')
        return redirect(url_for('exercise_library'))
    
    if exercise.exercise_type == 'pairs':
        try:
            # Récupérer les paires soumises
            pairs_json = request.form.get('pairs')
            if not pairs_json:
                flash('Veuillez associer des éléments avant de soumettre.', 'error')
                return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
            pairs = json.loads(pairs_json)
            app.logger.info('Paires reçues: %s', pairs)
            
            # Récupérer le contenu de l'exercice
            exercise_content = exercise.get_content()
            
            # Calculer le score
            score = 0
            feedback = []
            
            # Vérifier chaque paire
            for pair in pairs:
                left_index = pair.get('left')
                right_index = pair.get('right')
                
                if left_index == right_index:  # Les indices correspondent = bonne réponse
                    score += 1
                    feedback.append({
                        'left': exercise_content['items_left'][left_index],
                        'right': exercise_content['items_right'][right_index],
                        'is_correct': True
                    })
                else:
                    feedback.append({
                        'left': exercise_content['items_left'][left_index],
                        'right': exercise_content['items_right'][right_index],
                        'is_correct': False,
                        'correct_right': exercise_content['items_right'][left_index]
                    })
            
            # Calculer le pourcentage
            total_pairs = len(exercise_content['items_left'])
            score_percentage = (score / total_pairs) * 100 if total_pairs > 0 else 0
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                score=score_percentage,
                course_id=course.id,
                answers=pairs_json,
                feedback=json.dumps({
                    'pairs': feedback,
                    'score': score,
                    'total': total_pairs
                })
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score_percentage:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except Exception as e:
            app.logger.error('Erreur lors de la soumission : %s', str(e))
            flash('Une erreur est survenue lors de la soumission.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
    
    elif exercise.exercise_type == 'word_search':
        try:
            # Récupérer les réponses de l'utilisateur
            user_answers = request.form.get('answers', '').strip().split('\n')
            user_answers = [word.strip().lower() for word in user_answers if word.strip()]
            
            # Récupérer le contenu de l'exercice
            content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
            words = [word.lower() for word in content.get('words', [])]
            
            # Calculer le score
            correct_words = [word for word in user_answers if word in words]
            score = (len(correct_words) / len(words)) * 100 if words else 0
            
            # Générer le feedback
            feedback = {
                'found_words': correct_words,
                'total_words': len(words),
                'correct_count': len(correct_words),
                'missing_words': [word for word in words if word not in correct_words]
            }
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                score=score,
                course_id=course.id,
                answers=json.dumps(user_answers),
                feedback=json.dumps(feedback)
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except Exception as e:
            print(f"Erreur lors de la soumission : {str(e)}")  # Pour le débogage
            flash('Une erreur est survenue lors de la soumission.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
    elif exercise.exercise_type == 'qcm':
        try:
            # Récupérer les réponses de l'utilisateur
            user_answers = json.loads(request.form.get('answers', '[]'))
            
            # Récupérer les réponses correctes
            content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
            correct_answers = content.get('correct_answers', [])
            
            # Vérifier que nous avons le bon nombre de réponses
            total_questions = len(content.get('questions', []))
            if len(user_answers) != total_questions:
                flash('Veuillez répondre à toutes les questions.', 'warning')
                return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
            # Calculer le score
            correct_count = sum(1 for ua, ca in zip(user_answers, correct_answers) if ua == ca)
            score = (correct_count / total_questions) * 100
            
            # Créer un feedback détaillé
            feedback = {
                'total_questions': total_questions,
                'correct_count': correct_count,
                'details': []
            }
            
            # Ajouter les détails pour chaque question
            for i, (user_answer, correct_answer) in enumerate(zip(user_answers, correct_answers)):
                is_correct = user_answer == correct_answer
                feedback['details'].append({
                    'question_index': i,
                    'user_answer': user_answer,
                    'correct_answer': correct_answer,
                    'is_correct': is_correct
                })
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                score=score,
                course_id=course.id,
                answers=json.dumps(user_answers),  # Convertir en JSON
                feedback=json.dumps(feedback)  # Convertir en JSON
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            flash('Format de réponse invalide.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
    elif exercise.exercise_type == 'drag_and_drop':
        try:
            # Récupérer les réponses de l'utilisateur
            user_answers = json.loads(request.form.get('answers', '[]'))
            
            # Récupérer le contenu de l'exercice
            content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
            words = content.get('words', [])
            
            # Vérifier que nous avons le bon nombre de réponses
            if len(user_answers) != len(words):
                flash('Veuillez remplir tous les blancs.', 'warning')
                return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
            # Calculer le score
            correct_count = 0
            feedback = {
                'total_blanks': len(words),
                'correct_answers': 0,
                'details': []
            }
            
            # Vérifier chaque réponse
            for i, (user_answer, correct_word) in enumerate(zip(user_answers, words)):
                is_correct = user_answer == correct_word
                if is_correct:
                    correct_count += 1
                    feedback['correct_answers'] += 1
                
                feedback['details'].append({
                    'position': i + 1,
                    'user_answer': user_answer,
                    'is_correct': is_correct
                })
            
            score = (correct_count / len(words)) * 100
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                score=score,
                course_id=course.id,
                answers=json.dumps(user_answers),  # Convertir en JSON
                feedback=json.dumps(feedback)  # Convertir en JSON
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            flash('Format de réponse invalide.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
    
    elif exercise.exercise_type == 'file':
        try:
            # Récupérer les réponses de l'utilisateur
            user_answers = request.form.get('answers', '').strip().split('\n')
            user_answers = [word.strip().lower() for word in user_answers if word.strip()]
            
            # Récupérer le contenu de l'exercice
            content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
            words = [word.lower() for word in content.get('words', [])]
            
            # Calculer le score
            correct_words = [word for word in user_answers if word in words]
            score = (len(correct_words) / len(words)) * 100 if words else 0
            
            # Générer le feedback
            feedback = {
                'found_words': correct_words,
                'total_words': len(words),
                'correct_count': len(correct_words),
                'missing_words': [word for word in words if word not in correct_words]
            }
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                score=score,
                course_id=course.id,
                answers=json.dumps(user_answers),
                feedback=json.dumps(feedback)
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except Exception as e:
            print(f"Erreur lors de la soumission : {str(e)}")  # Pour le débogage
            flash('Une erreur est survenue lors de la soumission.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
    elif exercise.exercise_type == 'pairs':
        try:
            # Récupérer les réponses de l'utilisateur
            user_pairs = json.loads(request.form.get('pairs', '[]'))
            
            # Récupérer le contenu de l'exercice
            content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content
            items_left = content.get('items_left', [])
            items_right = content.get('items_right', [])
            
            # Vérifier les paires correctes
            correct_pairs = 0
            total_pairs = len(items_left)
            
            for pair in user_pairs:
                left_index = pair.get('left')
                right_index = pair.get('right')
                if left_index is not None and right_index is not None:
                    if left_index < len(items_left) and right_index < len(items_right):
                        if left_index == right_index:  # Les indices correspondent aux bonnes paires
                            correct_pairs += 1
            
            # Calculer le score
            score = (correct_pairs / total_pairs) * 100 if total_pairs > 0 else 0
            
            # Créer le feedback
            feedback = {
                'correct_pairs': correct_pairs,
                'total_pairs': total_pairs,
                'details': user_pairs
            }
            
            # Créer une nouvelle tentative
            attempt = ExerciseAttempt(
                student_id=current_user.id,
                exercise_id=exercise_id,
                course_id=course.id,
                score=score,
                answers=json.dumps(user_pairs),
                feedback=json.dumps(feedback)
            )
            
            db.session.add(attempt)
            db.session.commit()
            
            flash(f'Exercice soumis ! Score : {score:.1f}%', 'success')
            return redirect(url_for('view_feedback', exercise_id=exercise_id, attempt_id=attempt.id))
            
        except Exception as e:
            print(f"Erreur lors de la soumission : {str(e)}")  # Pour le débogage
            flash('Une erreur est survenue lors de la soumission.', 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
            
    # Pour les autres types d'exercices
    attempt = ExerciseAttempt(
        student_id=current_user.id,
        exercise_id=exercise_id,
        course_id=course.id,
        answers={},
        score=None
    )
    
    db.session.add(attempt)
    db.session.commit()
    
    flash('Réponse soumise avec succès !', 'success')
    
    if exercise.course:
        return redirect(url_for('view_course', course_id=exercise.course.id))
    else:
        return redirect(url_for('exercise_library'))

@app.route('/exercise/<int:exercise_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    
    # Vérifier les permissions
    if exercise.teacher_id != current_user.id:
        teaching_course_ids = [c.id for c in current_user.courses]
        exercise_course_ids = [c.id for c in exercise.courses]
        if not any(course_id in teaching_course_ids for course_id in exercise_course_ids):
            flash("Vous n'avez pas la permission de modifier cet exercice.", 'error')
            return redirect(url_for('exercise_library'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        exercise_type = request.form.get('exercise_type')

        # Gérer l'upload d'une nouvelle image
        if 'exercise_image' in request.files:
            file = request.files['exercise_image']
            if file and file.filename and allowed_file(file.filename):
                # Supprimer l'ancienne image si elle existe
                if exercise.image_path:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], exercise.image_path.split('/')[-1])
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                filename = secure_filename(file.filename)
                filename = f"{int(time.time())}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                exercise.image_path = f"uploads/{filename}"

        exercise.title = title
        exercise.description = description
        exercise.exercise_type = exercise_type

        # Gérer le contenu spécifique au type d'exercice
        if exercise_type == 'qcm':
            question = request.form.get('question')
            options = request.form.getlist('options[]')
            correct_option = request.form.get('correct_option')
            
            if not all([question, options, correct_option]):
                flash('Veuillez remplir tous les champs requis pour le QCM.', 'error')
                return redirect(url_for('edit_exercise', exercise_id=exercise_id))

            content = {
                'question': question,
                'options': options,
                'correct_option': int(correct_option)
            }
            exercise.set_content(json.dumps(content))  # Convertir en JSON
            
        elif exercise_type == 'text':
            text_question = request.form.get('text_question')
            if not text_question:
                flash('Veuillez entrer une question.', 'error')
                return redirect(url_for('edit_exercise', exercise_id=exercise_id))

            exercise.set_content(json.dumps({'question': text_question}))  # Convertir en JSON
            
        elif exercise_type == 'file':
            file_instructions = request.form.get('file_instructions')
            if not file_instructions:
                flash('Veuillez entrer les instructions.', 'error')
                return redirect(url_for('edit_exercise', exercise_id=exercise_id))

            exercise.set_content(json.dumps({'instructions': file_instructions}))  # Convertir en JSON
        
        try:
            db.session.commit()
            flash('Exercice modifié avec succès !', 'success')
            return redirect(url_for('exercise_library'))
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de la modification de l\'exercice.', 'error')
            return redirect(url_for('edit_exercise', exercise_id=exercise_id))

    # Pour la méthode GET, afficher le formulaire d'édition
    content = json.loads(exercise.content) if isinstance(exercise.content, str) else exercise.content  # Convertir en JSON
    return render_template('edit_exercise.html', exercise=exercise, content=content)

@app.route('/exercise/<int:exercise_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    
    # Vérifier que l'enseignant est bien le propriétaire de l'exercice
    if exercise.teacher_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à supprimer cet exercice.', 'error')
        return redirect(url_for('exercise_library'))
    
    try:
        # Supprimer l'image associée si elle existe
        if exercise.image_path:
            image_path = os.path.join(app.static_folder, exercise.image_path)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Supprimer les tentatives associées
        ExerciseAttempt.query.filter_by(exercise_id=exercise_id).delete()
        
        # Supprimer l'exercice des cours
        exercise.courses = []
        
        # Supprimer l'exercice
        db.session.delete(exercise)
        db.session.commit()
        
        flash('L\'exercice a été supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Une erreur est survenue lors de la suppression de l\'exercice.', 'error')
        print(f"Erreur lors de la suppression de l'exercice : {str(e)}")
    
    return redirect(url_for('exercise_library'))

@app.route('/submit-exercise/<int:exercise_id>', methods=['POST'])
@login_required
def submit_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    data = request.get_json()
    
    # Enregistrer la tentative
    record_attempt(exercise_id, data)
    
    return jsonify({'message': 'Exercice soumis avec succès !'})

@app.route('/record-attempt/<int:exercise_id>', methods=['POST'])
@login_required
def record_attempt(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    data = request.get_json()
    
    # Enregistrer les données de la tentative
    # TODO: Implémenter la logique d'enregistrement des tentatives
    
    return jsonify({'message': 'Tentative enregistrée avec succès !'})

@app.route('/course/<int:course_id>')
@login_required
def view_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Vérifier que l'utilisateur a accès au cours
    if not current_user.is_teacher and not current_user.is_enrolled(course.class_obj.id):
        flash('Vous n\'avez pas accès à ce cours.', 'error')
        return redirect(url_for('index'))
    
    # Si c'est un enseignant, récupérer la liste des exercices disponibles
    exercises_available = []
    if current_user.is_teacher:
        # Récupérer tous les exercices créés par l'enseignant qui ne sont pas déjà dans le cours
        exercises_available = Exercise.query.filter_by(teacher_id=current_user.id).filter(
            ~Exercise.id.in_([ex.id for ex in course.exercises])
        ).all()
    
    # Récupérer les exercices du cours
    exercises = course.exercises
    
    # Pour les enseignants, récupérer les statistiques du cours
    stats = None
    if current_user.is_teacher:
        stats = {
            'total_students': len(course.class_obj.students),
            'total_exercises': len(exercises),
            'exercises_stats': []
        }
        
        for exercise in exercises:
            exercise_stats = {
                'title': exercise.title,
                'completion_rate': 0,
                'average_score': 0,
                'needs_grading': 0
            }
            
            total_students = len(course.class_obj.students)
            if total_students > 0:
                completed = 0
                total_score = 0
                needs_grading = 0
                
                for student in course.class_obj.students:
                    progress = exercise.get_student_progress(student.id)
                    if progress['status'] == 'completed':
                        completed += 1
                        if progress['best_score'] is not None:
                            total_score += progress['best_score']
                    elif progress['needs_grading']:
                        needs_grading += 1
                
                exercise_stats['completion_rate'] = (completed / total_students) * 100
                if completed > 0:
                    exercise_stats['average_score'] = total_score / completed
                exercise_stats['needs_grading'] = needs_grading
            
            stats['exercises_stats'].append(exercise_stats)
    
    return render_template('view_course.html', 
                         course=course,
                         exercises=exercises,
                         exercises_available=exercises_available,
                         stats=stats)

@app.route('/get_courses/<int:class_id>')
def get_courses(class_id):
    try:
        app.logger.info(f"[get_courses] Début de la récupération des cours pour la classe {class_id}")
        
        # Vérifier si la classe existe
        class_obj = Class.query.get_or_404(class_id)
        app.logger.info(f"[get_courses] Classe trouvée: {class_obj.name}")
        
        # Debug des relations
        app.logger.info(f"[get_courses] Relations de la classe:")
        app.logger.info(f"[get_courses] - teacher_id: {class_obj.teacher_id}")
        app.logger.info(f"[get_courses] - nombre d'étudiants: {len(class_obj.students)}")
        
        # Récupérer tous les cours de la classe
        courses = Course.query.filter_by(class_obj=class_obj).all()
        app.logger.info(f"[get_courses] Requête des cours effectuée")
        
        # Préparer la réponse
        courses_data = []
        for course in courses:
            app.logger.info(f"[get_courses] Traitement du cours: {course.title}")
            app.logger.info(f"[get_courses] - ID: {course.id}")
            app.logger.info(f"[get_courses] - Contenu: {course.content}")
            courses_data.append({
                'id': course.id,
                'title': course.title
            })
        
        app.logger.info(f"[get_courses] Nombre total de cours trouvés: {len(courses_data)}")
        return jsonify(courses_data)
        
    except Exception as e:
        app.logger.error(f"[get_courses] Erreur lors de la récupération des cours: {str(e)}")
        app.logger.error(f"[get_courses] Type d'erreur: {type(e).__name__}")
        import traceback
        app.logger.error(f"[get_courses] Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/class/<int:class_id>/create_course', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_course(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    # Vérifier que l'utilisateur est bien le professeur de cette classe
    if class_obj.teacher_id != current_user.id:
        flash("Vous n'avez pas l'autorisation de créer un cours dans cette classe.", 'error')
        return redirect(url_for('teacher_dashboard'))
    
    class CourseForm(FlaskForm):
        title = StringField('Titre', validators=[DataRequired()])
        content = TextAreaField('Contenu')
        files = MultipleFileField('Fichiers joints')
    
    form = CourseForm()
    
    if form.validate_on_submit():
        # Récupérer le contenu de l'éditeur
        content = request.form.get('content', '{}')
        
        course = Course(
            title=form.title.data,
            content=json.dumps(content),  # Convertir en JSON
            class_id=class_id
        )
        
        # Gérer les fichiers
        files = request.files.getlist('files')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                course_file = CourseFile(
                    filename=filename,
                    original_filename=file.filename,
                    file_type=file.content_type,
                    file_size=os.path.getsize(filepath),
                    course=course
                )
                db.session.add(course_file)
        
        db.session.add(course)
        db.session.commit()
        flash('Le cours a été créé avec succès.', 'success')
        return redirect(url_for('view_class', class_id=class_id))
    
    return render_template('create_course.html', form=form, class_id=class_id)

@app.route('/student/classes')
@login_required
def view_student_classes():
    if current_user.role == 'teacher':
        flash('Cette page est réservée aux étudiants.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    enrolled_classes = current_user.classes_enrolled
    return render_template('student_classes.html', classes=enrolled_classes)

@app.route('/class/join_by_code', methods=['GET', 'POST'])
@login_required
def join_class_by_code():
    if request.method == 'POST':
        class_code = request.form.get('class_code')
        if not class_code:
            flash('Le code d\'accès est requis.', 'error')
            return redirect(url_for('view_student_classes'))
        
        class_obj = Class.query.filter_by(access_code=class_code).first()
        if not class_obj:
            flash('Code d\'accès invalide.', 'error')
            return redirect(url_for('view_student_classes'))
        
        if current_user in class_obj.students:
            flash('Vous êtes déjà inscrit dans cette classe.', 'warning')
            return redirect(url_for('view_class', class_id=class_obj.id))
        
        try:
            class_obj.students.append(current_user)
            db.session.commit()
            flash('Vous avez rejoint la classe avec succès !', 'success')
            return redirect(url_for('view_class', class_id=class_obj.id))
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de l\'inscription à la classe.', 'error')
            return redirect(url_for('view_student_classes'))
    
    return redirect(url_for('view_student_classes'))

@app.route('/class/<int:class_id>/view')
@login_required
def view_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    # Si c'est l'enseignant de la classe
    if current_user.role == 'teacher' and class_obj.teacher_id == current_user.id:
        return view_class_teacher(class_id)
    
    # Si c'est un étudiant inscrit dans la classe
    if not current_user.role == 'teacher' and class_obj in current_user.classes_enrolled:
        return render_template('view_class.html', class_obj=class_obj)
    
    flash('Accès non autorisé.', 'error')
    return redirect(url_for('index'))

@app.route('/class/<int:class_id>/view/teacher')
@login_required
@teacher_required
def view_class_teacher(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Vous n\'êtes pas le professeur de cette classe.', 'error')
        return redirect(url_for('index'))
    return render_template('view_class.html', class_obj=class_obj)

@app.route('/course/<int:course_id>/add-exercise', methods=['POST'])
@login_required
def add_exercise_to_course(course_id):
    app.logger.info(f"[add_exercise_to_course] Début de l'ajout d'exercice au cours {course_id}")
    app.logger.info(f"[add_exercise_to_course] Utilisateur: {current_user.id} ({current_user.role})")
    
    if not current_user.role == 'teacher':
        app.logger.warning("[add_exercise_to_course] Tentative d'accès non autorisé")
        flash('Accès non autorisé. Seuls les enseignants peuvent ajouter des exercices.', 'error')
        return redirect(url_for('index'))
    
    course = Course.query.get_or_404(course_id)
    app.logger.info(f"[add_exercise_to_course] Cours trouvé: {course.title}")
    
    # Vérifier que l'utilisateur est le propriétaire de la classe
    if course.class_obj.teacher_id != current_user.id:
        app.logger.warning("[add_exercise_to_course] L'utilisateur n'est pas le propriétaire de la classe")
        flash('Vous ne pouvez pas modifier ce cours.', 'error')
        return redirect(url_for('index'))
    
    exercise_id = request.form.get('exercise_id')
    app.logger.info(f"[add_exercise_to_course] ID de l'exercice reçu: {exercise_id}")
    
    if not exercise_id:
        app.logger.warning("[add_exercise_to_course] Aucun exercice sélectionné")
        flash('Veuillez sélectionner un exercice.', 'error')
        return redirect(url_for('view_course', course_id=course_id))
    
    exercise = Exercise.query.get_or_404(exercise_id)
    app.logger.info(f"[add_exercise_to_course] Exercice trouvé: {exercise.title}")
    
    # Vérifier que l'exercice n'est pas déjà dans le cours
    if exercise in course.exercises:
        app.logger.warning("[add_exercise_to_course] L'exercice est déjà dans le cours")
        flash('Cet exercice est déjà dans le cours.', 'error')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        app.logger.info(f"[add_exercise_to_course] Tentative d'ajout de l'exercice {exercise_id} au cours {course_id}")
        app.logger.info(f"[add_exercise_to_course] État actuel du cours - Exercices: {[ex.id for ex in course.exercises]}")
        
        course.exercises.append(exercise)
        db.session.commit()
        
        app.logger.info(f"[add_exercise_to_course] Nouvel état du cours - Exercices: {[ex.id for ex in course.exercises]}")
        flash('Exercice ajouté au cours avec succès !', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"[add_exercise_to_course] Erreur lors de l'ajout : {str(e)}")
        app.logger.error(f"[add_exercise_to_course] Type d'erreur : {type(e).__name__}")
        import traceback
        app.logger.error(f"[add_exercise_to_course] Traceback : {traceback.format_exc()}")
        flash('Erreur lors de l\'ajout de l\'exercice au cours.', 'error')
    
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/course/<int:course_id>/remove-exercise/<int:exercise_id>', methods=['POST'])
@login_required
def remove_exercise_from_course(course_id, exercise_id):
    if not current_user.role == 'teacher':
        flash('Accès non autorisé. Seuls les enseignants peuvent retirer des exercices.', 'error')
        return redirect(url_for('index'))
    
    course = Course.query.get_or_404(course_id)
    
    # Vérifier que l'utilisateur est le propriétaire de la classe
    if course.class_obj.teacher_id != current_user.id:
        flash('Vous ne pouvez pas modifier ce cours.', 'error')
        return redirect(url_for('index'))
    
    exercise = Exercise.query.get_or_404(exercise_id)
    
    try:
        course.exercises.remove(exercise)
        db.session.commit()
        flash('Exercice retiré du cours avec succès !', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Erreur lors du retrait de l\'exercice du cours.', 'error')
        print(f"Erreur : {str(e)}")
    
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/quick-add-exercise/<int:exercise_id>')
@login_required
@teacher_required
def quick_add_exercise(exercise_id):
    app.logger.info(f"[quick_add_exercise] Affichage du formulaire d'ajout rapide pour l'exercice {exercise_id}")
    
    # Récupérer l'exercice
    exercise = Exercise.query.get_or_404(exercise_id)
    app.logger.info(f"[quick_add_exercise] Exercice trouvé: {exercise.title}")
    
    # Récupérer les classes de l'enseignant
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    app.logger.info(f"[quick_add_exercise] Nombre de classes trouvées: {len(classes)}")
    
    return render_template('quick_add_exercise.html', 
                         exercise=exercise,
                         classes=classes)

@app.route('/quick-add-exercise/<int:exercise_id>/add', methods=['POST'])
@login_required
@teacher_required
def process_quick_add_exercise(exercise_id):
    app.logger.info(f"[process_quick_add_exercise] Traitement de l'ajout rapide pour l'exercice {exercise_id}")
    
    exercise = Exercise.query.get_or_404(exercise_id)
    app.logger.info(f"[process_quick_add_exercise] Exercice trouvé: {exercise.title}")
    
    class_id = request.form.get('class_id')
    course_id = request.form.get('course_id')
    app.logger.info(f"[process_quick_add_exercise] Données reçues - Class ID: {class_id}, Course ID: {course_id}")
    
    if not class_id or not course_id:
        app.logger.warning("[process_quick_add_exercise] Classe ou cours manquant")
        flash('Veuillez sélectionner une classe et un cours.', 'error')
        return redirect(url_for('quick_add_exercise', exercise_id=exercise_id))
    
    try:
        # Vérifier que la classe appartient à l'enseignant
        class_obj = Class.query.get_or_404(class_id)
        app.logger.info(f"[process_quick_add_exercise] Classe trouvée: {class_obj.name}")
        
        if class_obj.teacher_id != current_user.id:
            app.logger.warning(f"[process_quick_add_exercise] L'utilisateur n'a pas accès à la classe {class_id}")
            flash('Vous n\'avez pas accès à cette classe.', 'error')
            return redirect(url_for('exercise_library'))
        
        # Vérifier que le cours appartient à la classe
        course = Course.query.get_or_404(course_id)
        app.logger.info(f"[process_quick_add_exercise] Cours trouvé: {course.title}")
        
        if course.class_obj.id != class_obj.id:
            app.logger.warning(f"[process_quick_add_exercise] Le cours {course_id} n'appartient pas à la classe {class_id}")
            flash('Ce cours n\'appartient pas à la classe sélectionnée.', 'error')
            return redirect(url_for('exercise_library'))
        
        # Ajouter l'exercice au cours s'il n'y est pas déjà
        if exercise not in course.exercises:
            app.logger.info(f"[process_quick_add_exercise] Ajout de l'exercice {exercise_id} au cours {course_id}")
            course.exercises.append(exercise)
            db.session.commit()
            flash('Exercice ajouté avec succès au cours !', 'success')
        else:
            app.logger.info(f"[process_quick_add_exercise] L'exercice {exercise_id} est déjà dans le cours {course_id}")
            flash('Cet exercice est déjà dans le cours.', 'info')
        
        return redirect(url_for('view_course', course_id=course_id))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"[process_quick_add_exercise] Erreur lors de l'ajout de l'exercice: {str(e)}")
        app.logger.error(f"[process_quick_add_exercise] Type d'erreur: {type(e).__name__}")
        import traceback
        app.logger.error(f"[process_quick_add_exercise] Traceback: {traceback.format_exc()}")
        flash('Une erreur est survenue lors de l\'ajout de l\'exercice.', 'error')
        return redirect(url_for('quick_add_exercise', exercise_id=exercise_id))

@app.route('/class/create', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_class():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Le nom de la classe est requis.', 'error')
            return redirect(url_for('create_class'))
        
        # Générer un code d'accès unique
        import random
        import string
        
        access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        while Class.query.filter_by(access_code=access_code).first() is not None:
            access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        try:
            new_class = Class(
                name=name,
                description=description,
                teacher_id=current_user.id,
                access_code=access_code
            )
            
            db.session.add(new_class)
            db.session.commit()
            
            # Afficher le code d'accès à l'enseignant
            flash(f'Classe créée avec succès ! Code d\'accès : {access_code}', 'success')
            return redirect(url_for('view_class', class_id=new_class.id))
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de la création de la classe.', 'error')
            return redirect(url_for('create_class'))
    
    return render_template('create_class.html')

@app.route('/class/<int:class_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    # Vérifier que l'utilisateur est bien le propriétaire de la classe
    if class_obj.teacher_id != current_user.id:
        flash('Vous n\'avez pas la permission de modifier cette classe.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Le nom de la classe est requis.', 'error')
            return redirect(url_for('edit_class', class_id=class_id))
        
        try:
            class_obj.name = name
            class_obj.description = description
            db.session.commit()
            flash('Classe modifiée avec succès !', 'success')
            return redirect(url_for('view_class', class_id=class_id))
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de la modification de la classe.', 'error')
            return redirect(url_for('edit_class', class_id=class_id))
    
    return render_template('edit_class.html', class_obj=class_obj)

@app.route('/class/<int:class_id>/add_student', methods=['POST'])
@login_required
@teacher_required
def add_student_to_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    # Vérifier que l'utilisateur est bien le propriétaire de la classe
    if class_obj.teacher_id != current_user.id:
        flash('Vous n\'avez pas la permission de modifier cette classe.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    email = request.form.get('email')
    if not email:
        flash('L\'email de l\'étudiant est requis.', 'error')
        return redirect(url_for('view_class', class_id=class_id))
    
    student = User.query.filter_by(email=email).first()
    if not student:
        flash('Aucun étudiant trouvé avec cet email.', 'error')
        return redirect(url_for('view_class', class_id=class_id))
    
    if student in class_obj.students:
        flash('Cet étudiant est déjà inscrit dans cette classe.', 'warning')
        return redirect(url_for('view_class', class_id=class_id))
    
    try:
        class_obj.students.append(student)
        db.session.commit()
        flash('Étudiant ajouté avec succès !', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Une erreur est survenue lors de l\'ajout de l\'étudiant.', 'error')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/course/<int:course_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    class_obj = Class.query.get_or_404(course.class_id)
    
    # Vérifier que l'utilisateur est le professeur de la classe
    if current_user.id != class_obj.teacher_id:
        flash("Vous n'êtes pas autorisé à modifier ce cours.", 'error')
        return redirect(url_for('view_class', class_id=class_obj.id))
    
    class CourseForm(FlaskForm):
        title = StringField('Titre', validators=[DataRequired()])
        files = MultipleFileField('Ajouter des fichiers')
    
    form = CourseForm(obj=course)
    
    if form.validate_on_submit():
        course.title = form.title.data
        course.content = json.dumps(request.form.get('content', '{}'))  # Convertir en JSON
        
        # Gérer les nouveaux fichiers
        files = request.files.getlist('files')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                course_file = CourseFile(
                    filename=filename,
                    original_filename=file.filename,
                    file_type=file.content_type,
                    file_size=os.path.getsize(filepath),
                    course=course
                )
                db.session.add(course_file)
        
        db.session.commit()
        flash('Le cours a été modifié avec succès !', 'success')
        return redirect(url_for('view_course', course_id=course.id))
    
    return render_template('edit_course.html', course=course, form=form)

@app.route('/course/<int:course_id>/file/<int:file_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_course_file(course_id, file_id):
    course = Course.query.get_or_404(course_id)
    course_file = CourseFile.query.get_or_404(file_id)
    
    # Vérifier que le fichier appartient bien au cours
    if course_file.course_id != course.id:
        return jsonify({'error': 'Ce fichier n\'appartient pas à ce cours.'}), 403
    
    # Vérifier que l'utilisateur est bien le professeur de la classe
    class_obj = Class.query.get(course.class_id)
    if current_user.id != class_obj.teacher_id:
        return jsonify({'error': 'Vous n\'êtes pas autorisé à supprimer ce fichier.'}), 403
    
    try:
        # Supprimer le fichier physique
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], course_file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Supprimer l'entrée dans la base de données
        db.session.delete(course_file)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/create_exercise', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_exercise():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        exercise_type = request.form.get('exercise_type')

        # Traitement de l'image si elle est fournie
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    # Générer un nom de fichier sécurisé
                    filename = secure_filename(file.filename)
                    # Ajouter un timestamp pour éviter les doublons
                    name, ext = os.path.splitext(filename)
                    filename = f"{name}_{int(time.time())}{ext}"
                    # Sauvegarder le fichier
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = filename
                else:
                    flash('Format d\'image non supporté.', 'error')
                    return redirect(url_for('create_exercise'))
        
        content = {}
        
        if exercise_type == 'qcm':
            questions = request.form.getlist('questions[]')
            content['questions'] = questions
            content['options'] = []
            content['correct_answers'] = []
            
            for i in range(len(questions)):
                options = request.form.getlist(f'options_{i+1}[]')
                correct_answer = int(request.form.get(f'correct_answer_{i+1}', 0))
                content['options'].append(options)
                content['correct_answers'].append(correct_answer)
        
        elif exercise_type == 'drag_and_drop':
            sentence = request.form.get('sentence')
            words = request.form.get('words')
            
            if not sentence or not words:
                flash('Veuillez remplir tous les champs requis.', 'error')
                return redirect(url_for('create_exercise'))
            
            # Vérifier que le nombre de blancs correspond au nombre de mots
            blank_count = sentence.count('___')
            word_count = len(words.split(','))
            
            if blank_count != word_count:
                flash(f'Le nombre de blancs ({blank_count}) ne correspond pas au nombre de mots ({word_count}).', 'error')
                return redirect(url_for('create_exercise'))
            
            content = {
                'sentence': sentence,
                'words': [word.strip() for word in words.split(',')]
            }
        
        elif exercise_type == 'pairs':
            items_left = request.form.getlist('items_left[]')
            items_right = request.form.getlist('items_right[]')
            items_left_files = request.files.getlist('items_left_image[]')
            items_right_files = request.files.getlist('items_right_image[]')
            
            if len(items_left) != len(items_right) or not items_left or not items_right:
                flash('Veuillez fournir un nombre égal d\'éléments gauches et droits.', 'error')
                return redirect(url_for('create_exercise'))
            
            # Traitement des images
            items_left_images = []
            items_right_images = []
            
            for idx, (left_file, right_file) in enumerate(zip(items_left_files, items_right_files)):
                # Traitement image gauche
                left_image_path = None
                if left_file and left_file.filename:
                    if left_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        filename = secure_filename(left_file.filename)
                        name, ext = os.path.splitext(filename)
                        filename = f"pair_left_{idx}_{int(time.time())}{ext}"
                        left_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        left_image_path = filename
                items_left_images.append(left_image_path)
                
                # Traitement image droite
                right_image_path = None
                if right_file and right_file.filename:
                    if right_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        filename = secure_filename(right_file.filename)
                        name, ext = os.path.splitext(filename)
                        filename = f"pair_right_{idx}_{int(time.time())}{ext}"
                        right_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        right_image_path = filename
                items_right_images.append(right_image_path)
            
            content = {
                'items_left': items_left,
                'items_right': items_right,
                'items_left_images': items_left_images,
                'items_right_images': items_right_images
            }
        
        elif exercise_type == 'file':
            file_instructions = request.form.get('file_instructions')
            if not file_instructions:
                flash('Veuillez entrer les instructions.', 'error')
                return redirect(url_for('create_exercise'))
            
            content = {
                'instructions': file_instructions
            }
        
        elif exercise_type == 'word_search':
            # Récupérer les paramètres de la grille
            grid_rows = int(request.form.get('grid_rows', 10))
            grid_cols = int(request.form.get('grid_cols', 10))
            words_input = request.form.get('word_search_words', '').strip()
            
            # Valider l'entrée des mots
            if not words_input:
                flash("Veuillez entrer au moins un mot à cacher.", 'error')
                return redirect(url_for('create_exercise'))
            
            # Nettoyer et valider chaque mot
            words = []
            for word in words_input.split(','):
                word = word.strip().lower()
                if not word:
                    continue
                    
                # Vérifier la longueur du mot
                if len(word) > max(grid_rows, grid_cols):
                    flash(f"Le mot '{word}' est trop long ({len(word)} lettres). La longueur maximale est de {max(grid_rows, grid_cols)} lettres avec la taille de grille actuelle ({grid_rows}x{grid_cols}).", 'error')
                    return redirect(url_for('create_exercise'))
                    
                # Vérifier les caractères valides
                if not word.isalpha():
                    flash(f"Le mot '{word}' contient des caractères non autorisés. Utilisez uniquement des lettres.", 'error')
                    return redirect(url_for('create_exercise'))
                    
                words.append(word)
            
            # Vérifier qu'il y a au moins un mot valide
            if not words:
                flash("Veuillez entrer au moins un mot valide à cacher.", 'error')
                return redirect(url_for('create_exercise'))
            
            # Créer une grille vide
            grid = [['' for _ in range(grid_cols)] for _ in range(grid_rows)]
            
            # Fonction pour vérifier si un mot peut être placé à une position donnée
            def can_place_word(word, start_row, start_col, row_dir, col_dir):
                row, col = start_row, start_col
                for letter in word:
                    if not (0 <= row < grid_rows and 0 <= col < grid_cols):
                        return False
                    if grid[row][col] and grid[row][col] != letter:
                        return False
                    row += row_dir
                    col += col_dir
                return True
            
            # Fonction pour placer un mot dans la grille
            def place_word(word, start_row, start_col, row_dir, col_dir):
                row, col = start_row, start_col
                for letter in word:
                    grid[row][col] = letter
                    row += row_dir
                    col += col_dir
            
            # Directions possibles (horizontal, vertical, diagonal)
            directions = [
                (0, 1),   # droite
                (1, 0),   # bas
                (1, 1),   # diagonal bas-droite
                (-1, 1),  # diagonal haut-droite
            ]
            
            import random
            
            # Essayer de placer chaque mot
            random.shuffle(words)  # Mélanger les mots pour un placement plus varié
            placed_words = []
            
            for word in words:
                word = word.lower()
                # Essayer plusieurs fois de placer le mot
                placed = False
                attempts = 0
                max_attempts = 50
                
                while not placed and attempts < max_attempts:
                    # Choisir une position et une direction aléatoires
                    row_dir, col_dir = random.choice(directions)
                    
                    # Calculer les limites de départ possibles
                    if row_dir > 0:
                        max_start_row = grid_rows - len(word)
                        min_start_row = 0
                    elif row_dir < 0:
                        max_start_row = grid_rows - 1
                        min_start_row = len(word) - 1
                    else:
                        max_start_row = grid_rows - 1
                        min_start_row = 0
                        
                    if col_dir > 0:
                        max_start_col = grid_cols - len(word)
                        min_start_col = 0
                    elif col_dir < 0:
                        max_start_col = grid_cols - 1
                        min_start_col = len(word) - 1
                    else:
                        max_start_col = grid_cols - 1
                        min_start_col = 0
                    
                    # S'assurer que les limites sont valides
                    if max_start_row < min_start_row or max_start_col < min_start_col:
                        attempts += 1
                        continue
                    
                    start_row = random.randint(min_start_row, max_start_row)
                    start_col = random.randint(min_start_col, max_start_col)
                    
                    # Vérifier si on peut placer le mot
                    if can_place_word(word, start_row, start_col, row_dir, col_dir):
                        place_word(word, start_row, start_col, row_dir, col_dir)
                        placed = True
                        placed_words.append(word)
                    
                    attempts += 1
            
            if not placed_words:
                flash("Impossible de placer les mots dans la grille. Essayez avec une grille plus grande ou moins de mots.", 'error')
                return redirect(url_for('create_exercise'))
            
            # Remplir les cases vides avec des lettres aléatoires
            letters = 'abcdefghijklmnopqrstuvwxyz'
            for i in range(grid_rows):
                for j in range(grid_cols):
                    if not grid[i][j]:
                        grid[i][j] = random.choice(letters)
            
            content = {
                'grid': grid,
                'words': placed_words
            }
        
        exercise = Exercise(
            title=title,
            description=description,
            exercise_type=exercise_type,
            content=json.dumps(content),  # Convertir en JSON
            image_path=image_path,
            teacher_id=current_user.id
        )
        
        db.session.add(exercise)
        db.session.commit()
        
        flash('Exercice créé avec succès !', 'success')
        return redirect(url_for('exercise_library'))
    
    return render_template('create_exercise.html')

@app.route('/exercise/<int:exercise_id>/add_to_class', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_exercise_to_class(exercise_id):
    app.logger.info(f"[add_exercise_to_class] Début de la fonction pour l'exercice {exercise_id}")
    
    exercise = Exercise.query.get_or_404(exercise_id)
    app.logger.info(f"[add_exercise_to_class] Exercice trouvé: {exercise.title}")
    
    # Vérifier que l'utilisateur est le propriétaire de l'exercice
    app.logger.info(f"[add_exercise_to_class] Vérification du propriétaire - Teacher ID: {exercise.teacher_id}, Current User ID: {current_user.id}")
    if exercise.teacher_id != current_user.id:
        app.logger.warning(f"[add_exercise_to_class] L'utilisateur {current_user.id} n'est pas le propriétaire de l'exercice {exercise_id}")
        flash('Vous ne pouvez pas ajouter cet exercice.', 'error')
        return redirect(url_for('exercise_library'))
    
    # Récupérer les classes de l'enseignant
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    app.logger.info(f"[add_exercise_to_class] Nombre de classes trouvées: {len(classes)}")
    for class_obj in classes:
        app.logger.info(f"[add_exercise_to_class] - Classe: {class_obj.name} (ID: {class_obj.id})")
    
    if request.method == 'POST':
        app.logger.info("[add_exercise_to_class] Traitement d'une requête POST")
        class_id = request.form.get('class_id')
        course_id = request.form.get('course_id')
        app.logger.info(f"[add_exercise_to_class] Données reçues - Class ID: {class_id}, Course ID: {course_id}")
        
        if not class_id or not course_id:
            app.logger.warning("[add_exercise_to_class] Classe ou cours manquant dans le formulaire")
            flash('Veuillez sélectionner une classe et un cours.', 'error')
            return redirect(url_for('add_exercise_to_class', exercise_id=exercise_id))
        
        try:
            # Vérifier que la classe appartient à l'enseignant
            class_obj = Class.query.get_or_404(class_id)
            app.logger.info(f"[add_exercise_to_class] Classe trouvée: {class_obj.name}")
            
            if class_obj.teacher_id != current_user.id:
                app.logger.warning(f"[add_exercise_to_class] L'utilisateur n'a pas accès à la classe {class_id}")
                flash('Vous n\'avez pas accès à cette classe.', 'error')
                return redirect(url_for('exercise_library'))
            
            # Vérifier que le cours appartient à la classe
            course = Course.query.get_or_404(course_id)
            app.logger.info(f"[add_exercise_to_class] Cours trouvé: {course.title}")
            
            if course.class_obj.id != class_obj.id:
                app.logger.warning(f"[add_exercise_to_class] Le cours {course_id} n'appartient pas à la classe {class_id}")
                flash('Ce cours n\'appartient pas à la classe sélectionnée.', 'error')
                return redirect(url_for('exercise_library'))
            
            # Ajouter l'exercice au cours s'il n'y est pas déjà
            if exercise not in course.exercises:
                app.logger.info(f"[add_exercise_to_class] Ajout de l'exercice {exercise_id} au cours {course_id}")
                course.exercises.append(exercise)
                db.session.commit()
                flash('Exercice ajouté avec succès au cours !', 'success')
            else:
                app.logger.info(f"[add_exercise_to_class] L'exercice {exercise_id} est déjà dans le cours {course_id}")
                flash('Cet exercice est déjà dans le cours.', 'info')
            
            return redirect(url_for('view_course', course_id=course_id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"[add_exercise_to_class] Erreur lors de l'ajout de l'exercice: {str(e)}")
            app.logger.error(f"[add_exercise_to_class] Type d'erreur: {type(e).__name__}")
            import traceback
            app.logger.error(f"[add_exercise_to_class] Traceback: {traceback.format_exc()}")
            flash('Une erreur est survenue lors de l\'ajout de l\'exercice.', 'error')
            return redirect(url_for('add_exercise_to_class', exercise_id=exercise_id))
    
    app.logger.info("[add_exercise_to_class] Affichage du formulaire d'ajout")
    return render_template('add_exercise_to_class.html', 
                         exercise=exercise,
                         classes=classes)

@app.route('/api/class/<int:class_id>/courses')
@login_required
def get_class_courses_api(class_id):
    try:
        app.logger.info(f"[get_class_courses_api] Récupération des cours pour la classe {class_id}")
        
        # Vérifier si l'utilisateur a accès à la classe
        class_obj = Class.query.get_or_404(class_id)
        
        if current_user.role == 'teacher':
            if class_obj.teacher_id != current_user.id:
                app.logger.warning(f"[get_class_courses_api] L'enseignant {current_user.id} n'a pas accès à la classe {class_id}")
                return jsonify({'error': 'Non autorisé'}), 403
        else:
            if class_obj not in current_user.classes_enrolled:
                app.logger.warning(f"[get_class_courses_api] L'étudiant {current_user.id} n'est pas inscrit à la classe {class_id}")
                return jsonify({'error': 'Non autorisé'}), 403
        
        # Récupérer tous les cours de la classe
        courses = Course.query.filter_by(class_obj=class_obj).all()
        app.logger.info(f"[get_class_courses_api] {len(courses)} cours trouvés")
        
        # Convertir en format JSON
        courses_data = [{
            'id': course.id,
            'title': course.title
        } for course in courses]
        
        app.logger.info(f"[get_class_courses_api] Données renvoyées: {courses_data}")
        return jsonify(courses_data)
        
    except Exception as e:
        app.logger.error(f"[get_class_courses_api] Erreur API courses: {str(e)}")
        app.logger.error(f"[get_class_courses_api] Type d'erreur: {type(e).__name__}")
        import traceback
        app.logger.error(f"[get_class_courses_api] Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Erreur API courses: {str(e)}'}), 500

@app.route('/course/<int:course_id>/stats')
@login_required
def course_stats(course_id):
    print("\n=== DÉBUT COURSE_STATS ===")
    print(f"[DEBUG] Statistiques pour le cours {course_id}")
    print(f"[DEBUG] Utilisateur connecté: {current_user.username} (ID: {current_user.id})")
    
    try:
        course = Course.query.get_or_404(course_id)
        
        # Vérifier les permissions
        if current_user.role == 'teacher' and course.class_obj.teacher_id != current_user.id:
            print(f"[ERROR] L'utilisateur {current_user.id} n'est pas le professeur de la classe")
            flash("Vous n'avez pas l'autorisation de voir ces statistiques.", 'error')
            return redirect(url_for('teacher_dashboard'))
        
        if current_user.role == 'student' and current_user not in course.class_obj.students:
            print(f"[ERROR] L'utilisateur {current_user.id} n'est pas inscrit dans cette classe")
            flash("Vous n'êtes pas inscrit dans ce cours.", 'error')
            return redirect(url_for('student_dashboard'))
        
        # Obtenir les statistiques appropriées selon le rôle
        if current_user.role == 'teacher':
            stats = course.get_class_stats()
            print(f"[DEBUG] Statistiques du cours: {stats}")
            return render_template('course_stats_teacher.html', course=course, stats=stats)
        else:
            stats = course.get_student_stats(current_user.id)
            print(f"[DEBUG] Statistiques de l'élève: {stats}")
            return render_template('course_stats_student.html', course=course, stats=stats)
            
    except Exception as e:
        print(f"[ERROR] Erreur dans course_stats: {str(e)}")
        print(f"[ERROR] Type d'erreur: {type(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        flash('Une erreur est survenue lors de l\'accès aux statistiques.', 'error')
        return redirect(url_for('view_course', course_id=course_id))
    
    finally:
        print("=== FIN COURSE_STATS ===\n")

@app.route('/exercise/<int:exercise_id>/stats')
@login_required
@teacher_required
def exercise_stats(exercise_id):
    print("\n=== DÉBUT EXERCISE_STATS ===")
    print(f"[DEBUG] Statistiques pour l'exercice {exercise_id}")
    print(f"[DEBUG] Utilisateur connecté: {current_user.username} (ID: {current_user.id})")
    
    try:
        exercise = Exercise.query.get_or_404(exercise_id)
        
        # Si un cours est spécifié, obtenir les stats pour ce cours
        course_id = request.args.get('course_id', type=int)
        if course_id:
            course = Course.query.get_or_404(course_id)
            if course.class_obj.teacher_id != current_user.id:
                print(f"[ERROR] L'utilisateur {current_user.id} n'est pas le professeur de la classe")
                flash("Vous n'avez pas l'autorisation de voir ces statistiques.", 'error')
                return redirect(url_for('teacher_dashboard'))
        
        # Obtenir les statistiques
        stats = exercise.get_stats(course_id)
        print(f"[DEBUG] Statistiques de l'exercice: {stats}")
        
        # Obtenir les tentatives détaillées si un cours est spécifié
        if course_id:
            attempts = ExerciseAttempt.query.filter_by(
                exercise_id=exercise_id,
                course_id=course_id
            ).order_by(ExerciseAttempt.created_at.desc()).all()
        else:
            attempts = []
        
        return render_template('exercise_stats.html', 
                             exercise=exercise,
                             stats=stats,
                             attempts=attempts,
                             course_id=course_id)
            
    except Exception as e:
        print(f"[ERROR] Erreur dans exercise_stats: {str(e)}")
        print(f"[ERROR] Type d'erreur: {type(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        flash('Une erreur est survenue lors de l\'accès aux statistiques.', 'error')
        return redirect(url_for('exercise_library'))
    
    finally:
        print("=== FIN EXERCISE_STATS ===\n")

@app.route('/exercise/<int:exercise_id>/feedback/<int:attempt_id>')
@login_required
def view_feedback(exercise_id, attempt_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    attempt = ExerciseAttempt.query.get_or_404(attempt_id)
    
    # Vérifier que l'utilisateur a accès à cet exercice
    if not current_user.is_teacher and attempt.student_id != current_user.id:
        flash("Vous n'avez pas accès à ce feedback.", 'error')
        return redirect(url_for('exercise_library'))
    
    # Choisir le template en fonction du type d'exercice
    if exercise.exercise_type == 'word_search':
        template = 'feedback_word_search.html'
    else:
        template = 'feedback.html'
    
    # Convertir les réponses et le feedback de JSON en objets Python
    try:
        answers = json.loads(attempt.answers) if attempt.answers else None
        feedback = json.loads(attempt.feedback) if attempt.feedback else None
    except json.JSONDecodeError:
        answers = attempt.answers
        feedback = attempt.feedback
    
    return render_template(template, exercise=exercise, attempt=attempt, answers=answers, feedback=feedback)

def enumerate_filter(iterable, start=0):
    return enumerate(iterable, start=start)

def from_json_filter(value):
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

# Ajouter les filtres à l'environnement Jinja2
app.jinja_env.filters['enumerate'] = enumerate_filter
app.jinja_env.filters['from_json'] = from_json_filter

def init_admin():
    """Initialise le compte administrateur s'il n'existe pas"""
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        # Créer l'administrateur
        admin = User(
            username='admin',
            name='Admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Compte administrateur créé avec succès.')

if __name__ == '__main__':
    with app.app_context():
        # Créer les tables si elles n'existent pas
        db.create_all()
        # Initialiser l'administrateur
        init_admin()
    
    app.run(debug=True)
