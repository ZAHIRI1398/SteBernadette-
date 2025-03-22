from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
import os
import time
from functools import wraps
from models import db, User, Class, Course, Exercise, ExerciseAttempt, CourseFile, course_exercise, student_class_association
import json
import random
import string
from datetime import datetime, timedelta
import logging
import unicodedata
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, MultipleFileField
from wtforms.validators import DataRequired

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

# Fonctions pour les filtres Jinja2
def enumerate_filter(iterable, start=0):
    return enumerate(iterable, start=start)

def from_json_filter(value):
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

def tojson_filter(value, indent=None):
    return json.dumps(value, indent=indent, ensure_ascii=False)

def get_file_icon(filename):
    """Retourne l'icône Font Awesome appropriée en fonction de l'extension du fichier"""
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    icon_mapping = {
        'pdf': 'fa-file-pdf',
        'doc': 'fa-file-word',
        'docx': 'fa-file-word',
        'xls': 'fa-file-excel',
        'xlsx': 'fa-file-excel',
        'ppt': 'fa-file-powerpoint',
        'pptx': 'fa-file-powerpoint',
        'txt': 'fa-file-alt',
        'jpg': 'fa-file-image',
        'jpeg': 'fa-file-image',
        'png': 'fa-file-image',
        'gif': 'fa-file-image',
        'zip': 'fa-file-archive',
        'rar': 'fa-file-archive',
        '7z': 'fa-file-archive',
    }
    
    return icon_mapping.get(extension, 'fa-file')  # fa-file est l'icône par défaut

app.jinja_env.globals.update(get_file_icon=get_file_icon)

# Enregistrement des filtres Jinja2
app.jinja_env.filters['enumerate'] = enumerate_filter
app.jinja_env.filters['from_json'] = from_json_filter
app.jinja_env.filters['tojson'] = tojson_filter

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


# Routes
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
def exercise_library():
    # Récupérer les paramètres de filtrage
    search_query = request.args.get('search', '')
    exercise_type = request.args.get('type', '')
    subject = request.args.get('subject', '')
    level = request.args.get('level', '')

    # Construire la requête de base
    query = Exercise.query

    # Appliquer les filtres
    if search_query:
        search = f"%{search_query}%"
        query = query.filter(
            db.or_(
                Exercise.title.ilike(search),
                Exercise.description.ilike(search)
            )
        )
    
    if exercise_type:
        query = query.filter(Exercise.exercise_type == exercise_type)
    
    # Exécuter la requête
    exercises = query.all()

    # Debug: afficher le nombre d'exercices trouvés
    app.logger.info(f"Nombre d'exercices trouvés : {len(exercises)}")
    for ex in exercises:
        app.logger.info(f"Exercice : {ex.title} (type: {ex.exercise_type})")

    return render_template('exercise_library.html',
                         exercises=exercises,
                         exercise_types=Exercise.EXERCISE_TYPES,
                         search_query=search_query,
                         selected_type=exercise_type,
                         selected_subject=subject,
                         selected_level=level)

@app.route('/exercise/<int:exercise_id>')
@login_required
def view_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    
    # Vérifier si l'élève a accès à l'exercice via ses cours
    student_courses = Course.query.join(
        course_exercise,
        (course_exercise.c.course_id == Course.id) & 
        (course_exercise.c.exercise_id == exercise_id)
    ).join(
        Class,
        Class.id == Course.class_id
    ).join(
        student_class_association,
        (student_class_association.c.class_id == Class.id) &
        (student_class_association.c.student_id == current_user.id)
    ).all()
    
    if not student_courses and not current_user.is_teacher:
        flash("Vous n'avez pas accès à cet exercice.", 'error')
        return redirect(url_for('index'))

    course = student_courses[0] if student_courses else None

    # Déboguer le contenu de l'exercice
    content = exercise.get_content()
    app.logger.debug(f"[DEBUG] Content pour exercice {exercise_id}")
    app.logger.debug(f"[DEBUG] Content brut: {exercise.content}")
    app.logger.debug(f"[DEBUG] Content parsé: {content}")
    app.logger.debug(f"[DEBUG] Type d'exercice: {exercise.exercise_type}")
    if exercise.exercise_type == 'pairs':
        app.logger.debug(f"[DEBUG] Images gauche: {content.get('items_left_images', [])}")
        app.logger.debug(f"[DEBUG] Images droite: {content.get('items_right_images', [])}")
        
        # Générer le HTML directement pour déboguer
        template = render_template('exercise_types/pairs_preview.html', 
                                exercise=exercise, 
                                course=course)
        app.logger.debug("[DEBUG] HTML généré:")
        app.logger.debug(template)

    return render_template('view_exercise.html', 
                         exercise=exercise, 
                         course=course)

@app.route('/exercise/<int:exercise_id>/teacher')
@login_required
def view_exercise_teacher(exercise_id):
    if not current_user.is_teacher:
        flash("Accès non autorisé.", "error")
        return redirect(url_for('index'))
        
    exercise = Exercise.query.get_or_404(exercise_id)
    return render_template('view_exercise_teacher.html', exercise=exercise)

@app.route('/exercise/<int:exercise_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_exercise(exercise_id):
    if not current_user.is_teacher:
        flash("Accès non autorisé.", "error")
        return redirect(url_for('index'))
        
    exercise = Exercise.query.get_or_404(exercise_id)
    if exercise.teacher_id != current_user.id:
        flash("Vous n'êtes pas autorisé à modifier cet exercice.", "error")
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        exercise_type = request.form.get('exercise_type')
        content = {}

        # Mettre à jour les informations de base
        exercise.title = title
        exercise.description = description
        exercise.exercise_type = exercise_type

        # Gérer le contenu spécifique au type d'exercice
        if exercise_type == 'qcm':
            questions = []
            question_count = int(request.form.get('question_count', 0))
            
            for i in range(question_count):
                question = {
                    'question': request.form.get(f'question_{i}'),
                    'options': request.form.getlist(f'options_{i}[]'),
                    'correct': request.form.get(f'correct_{i}')
                }
                if question['question'] and question['options'] and question['correct']:
                    questions.append(question)
            
            content['questions'] = questions
            
        exercise.content = json.dumps(content)

        try:
            db.session.commit()
            flash('Exercice modifié avec succès !', 'success')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
        except Exception as e:
            db.session.rollback()
            flash('Une erreur est survenue lors de la modification.', 'error')

    # Pour la méthode GET
    content = exercise.get_content()
    return render_template('edit_exercise.html', exercise=exercise, content=content)

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

@app.route('/exercise/create', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_exercise():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        exercise_type = request.form.get('exercise_type')
        
        # Créer l'exercice
        exercise = Exercise(
            title=title,
            description=description,
            exercise_type=exercise_type,
            teacher_id=current_user.id
        )
        
        # Initialiser le contenu en fonction du type d'exercice
        if exercise_type == 'qcm':
            # Récupérer les questions
            questions = []
            i = 0
            while f'question_{i}' in request.form:
                question = {
                    'question': request.form.get(f'question_{i}'),
                    'options': request.form.getlist(f'options_{i}[]'),
                    'correct': request.form.get(f'correct_{i}')
                }
                if question['question'] and question['options'] and question['correct']:
                    questions.append(question)
            
            if not questions:
                # Créer une question exemple si aucune n'est fournie
                questions = [{
                    'question': 'Question exemple',
                    'options': ['Option 1', 'Option 2', 'Option 3'],
                    'correct': 'Option 1'
                }]
            
            exercise.content = json.dumps({'questions': questions})
            
        elif exercise_type == 'word_search':
            words = request.form.get('words', '').split(',')
            words = [w.strip() for w in words if w.strip()]
            exercise.content = json.dumps({
                'words': words,
                'grid': []  # La grille sera générée lors de l'édition
            })
            
        elif exercise_type == 'drag_and_drop':
            items = request.form.getlist('items[]')
            zones = request.form.getlist('zones[]')
            exercise.content = json.dumps({
                'elements': items,
                'zones': zones
            })
        
        db.session.add(exercise)
        db.session.commit()
        
        flash('Exercice créé avec succès !', 'success')
        return redirect(url_for('edit_exercise', exercise_id=exercise.id))
    
    return render_template('create_exercise.html', exercise_types=Exercise.EXERCISE_TYPES)

@app.route('/exercise/<int:exercise_id>/add_to_class', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_exercise_to_class(exercise_id):
    app.logger.info(f"[add_exercise_to_class] Début de la fonction pour l'exercice {exercise_id}")
    
    exercise = Exercise.query.get_or_404(exercise_id)
    app.logger.info(f"[add_exercise_to_class] Exercice trouvé: {exercise.title}")
    
    # Récupérer les classes de l'enseignant
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    app.logger.info(f"[add_exercise_to_class] Nombre de classes trouvées: {len(classes)}")
    
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

@app.route('/exercise/<int:exercise_id>/submit', methods=['POST'])
@login_required
def submit_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    content = exercise.get_content()
    
    if not content:
        flash("Erreur: Impossible de charger le contenu de l'exercice.", 'error')
        return redirect(url_for('view_exercise', exercise_id=exercise_id))

    exercise_type = request.form.get('exercise_type')
    score = 0
    total = 0
    feedback = ""

    if exercise_type == 'word_search':
        # Debug logs
        app.logger.debug(f"[DEBUG] Form data: {request.form}")
        app.logger.debug(f"[DEBUG] Found words raw: {request.form.get('found_words', '')}")
        
        found_words = set(request.form.get('found_words', '').split(','))
        if '' in found_words:  # Retirer la chaîne vide si présente
            found_words.remove('')
            
        app.logger.debug(f"[DEBUG] Found words set: {found_words}")
        app.logger.debug(f"[DEBUG] Words to find: {set(content['words'])}")
        
        # Vérifier que tous les mots trouvés sont dans la liste des mots à trouver
        invalid_words = found_words - set(content['words'])
        missing_words = set(content['words']) - found_words
        
        app.logger.debug(f"[DEBUG] Invalid words: {invalid_words}")
        app.logger.debug(f"[DEBUG] Missing words: {missing_words}")
        
        if invalid_words:
            flash(f"Erreur: Certains mots trouvés ne sont pas dans la liste: {', '.join(invalid_words)}", 'error')
            return redirect(url_for('view_exercise', exercise_id=exercise_id))
        
        total = len(content['words'])
        score = len(found_words)
        feedback = f"Vous avez trouvé {score} mot{'s' if score > 1 else ''} sur {total}."

    elif exercise_type == 'pairs':
        # Code existant pour les exercices de type pairs
        pairs = []
        for i in range(len(content['items_left'])):
            left_index = request.form.get(f'left_{i}')
            right_index = request.form.get(f'right_{i}')
            if left_index and right_index:
                pairs.append((int(left_index), int(right_index)))

        total = len(content['items_left'])
        for left_idx, right_idx in pairs:
            if left_idx < len(content['items_left']) and right_idx < len(content['items_right']):
                if left_idx == right_idx:  # Les indices correspondent car les items sont dans le même ordre
                    score += 1

        feedback = f"Vous avez trouvé {score} paire{'s' if score > 1 else ''} correcte{'s' if score > 1 else ''} sur {total}."

    # Enregistrer la tentative
    attempt = ExerciseAttempt(
        exercise_id=exercise_id,
        student_id=current_user.id,
        score=score,
        total=total,
        course_id=request.form.get('course_id', type=int)
    )
    db.session.add(attempt)
    db.session.commit()

    # Afficher le feedback
    if score == total:
        flash(f"Félicitations ! {feedback}", 'success')
    else:
        flash(feedback, 'info')

    return redirect(url_for('view_exercise', exercise_id=exercise_id))

@app.route('/exercise/<int:exercise_id>/stats')
@login_required
@teacher_required
def exercise_stats(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    course_id = request.args.get('course_id', type=int)
    
    # Vérifier que l'enseignant a le droit d'accéder à ces statistiques
    has_access = False
    
    # Vérifier si l'enseignant est le créateur de l'exercice
    if exercise.teacher_id == current_user.id:
        has_access = True
    else:
        # Vérifier si l'exercice est utilisé dans l'une des classes de l'enseignant
        teacher_classes = Class.query.filter_by(teacher_id=current_user.id).all()
        for class_obj in teacher_classes:
            for course in class_obj.courses:
                if exercise in course.exercises:
                    has_access = True
                    break
            if has_access:
                break
    
    if not has_access:
        flash("Vous n'avez pas l'autorisation de voir ces statistiques.", "error")
        return redirect(url_for('index'))
    
    # Récupérer les statistiques
    stats = exercise.get_stats(course_id)
    
    # Récupérer les informations du cours si spécifié
    course = Course.query.get(course_id) if course_id else None
    
    # Ajouter les informations de progression pour chaque étudiant
    student_progress = []
    students_to_show = course.class_obj.students if course else User.query.filter_by(role='student').all()
    
    for student in students_to_show:
        progress = exercise.get_student_progress(student.id)
        student_progress.append({
            'student': student,
            'progress': progress
        })
    
    return render_template('exercise_stats.html',
                         exercise=exercise,
                         course=course,
                         stats=stats,
                         student_progress=student_progress)

@app.route('/exercise/<int:exercise_id>/feedback/<int:attempt_id>')
@login_required
def view_feedback(exercise_id, attempt_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    attempt = ExerciseAttempt.query.get_or_404(attempt_id)
    
    # Vérifier que l'utilisateur a le droit de voir ce feedback
    if attempt.student_id != current_user.id and not current_user.role == 'teacher':
        flash("Vous n'avez pas l'autorisation de voir cette tentative.", "error")
        return redirect(url_for('index'))

    # Si c'est un enseignant, vérifier qu'il enseigne dans la classe associée au cours
    if current_user.is_teacher and attempt.course_id:
        course = Course.query.get(attempt.course_id)
        if course and course.teacher_id != current_user.id:
            flash("Vous n'avez pas l'autorisation de voir cette tentative.", "error")
            return redirect(url_for('index'))
    
    # Convertir les réponses et le feedback en dictionnaires
    answers = {}
    feedback = {}
    
    if exercise.exercise_type == 'qcm':
        answers_list = json.loads(attempt.answers)
        for i, answer in enumerate(answers_list, 1):
            answers[str(i)] = answer
    elif exercise.exercise_type == 'pair_match':
        pairs = json.loads(attempt.answers)
        for i, pair in enumerate(pairs, 1):
            answers[str(i)] = f"{pair['left']} → {pair['right']}"
    
    if attempt.feedback:
        feedback = json.loads(attempt.feedback)
    
    return render_template('feedback.html',
                         exercise=exercise,
                         attempt=attempt,
                         answers=answers,
                         feedback=feedback)

@app.route('/course/<int:course_id>/file/<int:file_id>/download')
@login_required
def download_course_file(course_id, file_id):
    course = Course.query.get_or_404(course_id)
    file = CourseFile.query.get_or_404(file_id)
    
    if file.course_id != course.id:
        flash('Fichier non trouvé.', 'error')
        return redirect(url_for('view_course', course_id=course_id))
    
    # Vérifier que l'utilisateur a accès au cours
    if current_user.role != 'teacher' and not any(c.id == course.class_id for c in current_user.classes_enrolled):
        flash('Accès non autorisé.', 'error')
        return redirect(url_for('index'))
    
    uploads_dir = os.path.join(app.root_path, 'uploads')
    return send_from_directory(uploads_dir, file.filename, as_attachment=True, download_name=file.original_filename)

@app.route('/course/<int:course_id>/get-available-exercises')
@login_required
def get_available_exercises(course_id):
    """Retourne la liste des exercices disponibles pour un cours"""
    if not current_user.role == 'teacher':
        return jsonify({'error': 'Non autorisé'}), 403
    
    course = Course.query.get_or_404(course_id)
    if course.class_obj.teacher_id != current_user.id:
        return jsonify({'error': 'Non autorisé'}), 403
    
    # Récupérer tous les exercices disponibles
    exercises = Exercise.query.all()
    
    # Filtrer les exercices qui ne sont pas déjà dans le cours
    available_exercises = [
        {'id': ex.id, 'title': ex.title, 'type': ex.exercise_type}
        for ex in exercises if ex not in course.exercises
    ]
    
    return jsonify(available_exercises)

@app.route('/exercise/<int:exercise_id>/submit', methods=['POST'])
@login_required
def submit_answer(exercise_id):
    print("\n=== DÉBUT SUBMIT_ANSWER ===")
    print(f"[DEBUG] Soumission pour l'exercice {exercise_id}")
    print(f"[DEBUG] Utilisateur: {current_user.username} (ID: {current_user.id})")
    
    exercise = Exercise.query.get_or_404(exercise_id)
    course_id = request.form.get('course_id')
    print(f"[DEBUG] Course ID: {course_id}")
    
    if not course_id:
        flash('Erreur: Cours non spécifié', 'error')
        return redirect(url_for('exercise_library'))
    
    # Vérifier que l'étudiant a accès à ce cours
    course = Course.query.get_or_404(course_id)
    if not current_user.is_enrolled(course.class_obj.id):
        flash('Vous n\'avez pas accès à cet exercice.', 'error')
        return redirect(url_for('exercise_library'))
    
    answers = {}
    score = 0
    feedback = []
    
    try:
        if exercise.exercise_type == 'qcm':
            content = exercise.get_content()
            total_questions = len(content['questions'])
            correct_answers = 0
            
            for i, question in enumerate(content['questions']):
                student_answer = request.form.get(f'q{i}')
                correct_answer = question['correct']
                
                is_correct = student_answer == correct_answer
                answers[f'q{i}'] = student_answer
                
                if is_correct:
                    correct_answers += 1
                    feedback.append({
                        'question': i + 1,
                        'correct': True,
                        'message': 'Bonne réponse !'
                    })
                else:
                    feedback.append({
                        'question': i + 1,
                        'correct': False,
                        'message': f'La réponse correcte était : {correct_answer}'
                    })
            
            score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
            
        # Enregistrer la tentative
        attempt = ExerciseAttempt(
            student_id=current_user.id,
            exercise_id=exercise_id,
            course_id=course_id,
            score=score,
            answers=json.dumps(answers),
            feedback=json.dumps(feedback)
        )
        
        print(f"[DEBUG] Tentative créée - Score: {score}, Course: {course_id}")
        
        db.session.add(attempt)
        db.session.commit()
        
        print(f"[DEBUG] Tentative enregistrée avec succès - ID: {attempt.id}")
        print("=== FIN SUBMIT_ANSWER ===\n")
        
        flash(f'Exercice soumis avec succès ! Score : {score}%', 'success')
        return redirect(url_for('view_exercise', exercise_id=exercise_id))
        
    except Exception as e:
        print(f"[ERROR] Erreur dans submit_answer: {str(e)}")
        db.session.rollback()
        flash('Une erreur est survenue lors de la soumission.', 'error')
        return redirect(url_for('view_exercise', exercise_id=exercise_id))

@app.route('/debug/exercises')
@login_required
def debug_exercises():
    if not current_user.is_teacher:
        return "Accès non autorisé", 403
        
    exercises = Exercise.query.all()
    debug_info = []
    
    for ex in exercises:
        debug_info.append({
            'id': ex.id,
            'title': ex.title,
            'type': ex.exercise_type,
            'content': ex.content,
            'parsed_content': ex.get_content()
        })
    
    return render_template('debug_exercises.html', exercises=debug_info)

@app.route('/exercise/<int:exercise_id>/attempt/<int:attempt_id>')
@login_required
def view_attempt(exercise_id, attempt_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    attempt = ExerciseAttempt.query.get_or_404(attempt_id)
    
    # Vérifier que l'utilisateur a le droit de voir cette tentative
    if not current_user.is_teacher and attempt.student_id != current_user.id:
        flash("Vous n'avez pas l'autorisation de voir cette tentative.", "error")
        return redirect(url_for('index'))
    
    # Si c'est un enseignant, vérifier qu'il enseigne dans la classe associée au cours
    if current_user.is_teacher and attempt.course_id:
        course = Course.query.get(attempt.course_id)
        if course and course.teacher_id != current_user.id:
            flash("Vous n'avez pas l'autorisation de voir cette tentative.", "error")
            return redirect(url_for('index'))
    
    return render_template('view_attempt.html', 
                         exercise=exercise, 
                         attempt=attempt)

@app.route('/debug/images')
def debug_images():
    # Lister tous les fichiers dans le dossier uploads
    files = []
    upload_dir = app.config['UPLOAD_FOLDER']
    for filename in os.listdir(upload_dir):
        if filename.startswith('pair_left_'):
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                files.append({
                    'name': filename,
                    'url': url_for('static', filename=f'uploads/{filename}'),
                    'size': os.path.getsize(file_path)
                })
    
    return render_template('debug_images.html', files=files)

def init_admin():
    # Vérifier si l'administrateur existe déjà
    admin = User.query.filter_by(email='admin@admin.com').first()
    if not admin:
        # Créer l'administrateur
        admin = User(
            username='admin',
            email='admin@admin.com',
            role='admin'
        )
        admin.set_password('admin')
        
        db.session.add(admin)
        db.session.commit()
        print("Administrateur créé avec succès !")

if __name__ == '__main__':
    with app.app_context():
        # Créer les tables si elles n'existent pas
        db.create_all()
        init_admin()
        
    app.run(debug=True)
