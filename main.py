from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')

# Inside the Quiz model in main.py
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    # Add this new column
    time_limit = db.Column(db.Integer, nullable=False, default=60)
    questions = db.relationship('Question', backref='quiz', lazy=True)
    

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

# --- Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 1. Get the username from the form
        username = request.form['username']
        password = request.form['password']
        
        # 2. Find the user by their username
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if current_user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('quizzes'))
        else:
            # 3. Update the error message
            return "Login Unsuccessful. Please check username and password"
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # First, check if an admin user already exists
        admin_user = User.query.filter_by(role='admin').first()

        # Determine the role for the new user
        if admin_user:
            # If an admin exists, new users are students
            new_user_role = 'student'
        else:
            # If no admin exists, the first user to register becomes the admin
            new_user_role = 'admin'
        
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create the new user with the determined role
        new_user = User(
            username=username, 
            email=email, 
            password=hashed_password, 
            role=new_user_role
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            # This can happen if the username or email is already taken
            return "Error: A user with that username or email already exists."
    
    return render_template('register.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    # Authorization check: Stop non-admins
    if current_user.role != 'admin':
        abort(403)  # 403 is the HTTP status code for "Forbidden"

    # If the check passes, the rest of the function runs
    all_quizzes = Quiz.query.all()
    all_users = User.query.all()
    return render_template('admin_dashboard.html', all_quizzes=all_quizzes, all_users=all_users)




@app.route('/quiz/create', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Get minutes from form and convert to an integer
        time_in_minutes = int(request.form['time_limit'])
        # Convert minutes to seconds
        time_in_seconds = time_in_minutes * 60
        
        # Save the total SECONDS to the database
        new_quiz = Quiz(title=title, description=description, time_limit=time_in_seconds)
        
        try:
            db.session.add(new_quiz)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        except:
            return "There was an issue creating your quiz."
    
    return render_template('create_quiz.html')

@app.route('/quiz/<int:quiz_id>/add', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if request.method == 'POST':
        new_question = Question(
            text=request.form['text'],
            option_a=request.form['option_a'],
            option_b=request.form['option_b'],
            option_c=request.form['option_c'],
            option_d=request.form['option_d'],
            correct_answer=request.form['correct_answer'],
            quiz_id=quiz.id
        )
        db.session.add(new_question)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_question.html', quiz=quiz)


@app.route('/quizzes')
@login_required
def quizzes():
    all_quizzes = Quiz.query.all()
    return render_template('quiz_lobby.html', quizzes=all_quizzes)

@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('take_quiz.html', quiz=quiz)

# --- New Route for Submitting and Grading the Quiz ---
@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    score = 0
    results_data = [] # Create a list to hold detailed results

    for question in quiz.questions:
        submitted_answer = request.form.get(f'question_{question.id}')
        is_correct = (submitted_answer == question.correct_answer)
        
        if is_correct:
            score += 1
        
        # Store all the details for this question
        results_data.append({
            'question_text': question.text,
            'submitted_answer': submitted_answer,
            'correct_answer': question.correct_answer,
            'is_correct': is_correct
        })
    
    # Instead of returning a string, render the new results template
    return render_template(
        'results.html',
        quiz=quiz,
        score=score,
        total=len(quiz.questions),
        results_data=results_data
    )
    
@app.route('/quiz/<int:quiz_id>/questions')
@login_required
def view_questions(quiz_id):
    # Ensure only admins can access this page
    if current_user.role != 'admin':
        abort(403)
    
    quiz = Quiz.query.get_or_404(quiz_id)
    # The quiz object already has the questions thanks to db.relationship!
    return render_template('view_questions.html', quiz=quiz)