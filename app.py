from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Survey, Question, SurveyResponse, Answer, PostbackConfig, PostbackLog
from gemini_service import generate_survey_from_prompt, validate_survey_structure
from postback_service import PostbackService
from flask_migrate import Migrate
import os
import json
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oliver_ads.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database and create admin user if needed
def init_db():
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()

# Initialize the database
init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    total_users = User.query.filter_by(is_admin=False).count()
    return render_template('admin_dashboard.html', total_users=total_users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Survey-related routes
@app.route('/surveys')
# @login_required
def surveys():
    if not current_user.is_authenticated:
        return render_template('surveys.html', surveys=[])
    user_surveys = Survey.query.filter_by(creator_id=current_user.id).all()
    return render_template('surveys.html', surveys=user_surveys)

@app.route('/surveys/create', methods=['GET', 'POST'])
@login_required
def create_survey():
    if request.method == 'POST':
        prompt = request.form.get('prompt')
        if not prompt:
            flash('Please provide a prompt for survey generation')
            return redirect(url_for('create_survey'))
        
        # Generate survey using Gemini
        survey_data = generate_survey_from_prompt(prompt)
        if not survey_data or not validate_survey_structure(survey_data):
            flash('Failed to generate survey. Please try again with a different prompt.')
            return redirect(url_for('create_survey'))
        
        # Create survey in database
        survey = Survey(
            title=survey_data['title'],
            description=survey_data['description'],
            creator_id=current_user.id
        )
        db.session.add(survey)
        db.session.flush()  # Get survey ID
        
        # Create questions
        for q_data in survey_data['questions']:
            # Convert options list to JSON string if it exists
            options = json.dumps(q_data.get('options', [])) if q_data.get('options') else None
            
            question = Question(
                survey_id=survey.id,
                question_text=q_data['question_text'],
                question_type=q_data['question_type'],
                options=options,  # Store as JSON string
                is_required=q_data['is_required'],
                order=q_data['order']
            )
            db.session.add(question)
        
        try:
            db.session.commit()
            flash('Survey created successfully!')
            return redirect(url_for('view_survey', survey_id=survey.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating survey: {str(e)}')
            return redirect(url_for('create_survey'))
    
    return render_template('create_survey.html')

# @app.route('/surveys/<int:survey_id>')
# @login_required
# def view_survey(survey_id):
#     survey = Survey.query.get_or_404(survey_id)
#     if survey.creator_id != current_user.id and not current_user.is_admin:
#         flash('You do not have permission to view this survey')
#         return redirect(url_for('surveys'))
#     return render_template('view_survey.html', survey=survey)
@app.route('/surveys/<int:survey_id>')
def view_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    # Only restrict access if user is logged in and not admin/owner
    if current_user.is_authenticated:
        if survey.creator_id != current_user.id and not current_user.is_admin:
            flash('You do not have permission to view this survey')
            return redirect(url_for('surveys'))

    return render_template('view_survey.html', survey=survey)


# @app.route('/surveys/<int:survey_id>/submit', methods=['POST'])
# @login_required
# def submit_survey(survey_id):
#     survey = Survey.query.get_or_404(survey_id)
    
#     # Create a new response
#     response = SurveyResponse(
#         survey_id=survey_id,
#         respondent_id=current_user.id
#     )
#     db.session.add(response)
    
#     # Process each question
#     for question in survey.questions:
#         answer_value = request.form.get(f'question_{question.id}')
#         if answer_value:
#             # Handle checkbox questions (multiple values)
#             if question.question_type == 'checkbox':
#                 answer_value = request.form.getlist(f'question_{question.id}[]')
#                 answer_value = json.dumps(answer_value)
            
#             answer = Answer(
#                 response_id=response.id,
#                 question_id=question.id,
#                 answer_text=answer_value
#             )
#             db.session.add(answer)
    
#     try:
#         db.session.commit()
        
#         # Process postbacks
#         PostbackService.process_survey_response(response)
        
#         flash('Survey submitted successfully!', 'success')
#         return redirect(url_for('surveys'))
#     except Exception as e:
#         db.session.rollback()
#         flash(f'Error submitting survey: {str(e)}', 'error')
#         return redirect(url_for('view_survey', survey_id=survey_id))
@app.route('/surveys/<int:survey_id>/submit', methods=['POST'])
def submit_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)

    # Create a new response — set respondent_id only if user is logged in
    response = SurveyResponse(
        survey_id=survey_id,
        respondent_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(response)
    db.session.flush()  # Ensure response.id is populated

    # Process each question
    for question in survey.questions:
        if question.question_type == 'checkbox':
            answer_values = request.form.getlist(f'question_{question.id}[]')
            if answer_values:
                answer = Answer(
                    response_id=response.id,
                    question_id=question.id,
                    answer_text=json.dumps(answer_values)
                )
                db.session.add(answer)
        else:
            answer_value = request.form.get(f'question_{question.id}')
            if answer_value:
                answer = Answer(
                    response_id=response.id,
                    question_id=question.id,
                    answer_text=answer_value
                )
                db.session.add(answer)

    try:
        db.session.commit()

        # Process postbacks
        PostbackService.process_survey_response(response)

        flash('Survey submitted successfully!', 'success')
        return redirect(url_for('surveys'))  # You can change this to a thank-you page
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting survey: {str(e)}', 'error')
        return redirect(url_for('view_survey', survey_id=survey_id))

@app.route('/surveys/<int:survey_id>/responses')
@login_required
def view_responses(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    if survey.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view these responses')
        return redirect(url_for('surveys'))
    return render_template('survey_responses.html', survey=survey)

# Postback Configuration Routes
@app.route('/surveys/<int:survey_id>/postbacks')
@login_required
def postback_configs(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    if survey.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this survey')
        return redirect(url_for('surveys'))
    
    configs = PostbackConfig.query.filter_by(survey_id=survey_id).all()
    return render_template('postback_configs.html', survey=survey, configs=configs)

@app.route('/surveys/<int:survey_id>/postbacks/create', methods=['GET', 'POST'])
@login_required
def create_postback(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    if survey.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this survey')
        return redirect(url_for('surveys'))
    
    if request.method == 'POST':
        try:
            config = PostbackConfig(
                name=request.form['name'],
                url=request.form['url'],
                method=request.form['method'],
                headers=json.loads(request.form['headers']) if request.form['headers'] else {},
                payload_template=request.form['payload_template'],
                creator_id=current_user.id,
                survey_id=survey_id
            )
            db.session.add(config)
            db.session.commit()
            flash('Postback configuration created successfully!')
            return redirect(url_for('postback_configs', survey_id=survey_id))
        except Exception as e:
            flash(f'Error creating postback configuration: {str(e)}')
    
    return render_template('create_postback.html', survey=survey)

@app.route('/postbacks/<int:config_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_postback(config_id):
    config = PostbackConfig.query.get_or_404(config_id)
    if config.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this configuration')
        return redirect(url_for('surveys'))
    
    if request.method == 'POST':
        try:
            config.name = request.form['name']
            config.url = request.form['url']
            config.method = request.form['method']
            config.headers = json.loads(request.form['headers']) if request.form['headers'] else {}
            config.payload_template = request.form['payload_template']
            config.is_active = 'is_active' in request.form
            
            db.session.commit()
            flash('Postback configuration updated successfully!')
            return redirect(url_for('postback_configs', survey_id=config.survey_id))
        except Exception as e:
            flash(f'Error updating postback configuration: {str(e)}')
    
    return render_template('edit_postback.html', config=config)

@app.route('/postbacks/<int:config_id>/test', methods=['POST'])
@login_required
def test_postback(config_id):
    config = PostbackConfig.query.get_or_404(config_id)
    if config.creator_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    try:
        test_data = json.loads(request.form['test_data'])
        result = PostbackService.test_postback(config, test_data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/postbacks/<int:config_id>/logs')
@login_required
def postback_logs(config_id):
    config = PostbackConfig.query.get_or_404(config_id)
    if config.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view these logs')
        return redirect(url_for('surveys'))
    
    logs = PostbackLog.query.filter_by(config_id=config_id).order_by(PostbackLog.sent_at.desc()).all()
    return render_template('postback_logs.html', config=config, logs=logs)
@app.route('/send_to_oliver_ads', methods=['POST'])
#
def send_to_oliver_ads():
    print("hi")
    try:
        payload = request.get_json()
        response = requests.post('http://20.48.204.15/oliver_ads', json=payload)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Register the custom filter
@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s)
    except (TypeError, json.JSONDecodeError):
        return []
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)