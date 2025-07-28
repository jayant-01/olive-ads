from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Survey, Question, SurveyResponse, Answer, PostbackConfig, PostbackLog, APIKey, ReceivedPostback
from gemini_service import generate_survey_from_prompt, validate_survey_structure
from postback_service import PostbackService
from api_auth import require_api_key, get_api_key_from_request
from flask_migrate import Migrate
import os
import json
import requests
from urllib.parse import urlparse, parse_qs
import re
from datetime import datetime, timedelta
from flask_cors import CORS
import logging
from sqlalchemy import func
from dateutil import parser

logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
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
        flash('You do not have permission to access the admin dashboard')
        return redirect(url_for('user_dashboard'))
    
    # Get basic statistics
    total_users = User.query.count()
    total_surveys = Survey.query.count()
    total_responses = SurveyResponse.query.count()
    
    # Get postback statistics
    total_postbacks = ReceivedPostback.query.count()
    postbacks_today = ReceivedPostback.query.filter(
        func.date(ReceivedPostback.received_at) == datetime.today().date()
    ).count()
    
    # Get postbacks by status
    postbacks_by_status = db.session.query(
        ReceivedPostback.status,
        func.count(ReceivedPostback.id).label('count')
    ).group_by(ReceivedPostback.status).all()
    
    # Get recent postbacks for the table
    recent_postbacks = ReceivedPostback.query.order_by(
        ReceivedPostback.received_at.desc()
    ).limit(5).all()
    
    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_surveys=total_surveys,
        total_responses=total_responses,
        total_postbacks=total_postbacks,
        postbacks_today=postbacks_today,
        postbacks_by_status=dict(postbacks_by_status),
        recent_postbacks=recent_postbacks
    )

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/surveys')
@login_required
def admin_all_surveys():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    all_surveys = Survey.query.all()
    return render_template('admin_all_surveys.html', all_surveys=all_surveys)

@app.route('/admin/responses')
@login_required
def admin_all_responses():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Start with base query
    query = SurveyResponse.query.join(Survey) # Join with Survey to filter by title

    # Get filter parameters from request arguments
    survey_title = request.args.get('survey_title')
    form_status = request.args.get('form_status')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # New filters
    response_id = request.args.get('response_id')
    respondent_id = request.args.get('respondent_id')
    session_id = request.args.get('session_id')
    browser = request.args.get('browser')
    device_type = request.args.get('device_type')

    utm_source = request.args.get('utm_source')
    utm_medium = request.args.get('utm_medium')
    utm_campaign = request.args.get('utm_campaign')
    utm_content = request.args.get('utm_content')
    utm_term = request.args.get('utm_term')

    session_ip = request.args.get('session_ip')
    actual_ip = request.args.get('actual_ip')
    conversion_ip = request.args.get('conversion_ip')

    geolocation_city = request.args.get('geolocation_city')
    geolocation_country = request.args.get('geolocation_country')

    clicks_suspicious = request.args.get('clicks_suspicious')
    clicks_rejected = request.args.get('clicks_rejected')

    # Apply filters
    if survey_title:
        query = query.filter(Survey.title.ilike(f'%{survey_title}%'))
    if form_status:
        query = query.filter(SurveyResponse.form_status == form_status)

    if start_date_str:
        try:
            start_datetime = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(SurveyResponse.created_at >= start_datetime)
        except ValueError:
            flash('Invalid start date format. Please use YYYY-MM-DD.', 'warning')

    if end_date_str:
        try:
            end_datetime = datetime.strptime(end_date_str, '%Y-%m-%d')
            end_datetime = end_datetime + timedelta(days=1)
            query = query.filter(SurveyResponse.created_at < end_datetime)
        except ValueError:
            flash('Invalid end date format. Please use YYYY-MM-DD.', 'warning')

    # Apply new filters
    if response_id:
        query = query.filter(SurveyResponse.id == response_id)
    if respondent_id:
        query = query.filter(SurveyResponse.respondent_id == respondent_id)
    if session_id:
        query = query.filter(SurveyResponse.session_id.ilike(f'%{session_id}%'))
    if browser:
        query = query.filter(SurveyResponse.browser.ilike(f'%{browser}%'))
    if device_type:
        query = query.filter(SurveyResponse.device_type == device_type)

    # UTM filters (accessing JSON fields)
    from sqlalchemy.dialects import sqlite
    from sqlalchemy import cast, String

    if utm_source:
        query = query.filter(cast(SurveyResponse.utm_data, String).ilike(f'%"utm_source": "{utm_source}"%'))
    if utm_medium:
        query = query.filter(cast(SurveyResponse.utm_data, String).ilike(f'%"utm_medium": "{utm_medium}"%'))
    if utm_campaign:
        query = query.filter(cast(SurveyResponse.utm_data, String).ilike(f'%"utm_campaign": "{utm_campaign}"%'))
    if utm_content:
        query = query.filter(cast(SurveyResponse.utm_data, String).ilike(f'%"utm_content": "{utm_content}"%'))
    if utm_term:
        query = query.filter(cast(SurveyResponse.utm_data, String).ilike(f'%"utm_term": "{utm_term}"%'))

    # IP filters (accessing JSON fields)
    if session_ip:
        query = query.filter(cast(SurveyResponse.ip_data, String).ilike(f'%"session_ip": "{session_ip}"%'))
    if actual_ip:
        query = query.filter(cast(SurveyResponse.ip_data, String).ilike(f'%"actual_ip": "{actual_ip}"%'))
    if conversion_ip:
        query = query.filter(cast(SurveyResponse.ip_data, String).ilike(f'%"conversion_ip": "{conversion_ip}"%'))

    # Geolocation filters (accessing JSON fields)
    if geolocation_city:
        query = query.filter(cast(SurveyResponse.geolocation_data, String).ilike(f'%"city": "{geolocation_city}"%'))
    if geolocation_country:
        query = query.filter(cast(SurveyResponse.geolocation_data, String).ilike(f'%"country": "{geolocation_country}"%'))

    # Clicks filters (accessing JSON fields - numerical comparison)
    if clicks_suspicious is not None and clicks_suspicious != '':
        try:
            clicks_suspicious_int = int(clicks_suspicious)
            query = query.filter(cast(SurveyResponse.click_data, String).ilike(f'%"suspicious": {clicks_suspicious_int}%'))
        except ValueError:
            flash('Invalid value for suspicious clicks. Please enter a number.', 'warning')
    
    if clicks_rejected is not None and clicks_rejected != '':
        try:
            clicks_rejected_int = int(clicks_rejected)
            query = query.filter(cast(SurveyResponse.click_data, String).ilike(f'%"rejected": {clicks_rejected_int}%'))
        except ValueError:
            flash('Invalid value for rejected clicks. Please enter a number.', 'warning')

    # Order and execute the query
    all_responses = query.order_by(SurveyResponse.created_at.desc()).all()

    return render_template('admin_all_responses.html', all_responses=all_responses)

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
        form_type = request.form.get('form_type', 'ai_generated')
        
        if form_type == 'external':
            # Redirect to external form creation
            return redirect(url_for('create_external_survey'))
        
        # Handle AI-generated survey
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
            creator_id=current_user.id,
            form_type='ai_generated',
            is_external=False
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

@app.route('/surveys/create/external', methods=['GET', 'POST'])
@login_required
def create_external_survey():
    if not current_user.is_admin:
        flash('Only admins can add external forms.', 'danger')
        return redirect(url_for('create_survey'))
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        external_url = request.form.get('external_url')
        
        if not title or not external_url:
            flash('Please provide both title and external URL')
            return redirect(url_for('create_external_survey'))
        
        # Validate URL format
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(external_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                flash('Please provide a valid URL with http:// or https://')
                return redirect(url_for('create_external_survey'))
        except Exception:
            flash('Please provide a valid URL')
            return redirect(url_for('create_external_survey'))
        
        # Create external survey in database
        survey = Survey(
            title=title,
            description=description,
            creator_id=current_user.id,
            form_type='external',
            is_external=True,
            external_url=external_url
        )
        
        try:
            db.session.add(survey)
            db.session.commit()
            flash('External form added successfully!')
            return redirect(url_for('view_survey', survey_id=survey.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding external form: {str(e)}')
            return redirect(url_for('create_external_survey'))
    
    return render_template('create_survey.html')

@app.route('/surveys/<int:survey_id>')
def view_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    # Only restrict access if user is logged in and not admin/owner
    if current_user.is_authenticated:
        if survey.creator_id != current_user.id and not current_user.is_admin:
            flash('You do not have permission to view this survey')
            return redirect(url_for('surveys'))

    return render_template('view_survey.html', survey=survey)

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
                headers=json.dumps(json.loads(request.form['headers'])) if request.form['headers'] else json.dumps({}),
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
def send_to_oliver_ads():
    try:
        payload = request.get_json()
        print("📩 Payload received at /send_to_oliver_ads:", payload)

        referer_url = request.referrer or ""
        print(f"🌐 Referrer: {referer_url}")

        survey_id = None
        survey_match = re.search(r'/surveys/(\d+)', referer_url)
        if survey_match:
            survey_id = int(survey_match.group(1))
        # Fallback: if survey_id not in referrer, try to get from payload if applicable
        if not survey_id and 'survey_id' in payload: # Assuming payload might contain it
            survey_id = payload.get('survey_id')

        if not survey_id:
            return jsonify({'error': 'Survey ID not found in referrer URL or payload'}), 400

        survey = Survey.query.get(survey_id)
        if not survey:
            return jsonify({'error': 'Survey not found'}), 404

        # Extract data for SurveyResponse
        form_clone_response_id = payload.get("formClone_RespondeId")
        user_id_from_url = parse_qs(urlparse(referer_url).query).get("userid", [None])[0]
        company_name_from_url = parse_qs(urlparse(referer_url).query).get("companyname", [None])[0]

        # Initialize SurveyResponse
        survey_response = SurveyResponse(
            survey_id=survey.id,
            respondent_id=current_user.id if current_user.is_authenticated else None,
            session_id=form_clone_response_id, # Use formClone_RespondeId as session_id
            form_status='Complete' # Assuming submission means completion
        )
        print(f"DEBUG: Initial SurveyResponse session_id: {survey_response.session_id}")

        # Extract UTM parameters from referrer URL (if present)
        parsed_referer = urlparse(referer_url)
        referer_query_params = parse_qs(parsed_referer.query)
        utm_data = {
            'utm_source': referer_query_params.get('utm_source', [None])[0],
            'utm_medium': referer_query_params.get('utm_medium', [None])[0],
            'utm_campaign': referer_query_params.get('utm_campaign', [None])[0],
            'utm_content': referer_query_params.get('utm_content', [None])[0],
            'utm_term': referer_query_params.get('utm_term', [None])[0],
        }
        survey_response.utm_data = {k: v for k, v in utm_data.items() if v is not None} # Store only non-None values
        print(f"DEBUG: Extracted UTM Data: {survey_response.utm_data}")

        # Extract IP Addresses
        session_ip = request.remote_addr # This is often the immediate client IP or proxy
        actual_ip = request.headers.get('X-Forwarded-For', session_ip) # For proxies, get actual client IP
        survey_response.ip_data = {
            'session_ip': session_ip,
            'actual_ip': actual_ip,
            'conversion_ip': None # Placeholder, requires more info on how this is obtained
        }
        print(f"DEBUG: Extracted IP Data: {survey_response.ip_data}")

        # Extract Geolocation Data (Placeholder - requires external API for real data)
        survey_response.geolocation_data = {
            'ip': actual_ip, # Store the actual IP for potential later lookup
            'city': None,
            'country': None,
            'latitude': None,
            'longitude': None
        }
        print(f"DEBUG: Extracted Geolocation Data: {survey_response.geolocation_data}")

        # Browser and Device Type (basic extraction from User-Agent)
        user_agent = request.headers.get('User-Agent', '')
        browser = 'Unknown'
        device_type = 'Unknown'
        if 'Mobi' in user_agent or 'Android' in user_agent or 'iPhone' in user_agent:
            device_type = 'Mobile'
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            device_type = 'Tablet'
        else:
            device_type = 'Desktop'

        if 'Chrome' in user_agent and 'Edge' not in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent and 'Chrome' not in user_agent: # Safari can contain Chrome
            browser = 'Safari'
        elif 'Edge' in user_agent: # Edge is Chromium based, check after Chrome
            browser = 'Edge'
        elif 'MSIE' in user_agent or 'Trident' in user_agent: # Older IE
            browser = 'IE'
        survey_response.browser = browser
        survey_response.device_type = device_type
        print(f"DEBUG: Extracted Browser: {survey_response.browser}, Device Type: {survey_response.device_type}")

        # Clicks (Suspicious/Rejected) - Assuming these would be passed in the payload
        survey_response.click_data = {
            'suspicious': payload.get('suspicious_clicks', 0),
            'rejected': payload.get('rejected_clicks', 0)
        }
        print(f"DEBUG: Extracted Click Data: {survey_response.click_data}")

        db.session.add(survey_response)
        db.session.flush() # Get survey_response.id for answers

        # Process answers from payload (assuming payload contains form field names like 'question_ID')
        for question in survey.questions:
            if question.question_type == 'checkbox':
                answer_value_raw = payload.get(f'question_{question.id}')
                if answer_value_raw:
                    if isinstance(answer_value_raw, list):
                        answer_value = json.dumps(answer_value_raw)
                    elif isinstance(answer_value_raw, str): # Handle comma-separated string from JS if needed
                        answer_value = json.dumps([s.strip() for s in answer_value_raw.split(',')])
                    else:
                        answer_value = json.dumps([str(answer_value_raw)]) # Handle single value as list
                else:
                    answer_value = json.dumps([]) # No answer for checkbox
            else:
                answer_value = payload.get(f'question_{question.id}')
                if answer_value is not None:
                    answer_value = str(answer_value) # Ensure string for text field
                else:
                    answer_value = "" # Default to empty string for non-checkbox if no answer

            # Only add an answer if the question was answered
            if answer_value is not None and answer_value != "":
                answer = Answer(
                    response_id=survey_response.id,
                    question_id=question.id,
                    answer_text=answer_value
                )
                db.session.add(answer)

        # Store (user_id, company_name) in survey.merged_user_data
        if survey.merged_user_data is None:
            survey.merged_user_data = []
        # Ensure we only append if both user_id and company_name are meaningful
        if user_id_from_url and company_name_from_url:
            survey.merged_user_data.append((user_id_from_url, company_name_from_url))
        db.session.commit()
        print(f"✅ SurveyResponse ID {survey_response.id} created with detailed data.")

        # Process postbacks after survey response is committed
        PostbackService.process_survey_response(survey_response)

        # Forward payload to oliver_ads (original functionality)
        oliver_ads_response = requests.post('https://pepeleads-a0abffhpc9d3fvgy.canadacentral-01.azurewebsites.net/oliver_ads', json=payload)
        return jsonify(oliver_ads_response.json()), oliver_ads_response.status_code

    except Exception as e:
        db.session.rollback() # Rollback if anything fails during response/answer creation
        print("❌ Error in /send_to_oliver_ads:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/surveys/<int:survey_id>/merge_data')
@login_required
def view_merged_users(survey_id):
    survey = Survey.query.get_or_404(survey_id)

    # Permission check
    if survey.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this data.', 'danger')
        return redirect(url_for('surveys'))

    # who_merged is a dictionary of {user_id: email}
    merged_data = survey.who_merged or {}

    return render_template('survey_merge_data.html', survey=survey, merged_data=merged_data)

@app.route('/save_merge_data', methods=['POST'])
def save_merge_data():
    try:
        data = request.get_json()
        oliver_form_id = data.get('oliver_form_id')
        email = data.get('email')
        user_id = str(data.get('username'))  # Cast to str for JSON key safety

        print("🔁 Received Merge Data:")
        print(f"👤 Email: {email}")
        print(f"📝 Oliver Form ID: {oliver_form_id}")
        print(f"🧑 ID: {user_id}")

        # Fetch the survey
        survey = Survey.query.get(oliver_form_id)
        if not survey:
            return jsonify({"status": "error", "message": "Survey not found"}), 404

        # Initialize who_merged if None
        if survey.who_merged is None:
            survey.who_merged = {}

        # Add or update the user's info
        survey.who_merged[user_id] = email

        # Save changes
        db.session.commit()

        return jsonify({"status": "success", "message": "Data saved to survey.who_merged"}), 200

    except Exception as e:
        print("❌ Error processing merge data:", e)
        return jsonify({"status": "error", "message": str(e)}), 400

# Postback Receiver Endpoint
@app.route('/api/postbacks/receive', methods=['GET', 'POST'])
def receive_postback():
    """
    Endpoint to receive postback data from external services.
    Supports both GET and POST requests with form data or JSON payloads.
    """
    start_time = datetime.utcnow()
    postback = ReceivedPostback(
        method=request.method,
        url=request.url,
        source_ip=request.remote_addr,
        received_at=start_time
    )
    
    try:
        # Store request data based on content type
        if request.is_json:
            postback.json_data = request.get_json()
        elif request.form:
            postback.form_data = request.form.to_dict()
        
        # Store query parameters and headers
        postback.query_params = request.args.to_dict()
        postback.headers = dict(request.headers)
        
        # Store raw data for debugging
        if request.data:
            try:
                postback.raw_data = request.data.decode('utf-8')
            except UnicodeDecodeError:
                postback.raw_data = str(request.data)
        
        # Extract reference ID from query parameters
        postback.reference_id = postback.query_params.get('ref')
        
        # Process the postback
        postback.status = 'processed'
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        postback.processing_time_ms = int(processing_time)
        
        # Save to database
        db.session.add(postback)
        db.session.commit()
        
        logger.info(f"Received postback {postback.id} from {postback.source_ip}")
        
        return jsonify({
            'status': 'success',
            'message': 'Postback received and processed',
            'postback_id': postback.id,
            'received_at': postback.received_at.isoformat(),
            'reference_id': postback.reference_id
        }), 200
        
    except Exception as e:
        # Log the error
        postback.status = 'error'
        postback.error_message = str(e)
        db.session.rollback()
        db.session.add(postback)
        db.session.commit()
        
        logger.error(f"Error processing postback: {str(e)}", exc_info=True)
        
        return jsonify({
            'status': 'error',
            'message': 'Error processing postback',
            'error': str(e)
        }), 500

# Postback Receiver Dashboard
@app.route('/postbacks/received')
@login_required
def postback_receiver_dashboard():
    """Dashboard to view received postbacks"""
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Check if we should show all postbacks
    show_all = request.args.get('show_all', 'false').lower() == 'true'
    
    # Build query
    query = ReceivedPostback.query
    
    # Apply filters
    if request.args.get('method'):
        query = query.filter_by(method=request.args['method'].upper())
    if request.args.get('status'):
        query = query.filter_by(status=request.args['status'])
    if request.args.get('date_from'):
        try:
            date_from = datetime.strptime(request.args['date_from'], '%Y-%m-%d')
            query = query.filter(ReceivedPostback.received_at >= date_from)
        except ValueError:
            pass
    
    # Order by most recent first
    query = query.order_by(ReceivedPostback.received_at.desc())
    
    # Handle pagination or show all
    if show_all:
        postbacks = query.all()
        total = len(postbacks)
        postbacks = {
            'items': postbacks,
            'total': total,
            'pages': 1,
            'page': 1,
            'per_page': total,
            'has_prev': False,
            'has_next': False,
            'prev_num': None,
            'next_num': None,
            'iter_pages': lambda left_edge=2, left_current=2, right_current=5, right_edge=2: [1]
        }
    else:
        # Paginate results
        postbacks = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('postback_receiver_dashboard.html', postbacks=postbacks)

@app.route('/api/postbacks/<int:postback_id>')
@login_required
def get_postback_details(postback_id):
    """Get detailed information about a specific postback"""
    if not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    postback = ReceivedPostback.query.get_or_404(postback_id)
    
    return jsonify({
        'id': postback.id,
        'received_at': postback.received_at.isoformat(),
        'method': postback.method,
        'url': postback.url,
        'source_ip': postback.source_ip,
        'status': postback.status,
        'processing_time_ms': postback.processing_time_ms,
        'error_message': postback.error_message,
        'reference_id': postback.reference_id,
        'headers': postback.headers,
        'query_params': postback.query_params,
        'form_data': postback.form_data,
        'json_data': postback.json_data,
        'raw_data': postback.raw_data
    })

# API Key Management Routes
@app.route('/admin/api-keys')
@login_required
def admin_api_keys():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    api_keys = APIKey.query.all()
    return render_template('admin_api_keys.html', api_keys=api_keys)

@app.route('/admin/api-keys/create', methods=['GET', 'POST'])
@login_required
def create_api_key():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Please provide a name for the API key')
            return redirect(url_for('create_api_key'))
        
        # Generate new API key
        api_key_value = APIKey.generate_key()
        
        # Create API key object
        api_key = APIKey(
            name=name,
            creator_id=current_user.id,
            permissions={
                'read_forms': True,
                'read_responses': False,
                'create_forms': False
            }
        )
        api_key.set_key(api_key_value)
        
        try:
            db.session.add(api_key)
            db.session.commit()
            
            # Show the API key to the user (they won't see it again)
            flash(f'API key created successfully! Key: {api_key_value}', 'success')
            return redirect(url_for('admin_api_keys'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating API key: {str(e)}')
    
    return render_template('create_api_key.html')

@app.route('/admin/api-keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_api_key(key_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    api_key = APIKey.query.get_or_404(key_id)
    try:
        db.session.delete(api_key)
        db.session.commit()
        flash('API key deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting API key: {str(e)}')
    
    return redirect(url_for('admin_api_keys'))

@app.route('/admin/api-keys/<int:key_id>/toggle', methods=['POST'])
@login_required
def toggle_api_key(key_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    api_key = APIKey.query.get_or_404(key_id)
    api_key.is_active = not api_key.is_active
    
    try:
        db.session.commit()
        status = 'activated' if api_key.is_active else 'deactivated'
        flash(f'API key {status} successfully!')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating API key: {str(e)}')
    
    return redirect(url_for('admin_api_keys'))

# Public API Routes
@app.route('/api/forms', methods=['GET'])
@require_api_key
def api_get_forms():
    """Get all forms (surveys) with basic information."""
    try:
        # Get query parameters for filtering
        form_type = request.args.get('type')  # 'ai_generated' or 'external'
        active_only = request.args.get('active', 'true').lower() == 'true'
        
        # Build query
        query = Survey.query
        
        if form_type:
            query = query.filter(Survey.form_type == form_type)
        
        if active_only:
            query = query.filter(Survey.is_active == True)
        
        surveys = query.all()
        
        # Prepare response data
        forms_data = []
        for survey in surveys:
            form_data = {
                'id': survey.id,
                'title': survey.title,
                'description': survey.description,
                'form_type': survey.form_type,
                'is_external': survey.is_external,
                'external_url': survey.external_url if survey.is_external else None,
                'created_at': survey.created_at.isoformat(),
                'is_active': survey.is_active,
                'total_questions': len(survey.questions),
                'total_responses': len(survey.responses)
            }
            forms_data.append(form_data)
        
        return jsonify({
            'success': True,
            'data': {
                'forms': forms_data,
                'total_forms': len(forms_data),
                'ai_generated_forms': len([f for f in forms_data if f['form_type'] == 'ai_generated']),
                'external_forms': len([f for f in forms_data if f['form_type'] == 'external'])
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/forms/<int:form_id>', methods=['GET'])
@require_api_key
def api_get_form_details(form_id):
    """Get detailed information about a specific form."""
    try:
        survey = Survey.query.get_or_404(form_id)
        
        # Prepare detailed form data
        form_data = {
            'id': survey.id,
            'title': survey.title,
            'description': survey.description,
            'form_type': survey.form_type,
            'is_external': survey.is_external,
            'external_url': survey.external_url if survey.is_external else None,
            'created_at': survey.created_at.isoformat(),
            'is_active': survey.is_active,
            'questions': []
        }
        
        # Add questions if it's an AI-generated form
        if not survey.is_external:
            for question in survey.questions:
                question_data = {
                    'id': question.id,
                    'text': question.question_text,
                    'type': question.question_type,
                    'is_required': question.is_required,
                    'order': question.order
                }
                
                if question.question_type in ['multiple_choice', 'checkbox']:
                    question_data['options'] = question.options_list
                
                form_data['questions'].append(question_data)
        
        return jsonify({
            'success': True,
            'data': form_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@require_api_key
def api_get_stats():
    """Get overall statistics about forms."""
    try:
        total_forms = Survey.query.count()
        ai_generated_forms = Survey.query.filter_by(form_type='ai_generated').count()
        external_forms = Survey.query.filter_by(form_type='external').count()
        active_forms = Survey.query.filter_by(is_active=True).count()
        total_responses = SurveyResponse.query.count()
        
        # Get recent activity
        recent_forms = Survey.query.order_by(Survey.created_at.desc()).limit(5).all()
        recent_forms_data = []
        for survey in recent_forms:
            recent_forms_data.append({
                'id': survey.id,
                'title': survey.title,
                'form_type': survey.form_type,
                'created_at': survey.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'data': {
                'total_forms': total_forms,
                'ai_generated_forms': ai_generated_forms,
                'external_forms': external_forms,
                'active_forms': active_forms,
                'total_responses': total_responses,
                'recent_forms': recent_forms_data
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api-key-tester')
@login_required
def api_key_tester():
    if not current_user.is_admin:
        flash('Permission denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    return render_template('api_key_tester.html')

@app.route('/surveys/<int:survey_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    # Only the creator or admin can edit
    if survey.creator_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this survey.', 'danger')
        return redirect(url_for('surveys'))

    if request.method == 'POST':
        survey.title = request.form.get('title')
        survey.description = request.form.get('description')
        # Only admin can edit external fields
        if current_user.is_admin:
            is_external = request.form.get('is_external') == 'on'
            survey.is_external = is_external
            survey.form_type = 'external' if is_external else 'ai_generated'
            survey.external_url = request.form.get('external_url') if is_external else None
        try:
            db.session.commit()
            flash('Survey updated successfully!', 'success')
            return redirect(url_for('view_survey', survey_id=survey.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating survey: {str(e)}', 'danger')
    return render_template('edit_survey.html', survey=survey)

@app.route('/postbacks/instructions')
@login_required
def postback_instructions():
    """Show instructions for using postback URLs"""
    return render_template('postback_instructions.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
