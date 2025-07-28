from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import secrets
import string
from sqlalchemy.types import JSON
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.ext.mutable import MutableList
db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(128), nullable=False, unique=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    permissions = db.Column(MutableDict.as_mutable(JSON), default=dict)  # Store permissions as JSON
    
    creator = db.relationship('User', backref=db.backref('api_keys', lazy=True))
    
    @staticmethod
    def generate_key():
        """Generate a secure API key."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    def set_key(self, key):
        """Hash and store the API key."""
        self.key_hash = generate_password_hash(key)
    
    def check_key(self, key):
        """Check if the provided key matches the stored hash."""
        return check_password_hash(self.key_hash, key)
    
    def __repr__(self):
        return f'<APIKey {self.name}>'

class Survey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # New fields for external forms
    is_external = db.Column(db.Boolean, default=False)
    external_url = db.Column(db.String(500))
    form_type = db.Column(db.String(50), default='ai_generated')  # 'ai_generated' or 'external'
    
    creator = db.relationship('User', backref=db.backref('surveys', lazy=True))
    questions = db.relationship('Question', backref='survey', lazy=True, cascade='all, delete-orphan')
    responses = db.relationship('SurveyResponse', backref='survey', lazy=True, cascade='all, delete-orphan')
    postback_configs = db.relationship('PostbackConfig', backref='survey', lazy=True, cascade='all, delete-orphan')
    who_merged = db.Column(MutableDict.as_mutable(JSON), default=dict)
    # merged_user_data = db.Column(MutableDict.as_mutable(JSON), default=dict)
    merged_user_data = db.Column(MutableList.as_mutable(JSON), default=list)
    def __repr__(self):
        return f'<Survey {self.title}>'

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey('survey.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)  # text, multiple_choice, checkbox
    options = db.Column(db.Text)  # JSON string for multiple choice and checkbox options
    is_required = db.Column(db.Boolean, default=False)
    order = db.Column(db.Integer, default=0)
    
    answers = db.relationship('Answer', backref='question', lazy=True, cascade='all, delete-orphan')

    @property
    def options_list(self):
        """Convert options JSON string to list."""
        if self.options:
            try:
                return json.loads(self.options)
            except json.JSONDecodeError:
                return []
        return []

    def __repr__(self):
        return f'<Question {self.question_text[:50]}>'

class SurveyResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey('survey.id'), nullable=False)
    respondent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # New fields for detailed response data
    session_id = db.Column(db.String(255))
    form_status = db.Column(db.String(50))
    utm_data = db.Column(MutableDict.as_mutable(JSON), default=dict) # Stores utm_source, utm_medium, etc.
    ip_data = db.Column(MutableDict.as_mutable(JSON), default=dict)  # Stores session_ip, actual_ip, conversion_ip
    click_data = db.Column(MutableDict.as_mutable(JSON), default=dict) # Stores suspicious and rejected clicks
    browser = db.Column(db.String(255))
    device_type = db.Column(db.String(255))
    geolocation_data = db.Column(MutableDict.as_mutable(JSON), default=dict) # Stores city, country, lat/lon etc.
    
    respondent = db.relationship('User', backref=db.backref('responses', lazy=True))
    answers = db.relationship('Answer', backref='response', lazy=True, cascade='all, delete-orphan')
    # postback_logs is defined as a backref in PostbackLog model

    def __repr__(self):
        return f'<SurveyResponse {self.id}>'

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response_id = db.Column(db.Integer, db.ForeignKey('survey_response.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Answer {self.answer_text[:50]}>'

class PostbackConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey('survey.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, PUT, etc.
    headers = db.Column(db.Text)  # JSON string of headers
    payload_template = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref=db.backref('postback_configs', lazy=True))
    logs = db.relationship('PostbackLog', backref='config', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<PostbackConfig {self.name}>'

class PostbackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config_id = db.Column(db.Integer, db.ForeignKey('postback_config.id'), nullable=False)
    response_id = db.Column(db.Integer, db.ForeignKey('survey_response.id'), nullable=False)
    status_code = db.Column(db.Integer)
    response_text = db.Column(db.Text)
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    payload = db.Column(db.JSON)
    headers = db.Column(db.JSON)
    
    response = db.relationship('SurveyResponse', backref=db.backref('postback_logs', lazy=True))

    def __repr__(self):
        return f'<PostbackLog {self.id}>'

class ReceivedPostback(db.Model):
    """Stores data received from external postbacks"""
    id = db.Column(db.Integer, primary_key=True)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, etc.
    url = db.Column(db.String(500), nullable=False)    # The URL that was called
    headers = db.Column(JSON)                          # Request headers as JSON
    query_params = db.Column(JSON)                     # Query parameters for GET requests
    form_data = db.Column(JSON)                        # Form data for POST requests
    json_data = db.Column(JSON)                        # JSON data for POST requests with Content-Type: application/json
    raw_data = db.Column(db.Text)                      # Raw request data
    source_ip = db.Column(db.String(45))               # IP address of the sender
    
    # For tracking and filtering
    status = db.Column(db.String(20), default='received')  # received, processed, error
    processing_time_ms = db.Column(db.Integer)             # Time taken to process in milliseconds
    error_message = db.Column(db.Text)                     # Error message if processing failed
    
    # For linking to related data
    reference_id = db.Column(db.String(100))          # External reference ID if provided
    
    def __repr__(self):
        return f'<ReceivedPostback {self.id} {self.method} {self.url} {self.received_at}>'