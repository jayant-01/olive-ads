from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

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

class Survey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', backref=db.backref('surveys', lazy=True))
    questions = db.relationship('Question', backref='survey', lazy=True, cascade='all, delete-orphan')
    responses = db.relationship('SurveyResponse', backref='survey', lazy=True, cascade='all, delete-orphan')
    postback_configs = db.relationship('PostbackConfig', backref='survey', lazy=True, cascade='all, delete-orphan')

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
    
    respondent = db.relationship('User', backref=db.backref('responses', lazy=True))
    answers = db.relationship('Answer', backref='response', lazy=True, cascade='all, delete-orphan')

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